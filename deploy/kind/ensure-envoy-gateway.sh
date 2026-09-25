#!/usr/bin/env bash
set -euo pipefail

readonly ENVOY_GATEWAY_VERSION="v1.9.1"
readonly RELEASE_NAME="eg"
readonly RELEASE_NAMESPACE="envoy-gateway-system"
readonly CHART="oci://docker.io/envoyproxy/gateway-helm"
readonly GATEWAY_CLASS="meridian-gateway"
readonly GATEWAY_NAMESPACE="gateway-demo"
readonly GATEWAY_NAME="meridian-edge"
readonly IDENTITY_TLS_SECRET="axiom-identity-tls"
readonly ADMIN_TLS_SECRET="axiom-admin-tls"
readonly EXPECTED_CONTROLLER="gateway.envoyproxy.io/gatewayclass-controller"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly EXPECTED_CONTEXT="${AXIOM_KUBE_CONTEXT:-docker-desktop}"

current_context="$(kubectl config current-context)"
if [[ "${current_context}" != "${EXPECTED_CONTEXT}" ]]; then
  echo "Refusing to install Axiom edge into context ${current_context}; expected ${EXPECTED_CONTEXT}." >&2
  exit 1
fi

if helm status "${RELEASE_NAME}" --namespace "${RELEASE_NAMESPACE}" >/dev/null 2>&1; then
  installed_version="$(helm list --namespace "${RELEASE_NAMESPACE}" -o json \
    | python3 -c 'import json,sys; releases=json.load(sys.stdin); print(next(r["app_version"] for r in releases if r["name"]=="eg"))')"
  if [[ "${installed_version}" != "${ENVOY_GATEWAY_VERSION}" ]]; then
    echo "Envoy Gateway ${installed_version} is installed; Axiom requires ${ENVOY_GATEWAY_VERSION}." >&2
    exit 1
  fi
  echo "Envoy Gateway ${installed_version} already exists; validating it."
else
  echo "Envoy Gateway is absent; installing pinned version ${ENVOY_GATEWAY_VERSION}."
  helm upgrade --install "${RELEASE_NAME}" "${CHART}" \
    --version "${ENVOY_GATEWAY_VERSION}" \
    --namespace "${RELEASE_NAMESPACE}" \
    --create-namespace \
    --wait \
    --timeout 5m
fi

kubectl wait \
  --namespace "${RELEASE_NAMESPACE}" \
  --for=condition=Available \
  deployment/envoy-gateway \
  --timeout=5m

kubectl create namespace "${GATEWAY_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "${GATEWAY_NAMESPACE}" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

existing_controller="$(kubectl get gatewayclass "${GATEWAY_CLASS}" -o jsonpath='{.spec.controllerName}' 2>/dev/null || true)"
if [[ -n "${existing_controller}" && "${existing_controller}" != "${EXPECTED_CONTROLLER}" ]]; then
  echo "GatewayClass ${GATEWAY_CLASS} belongs to ${existing_controller}, not ${EXPECTED_CONTROLLER}." >&2
  exit 1
fi

if [[ -z "${existing_controller}" ]]; then
  kubectl apply -f - <<YAML
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: ${GATEWAY_CLASS}
spec:
  controllerName: ${EXPECTED_CONTROLLER}
YAML
fi

if kubectl get gateway "${GATEWAY_NAME}" --namespace "${GATEWAY_NAMESPACE}" >/dev/null 2>&1; then
  actual_class="$(kubectl get gateway "${GATEWAY_NAME}" --namespace "${GATEWAY_NAMESPACE}" -o jsonpath='{.spec.gatewayClassName}')"
  if [[ "${actual_class}" != "${GATEWAY_CLASS}" ]]; then
    echo "Gateway ${GATEWAY_NAMESPACE}/${GATEWAY_NAME} uses ${actual_class}, not ${GATEWAY_CLASS}." >&2
    exit 1
  fi

  gateway_patch="$(mktemp /private/tmp/axiom-gateway-listeners.XXXXXX)"
  kubectl get gateway "${GATEWAY_NAME}" --namespace "${GATEWAY_NAMESPACE}" -o json \
    | python3 -c '
import json, sys

gateway = json.load(sys.stdin)
expected = [
    {"name": "axiom-identity-http", "hostname": "identity.meridian.com", "port": 80, "protocol": "HTTP",
     "allowedRoutes": {"namespaces": {"from": "Same"}, "kinds": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}]}},
    {"name": "axiom-identity-https", "hostname": "identity.meridian.com", "port": 443, "protocol": "HTTPS",
     "tls": {"mode": "Terminate", "certificateRefs": [{"group": "", "kind": "Secret", "name": "axiom-identity-tls"}]},
     "allowedRoutes": {"namespaces": {"from": "Same"}, "kinds": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}]}},
    {"name": "axiom-admin-http", "hostname": "identity-admin.meridian.com", "port": 80, "protocol": "HTTP",
     "allowedRoutes": {"namespaces": {"from": "Same"}, "kinds": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}]}},
    {"name": "axiom-admin-https", "hostname": "identity-admin.meridian.com", "port": 443, "protocol": "HTTPS",
     "tls": {"mode": "Terminate", "certificateRefs": [{"group": "", "kind": "Secret", "name": "axiom-admin-tls"}]},
     "allowedRoutes": {"namespaces": {"from": "Same"}, "kinds": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}]}},
]
current = {item["name"]: item for item in gateway["spec"].get("listeners", [])}
patch = []
for listener in expected:
    name = listener["name"]
    if name in current:
        if current[name] != listener:
            raise SystemExit(f"Gateway listener {name} conflicts with the Axiom contract")
    else:
        patch.append({"op": "add", "path": "/spec/listeners/-", "value": listener})
json.dump(patch, sys.stdout)
' > "${gateway_patch}"
  if [[ "$(cat "${gateway_patch}")" != "[]" ]]; then
    kubectl patch gateway "${GATEWAY_NAME}" --namespace "${GATEWAY_NAMESPACE}" \
      --type=json --patch-file "${gateway_patch}"
  fi
  rm -f "${gateway_patch}"
else
  kubectl apply -f "${SCRIPT_DIR}/gateway-base.yaml"
fi

tls_work_directory="$(mktemp -d /private/tmp/axiom-identity-certificates.XXXXXX)"
trap 'rm -rf "${tls_work_directory}"' EXIT

ensure_tls_secret() {
  local secret_name="$1"
  local hostname="$2"
  local certificate_file="${tls_work_directory}/${secret_name}.crt"
  local private_key_file="${tls_work_directory}/${secret_name}.key"

  if kubectl get secret "${secret_name}" --namespace "${GATEWAY_NAMESPACE}" >/dev/null 2>&1; then
    local secret_type
    secret_type="$(kubectl get secret "${secret_name}" --namespace "${GATEWAY_NAMESPACE}" -o jsonpath='{.type}')"
    if [[ "${secret_type}" != "kubernetes.io/tls" ]]; then
      echo "Secret ${GATEWAY_NAMESPACE}/${secret_name} is not a TLS Secret." >&2
      exit 1
    fi
    kubectl get secret "${secret_name}" --namespace "${GATEWAY_NAMESPACE}" -o jsonpath='{.data.tls\.crt}' \
      | base64 --decode > "${certificate_file}"
  else
    openssl req \
      -x509 \
      -newkey rsa:3072 \
      -sha256 \
      -nodes \
      -days 365 \
      -subj "/CN=${hostname}/O=Meridian Local Development" \
      -addext "subjectAltName=DNS:${hostname}" \
      -keyout "${private_key_file}" \
      -out "${certificate_file}" \
      >/dev/null 2>&1
    chmod 600 "${private_key_file}"
    kubectl create secret tls "${secret_name}" \
      --namespace "${GATEWAY_NAMESPACE}" \
      --cert="${certificate_file}" \
      --key="${private_key_file}"
  fi

  local certificate_sans
  certificate_sans="$(openssl x509 -in "${certificate_file}" -noout -ext subjectAltName)"
  local san_count
  san_count="$(printf '%s' "${certificate_sans}" | grep -o 'DNS:' | wc -l | tr -d ' ')"
  if [[ "${certificate_sans}" != *"DNS:${hostname}"* || "${san_count}" != "1" ]]; then
    echo "Secret ${GATEWAY_NAMESPACE}/${secret_name} must cover only ${hostname}." >&2
    exit 1
  fi
}

ensure_tls_secret "${IDENTITY_TLS_SECRET}" identity.meridian.com
ensure_tls_secret "${ADMIN_TLS_SECRET}" identity-admin.meridian.com

kubectl apply -f "${SCRIPT_DIR}/gateway-routes.yaml"
kubectl wait --for=condition=Accepted gatewayclass/"${GATEWAY_CLASS}" --timeout=5m
kubectl wait --namespace "${GATEWAY_NAMESPACE}" --for=condition=Programmed gateway/"${GATEWAY_NAME}" --timeout=5m

for route in axiom-identity-http axiom-identity-https axiom-admin-http axiom-admin-https; do
  kubectl wait --namespace "${GATEWAY_NAMESPACE}" \
    --for=jsonpath='{.status.parents[0].conditions[?(@.type=="Accepted")].status}'=True \
    httproute/"${route}" --timeout=5m
  kubectl wait --namespace "${GATEWAY_NAMESPACE}" \
    --for=jsonpath='{.status.parents[0].conditions[?(@.type=="ResolvedRefs")].status}'=True \
    httproute/"${route}" --timeout=5m
done

echo "Axiom Envoy edge is ready."
