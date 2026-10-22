#!/usr/bin/env bash
set -euo pipefail

if [[ "$(kubectl config current-context)" != "docker-desktop" ]]; then
  echo "Refusing TLS Secret creation outside docker-desktop." >&2
  exit 1
fi
kubectl --context docker-desktop get namespace gateway-demo >/dev/null

for secret_name in axiom-identity-tls axiom-admin-tls; do
  if kubectl --context docker-desktop -n gateway-demo get secret "${secret_name}" >/dev/null 2>&1; then
    echo "Refusing to replace gateway-demo/${secret_name}." >&2
    exit 1
  fi
done

tls_workdir="$(mktemp -d /private/tmp/axiom-local-tls.XXXXXX)"
trap 'rm -rf "${tls_workdir}"' EXIT
chmod 700 "${tls_workdir}"

create_cert() {
  local secret_name="$1"
  local host_name="$2"
  local key_file="${tls_workdir}/${secret_name}.key"
  local cert_file="${tls_workdir}/${secret_name}.crt"
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
    -subj "/CN=${host_name}/O=Axiom Local Test" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=DNS:${host_name}" \
    -keyout "${key_file}" -out "${cert_file}" >/dev/null 2>&1
  chmod 600 "${key_file}"
  kubectl --context docker-desktop -n gateway-demo create secret tls "${secret_name}" \
    --key="${key_file}" --cert="${cert_file}" >/dev/null
  echo "Created gateway-demo/${secret_name} for ${host_name}; key not displayed."
}

create_cert axiom-identity-tls identity.meridian.com
create_cert axiom-admin-tls identity-admin.meridian.com
