#!/usr/bin/env bash
set -euo pipefail

if [[ "$(kubectl config current-context)" != "docker-desktop" ]]; then
  echo "Refusing to expose a Gateway outside docker-desktop." >&2
  exit 1
fi

gateway_service="$(kubectl --context docker-desktop -n envoy-gateway-system get service \
  --selector gateway.envoyproxy.io/owning-gateway-namespace=gateway-demo,gateway.envoyproxy.io/owning-gateway-name=axiom-local-edge \
  -o jsonpath='{.items[0].metadata.name}')"
if [[ -z "${gateway_service}" ]]; then
  echo "No Axiom local Envoy data-plane Service found." >&2
  exit 1
fi
service_type="$(kubectl --context docker-desktop -n envoy-gateway-system get service "${gateway_service}" -o jsonpath='{.spec.type}')"
if [[ "${service_type}" != "ClusterIP" ]]; then
  echo "Refusing to port-forward non-ClusterIP service ${gateway_service}." >&2
  exit 1
fi

echo "Forwarding Axiom Envoy only on 127.0.0.1:8080 and 127.0.0.1:8443; Ctrl-C stops it."
exec kubectl --context docker-desktop -n envoy-gateway-system port-forward \
  "service/${gateway_service}" --address 127.0.0.1 8080:80 8443:443
