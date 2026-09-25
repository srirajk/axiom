#!/usr/bin/env bash
set -euo pipefail

service_name="$(kubectl get service \
  --namespace envoy-gateway-system \
  --selector gateway.envoyproxy.io/owning-gateway-namespace=gateway-demo,gateway.envoyproxy.io/owning-gateway-name=meridian-edge \
  --output jsonpath='{.items[0].metadata.name}')"

if [[ -z "${service_name}" ]]; then
  echo "The gateway-demo/meridian-edge data-plane Service was not found." >&2
  exit 1
fi

echo "HTTP  http://identity.meridian.com:8080"
echo "HTTPS https://identity.meridian.com:8443"
echo "Admin https://identity-admin.meridian.com:8443"

exec kubectl port-forward \
  --namespace envoy-gateway-system \
  "service/${service_name}" \
  --address 127.0.0.1 \
  8080:80 \
  8443:443
