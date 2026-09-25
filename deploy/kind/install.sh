#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

for resource in secret/axiom-runtime secret/axiom-signing-key configmap/axiom-cerbos-config configmap/axiom-platform-policies; do
  kubectl get "${resource}" --namespace axiom >/dev/null
done

kubectl apply -f "${SCRIPT_DIR}/dependencies.yaml"
kubectl rollout status statefulset/axiom-postgresql --namespace axiom --timeout=5m
kubectl rollout status statefulset/axiom-redis --namespace axiom --timeout=5m
kubectl rollout status deployment/axiom-cerbos --namespace axiom --timeout=5m

database_exists="$(kubectl exec --namespace axiom axiom-postgresql-0 -- \
  psql -U axiom -d axiom -tAc "SELECT 1 FROM pg_database WHERE datname='axiom_quickstart'")"
if [[ "${database_exists}" != "1" ]]; then
  kubectl exec --namespace axiom axiom-postgresql-0 -- createdb -U axiom axiom_quickstart
fi

helm lint "${ROOT}/deploy/helm/axiom" --values "${SCRIPT_DIR}/values.yaml"
helm upgrade --install axiom "${ROOT}/deploy/helm/axiom" \
  --namespace axiom \
  --values "${SCRIPT_DIR}/values.yaml" \
  --atomic \
  --wait \
  --timeout 15m
helm test axiom --namespace axiom --logs --timeout 5m

"${SCRIPT_DIR}/ensure-envoy-gateway.sh"
