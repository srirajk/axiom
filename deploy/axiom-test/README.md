# Disposable internal-only `axiom-test` release on Docker Desktop

For the current fresh-cluster Axiom + Envoy Gateway edge, use
[`deploy/axiom-local-edge/README.md`](../axiom-local-edge/README.md) instead. This profile has no Envoy edge.

This is the **new** isolated Axiom test estate. It does not use the old `axiom-phase0-test` namespace, the original
`axiom` installation, the Argus rollout, a GatewayClass, Ingress, NodePort or LoadBalancer. Both Helm releases are
namespace-scoped. Do not use these values on a shared or production cluster: the issuer uses internal HTTP, Redis is
network-isolated rather than password-protected, and the local policy-runtime PVC is ReadWriteOnce.

## Prerequisites and boundaries

- Docker Desktop Kubernetes context `docker-desktop`, with worker `desktop-worker` and a dynamic StorageClass.
- The local images `postgres:16`, `redis:7-alpine`, `ghcr.io/cerbos/cerbos:0.53.0` and the server/admin images below.
- No concurrent writer or build in this checkout. Do not install if chart lint/render or image build fails.
- The two releases must be installed **in order**: `axiom-dependencies` first, then `axiom`. Axiom's pre-install
  bootstrap hook needs live PostgreSQL, Redis, Cerbos and the policy-runtime PVC.
- The namespace contains disposable data only. Deleting it also deletes its PVCs and locally provisioned PVs; this
  is intentionally irreversible. A plain `helm uninstall` keeps claims, for safer recovery.

From the Axiom clone root, verify the target and the source image:

```bash
kubectl config current-context                                      # must be docker-desktop
kubectl --context docker-desktop get ns axiom-test                  # NotFound before first install
helm lint deploy/helm/axiom-dependencies -f deploy/axiom-test/dependencies-values.yaml
helm lint deploy/helm/axiom -f deploy/axiom-test/values.yaml
docker build --pull=false -f server/Dockerfile -t axiom-server:axiom-test-20261003b .
docker image inspect axiom-server:axiom-test-20261003b --format '{{.Id}}'
docker image inspect axiom-admin:phase0-codex-74e7e56 --format '{{.Id}}'
```

The server image tag in `values.yaml` is deliberately specific to this build. If the source changes, use a new tag,
update that file, rebuild and record the resulting image ID. Never use the old Phase 0 server tag for this profile.

## Create exactly this namespace and operator-owned Secrets

```bash
kubectl --context docker-desktop create namespace axiom-test
kubectl --context docker-desktop label namespace axiom-test \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
python3 deploy/axiom-test/create-runtime-secret.py
python3 deploy/helm/axiom/scripts/create-signing-secret.py \
  --context docker-desktop --namespace axiom-test --name axiom-signing-key --apply
kubectl --context docker-desktop -n axiom-test get secret axiom-runtime axiom-signing-key
```

The runtime-secret helper creates fresh database, master-key and bootstrap-admin credentials without printing or
writing them to disk. The signing helper creates a fresh immutable 3072-bit RSA JWK Secret in the explicitly named
context. Neither chart owns the Secrets, and neither
Secret is placed in Helm release history. The bootstrap administrator password is available only to an authorized
namespace Secret reader. Do not paste it into a ticket or log.

## Install and test

```bash
helm --kube-context docker-desktop upgrade --install axiom-dependencies deploy/helm/axiom-dependencies \
  -n axiom-test -f deploy/axiom-test/dependencies-values.yaml --wait --timeout 10m
kubectl --context docker-desktop -n axiom-test rollout status statefulset/axiom-postgresql --timeout=5m
kubectl --context docker-desktop -n axiom-test rollout status statefulset/axiom-redis --timeout=5m
kubectl --context docker-desktop -n axiom-test rollout status deployment/axiom-cerbos --timeout=5m
helm --kube-context docker-desktop test axiom-dependencies -n axiom-test --logs

helm --kube-context docker-desktop upgrade --install axiom deploy/helm/axiom \
  -n axiom-test -f deploy/axiom-test/values.yaml --atomic --timeout 15m
helm --kube-context docker-desktop test axiom -n axiom-test --logs
kubectl --context docker-desktop -n axiom-test get pods,svc,pvc,networkpolicy

# Prove the CNI enforces the denial, then remove only these short-lived probe pods.
kubectl --context docker-desktop -n axiom-test apply -f deploy/axiom-test/network-canary.yaml
kubectl --context docker-desktop -n axiom-test wait --for=jsonpath='{.status.phase}'=Succeeded \
  pod/axiom-test-network-canary pod/axiom-test-admin-network-canary --timeout=60s
kubectl --context docker-desktop -n axiom-test logs pod/axiom-test-network-canary
kubectl --context docker-desktop -n axiom-test logs pod/axiom-test-admin-network-canary
kubectl --context docker-desktop -n axiom-test delete pod \
  axiom-test-network-canary axiom-test-admin-network-canary
```

The dependency Helm test checks network reachability and liveness of PostgreSQL, Redis and Cerbos, not an authenticated
database query. The app Helm test checks readiness, exact discovery issuer, Admin UI and CIAM runtime configuration.
These tests do **not** certify the full IDP-01–12 cookbook. Record the exact test logs, image ID and `helm status`
before claiming the release is ready.
Both canary logs must say access was denied; `UNEXPECTED_*_REACHABILITY` or a Failed pod is a security stop, not a
passing result. NetworkPolicy objects alone do not prove enforcement.

## Generic identity quickstart

The active integration guide is [the Axiom identity cookbook](../../examples/identity_scenarios/README.md), with
IDP-01–12 coverage and separate workforce/CIAM examples. It uses real Axiom HTTP APIs, PostgreSQL and Redis in its
**own disposable local estate** by default. Its target guard intentionally refuses `*.svc.cluster.local` and
shared-looking hosts. Do not weaken that guard or point destructive cookbook tests at this Helm namespace just to
obtain a green report. Run the cookbook's normal local suite independently; use the in-cluster Helm smoke tests and
read-only discovery checks to prove this deployment.

For read-only discovery through a loopback port-forward, use a dedicated terminal:

```bash
kubectl --context docker-desktop -n axiom-test port-forward service/axiom 18084:8084
```

Then, in another terminal:

```bash
curl --fail --silent --show-error http://127.0.0.1:18084/actuator/health/readiness
curl --fail --silent --show-error http://127.0.0.1:18084/.well-known/openid-configuration
```

The discovery document must advertise `http://axiom.axiom-test.svc.cluster.local:8084` as issuer; the port-forward
does not rewrite the issuer. A browser or external relying party cannot use that internal issuer without an explicit,
separately reviewed transport/issuer design. No public ingress is created by this profile.

## Recovery and teardown

If the app install fails, inspect only this namespace's hook Jobs/pods and dependency health. Do not delete the
database or rotate signing keys as a first repair. The app chart's pre-install hooks may leave service accounts;
`python3 deploy/helm/recover_hook_service_accounts.py -n axiom-test --release axiom` previews exact cleanup.

To stop the app while retaining the database and claims:

```bash
helm --kube-context docker-desktop uninstall axiom -n axiom-test
```

Only when this exact test estate is no longer needed and its data is confirmed disposable, delete
`namespace/axiom-test` (after removing both releases). Namespace deletion also removes retained claims and locally
provisioned PVs, unlike Helm uninstall. Never run that cleanup against any other namespace.
