# Deployment readiness assessment — IDP baseline build into `axiom-phase0-test` (read-only, not applied)

**Status: assessment only. Nothing was built into an image, pushed, applied, installed, upgraded or deleted. No
command contacted any Kubernetes cluster while preparing this document** (not even read-only `kubectl get`); facts below
come from the repository manifests and from local, offline renders (`helm template`, `kubectl kustomize`). The test
deployment needs separate, explicit authorization. Scope: the `axiom-phase0-test` namespace only, kube context
`docker-desktop` (as fixed by `deploy/phase0-isolated/harness/phase0_harness.py`).

## 1. What would be deployed

| Item | Source | Notes |
|---|---|---|
| Server image | `server/Dockerfile`, built from this tree | new tag required (e.g. `axiom-server:phase0-idp-<fingerprint8>`); the values file still names `phase0-codex-74e7e56`, which does **not** contain the IDP baseline |
| Admin image | `admin/Dockerfile` | unchanged by this work; may keep its current tag |
| Release | Helm chart `deploy/helm/axiom`, values `deploy/phase0-isolated/values.yaml` | renders 2 Deployments, 3 Jobs (pre-install/pre-upgrade `preflight`, `bootstrap`; `verify`), 1 test Pod, 2 Services, 1 ConfigMap, 5 ServiceAccounts (all `automountServiceAccountToken: false`); no Role, RoleBinding or cluster-scoped object |
| Dependencies | `kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/phase0-isolated` | PostgreSQL 16 and Redis 7 StatefulSets, Cerbos 0.53.0 Deployment, 3 Services, 2 PVCs, 7 NetworkPolicies, ResourceQuota, LimitRange — **and a cluster-scoped `Namespace/axiom-phase0-test`** (see §4) |
| Database change | Flyway `V40__interactive_client_population_and_consent.sql` on the namespace's own PostgreSQL | forward-only: adds `population`, widens two CHECK constraints, creates `oauth2_authorization_consent` |

Server configuration added by this work (all environment variables, rendered by `_helpers.tpl`):
`IAM_AUTH_LEGACY_PASSWORD_LOGIN_ENABLED` (**true** in `deploy/phase0-isolated/values.yaml`, an explicit opt-in because the
Phase 0 harness still logs in with `POST /auth/login`; chart default false), `IAM_AUTH_IMPERSONATION_ENABLED` (false),
`IAM_OAUTH2_INTERACTIVE_ACCESS_TOKEN_TTL`/`_MAX_TTL` (PT1H/PT1H), `IAM_OAUTH2_REFRESH_TOKEN_TTL`/`_MAX_TTL` (PT8H/P30D).
`IAM_CIAM_LOCAL_DEMO_CHALLENGE_DISCLOSURE` stays false (no simulated customer-code disclosure in the namespace).

## 2. Namespace-scoped permissions the deploying identity needs

In `axiom-phase0-test` only: get/list/watch/create/update/patch/delete on Deployments, StatefulSets, Jobs, Pods
(including `pods/log`, `pods/portforward` for the harness and `helm test`), Services, ConfigMaps, ServiceAccounts,
PersistentVolumeClaims, NetworkPolicies, ResourceQuotas, LimitRanges; get/list/create/update/delete on Secrets (Helm
stores release state as Secrets in the release namespace); get (metadata only) on the operator-owned Secrets
`axiom-runtime` and `axiom-signing-key`. No ClusterRole, no access to other namespaces, no node or storage-class rights.

## 3. Secrets and isolation

* Secrets are operator-owned and must exist before install: `axiom-runtime` (keys `spring.datasource.password`,
  `iam.secrets.master-key`, `axiom.bootstrap.admin-password`, …) and `axiom-signing-key` (`signing-key.json`,
  `jwks.json`; `deploy/helm/axiom/scripts/create-signing-secret.py`). Readiness check: confirm presence by name only;
  do not read values. Helm never renders secret values.
* Database and Redis are the namespace's own StatefulSets (`axiom-postgresql`, `axiom-redis`); NetworkPolicies
  default-deny and allow only the Axiom pods and the probe/harness to reach them. Redis key prefix `axiom:oauth2`.
  New Redis keys from this work: `…:spent-refresh:*`, `…:refresh-redemption-lock:*`, `…:client-assertion-jti:*`
  (all TTL-bounded).
* No change widens access: the new endpoints are Axiom's own (`/login/customer`, consent pages, CIAM consent API); the
  NetworkPolicy allow-list is unchanged.

## 4. Cluster-scoped and shared-environment effects (stop points)

1. **Namespace object.** The kustomization renders `Namespace/axiom-phase0-test` (renamed by kustomize from
   `axiom` in `deploy/kind/dependencies.yaml`) with `pod-security.kubernetes.io/*: restricted` labels. Applying it
   would create or patch a cluster-scoped object. **Recommendation:** exclude the Namespace document from the apply
   (the namespace already exists) or obtain explicit approval for that object alone; verify first, read-only, that the
   live labels already match.
2. **Dynamic volume provisioning.** The two PVCs set no `storageClassName`; if not already bound, the default
   StorageClass provisions cluster-scoped PersistentVolumes. Expect the existing claims to be reused (StatefulSet
   volume claims as well); a fresh install would create PVs.
3. **Container images.** Building the new server image writes to the local Docker daemon that the `docker-desktop`
   cluster shares; the nodeSelector `kubernetes.io/hostname: desktop-worker` must be able to pull/see that image.
   This is shared-host state outside the namespace (image tags only; no registry push).
4. **Schema migration.** V40 is forward-only in the namespace's database (see §6 for rollback behaviour).

No ClusterRole/ClusterRoleBinding, CRD, webhook, IngressClass, Gateway or PriorityClass is part of the
`axiom-phase0-test` render. The Gateway/HTTPRoute manifests in `deploy/kind/gateway-*.yaml` are **not** included and must
not be applied.

## 5. Proposed gated sequence (for later approval; not executed)

1. Read-only pre-checks (namespace only): `helm --kube-context docker-desktop -n axiom-phase0-test status axiom`;
   `kubectl --context docker-desktop -n axiom-phase0-test get deploy,sts,pvc,netpol,secret -o name`; record the current
   image tag and Helm revision for rollback.
2. Build `axiom-server:phase0-idp-<fingerprint8>` from this tree (record the source fingerprint and image digest).
3. `helm --kube-context docker-desktop -n axiom-phase0-test upgrade axiom deploy/helm/axiom -f
   deploy/phase0-isolated/values.yaml --set server.image.tag=phase0-idp-<fingerprint8> --wait --timeout 10m`
   (dependencies unchanged; do **not** re-apply the kustomization unless §4.1 is resolved).
4. Smoke: `helm test axiom` (readiness, discovery issuer, admin UI) and the verify Job; then the Phase 0 harness
   (`--execute`) for V-1…V-10; then a namespace-bounded subset of the IDP contracts through a port-forward
   (discovery, client credentials, exchange, introspection, refresh, logout) — with the cookbook's target guard
   explicitly allowing the port-forwarded loopback target and a fixture namespace.
5. Record evidence (commands, revision, image digest, results) without token values.

## 6. Rollback

`helm --kube-context docker-desktop -n axiom-phase0-test rollback axiom <previous-revision> --wait`. The previous image
starts against the V40 schema: Flyway's default `ignoreMigrationPatterns=*:future` tolerates an applied future
migration and Hibernate `validate` ignores the extra column and table. **Caveat:** application clients created with
the new type `CONFIDENTIAL_WEB` cannot be loaded by older code (unknown enum value); disable them (management API)
before rolling back, or roll forward. Refresh tokens and consents issued by the new build are simply unused by the old
build. Redis keys expire on their own.

## 7. Blocking items before requesting authorization

* Decide §4.1 (exclude or approve the Namespace object) and confirm PVC binding (§4.2).
* Approve the image build on the shared Docker host (§4.3).
* Migrate the Phase 0 harness from `/auth/login` to the authorization-code flow, or keep the explicit
  `config.auth.legacyPasswordLogin: true` opt-in for this namespace (current state, documented in the values file).
