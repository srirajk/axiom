# RESOURCE-route local server deployment — 2026-10-26

The updated Axiom server is deployed and healthy on Docker Desktop Kubernetes. This is an in-place application
upgrade of the existing estate; no database purge, reinstall, namespace deletion, PVC replacement, credential
rotation, or Argus configuration change was performed.

## Target and image

- Context: `docker-desktop`, Kubernetes `v1.36.4`, namespace `axiom`, Helm release `axiom`.
- Chart: `axiom-0.1.4`; release advanced from revision **1** to **2**, status **deployed**.
- Previous image: `axiom-server:local-14add8a9ce0d57c0` (retained locally for rollback).
- New image: `axiom-server:local-50583213b6f09116`.
- Running image digest: `sha256:1bd2388ba2994704f756eb498a483ba32bbee897e281d43c07eecb6f8aa07075`.
- Running server pod: `axiom-5c6bbb9645-9j5pp`, Ready, zero restarts at verification.

The new image was built locally from the current checkout at `c292924e207feee603faee8f2d8c480972ed918b`, retaining
the pre-existing logout fix. Reconstructing the pre-RESOURCE source fingerprint while retaining that logout fix
produced the exact previously deployed tag, `local-14add8a9ce0d57c0`. The Admin source fingerprint also matched its
installed image, `axiom-admin:local-1e6f2a1fba3a8d42`. No registry image push was needed.

## Upgrade controls

The existing release values, manifest, pod/PVC inventory and operator Secret metadata were saved privately under
`/private/tmp/axiom-resource-local-deploy-20261026/`. A custom-format PostgreSQL backup was taken before the upgrade
at `axiom-before.dump` in that directory (owner-only directory and backup permissions; contents not printed).

Helm lint passed. The installed manifest matched a fresh render with the existing values. Comparing the proposed
render showed exactly one non-hook resource change: the `server` container image in `Deployment/axiom`.
Helm server dry-run and Kubernetes admission dry-run passed.

The upgrade reused the existing values and used atomic rollback protection:

```bash
helm --kube-context docker-desktop upgrade axiom deploy/helm/axiom -n axiom \
  --reuse-values --set-string server.image.tag=local-50583213b6f09116 \
  --no-hooks --atomic --timeout 10m
```

First-install bootstrap hooks were not replayed against the existing database. The server performed its ordinary
Flyway validation on startup: 43 existing migrations validated, current schema **V44**, **no migration necessary**.
The existing in-cluster Helm smoke test was run separately after rollout.

## Verification

- Helm upgrade exited 0; `kubectl rollout status deployment/axiom` succeeded.
- Running pod image digest matched the locally built image's repository digest.
- `helm test axiom -n axiom --logs` passed (`axiom-smoke`, Succeeded).
- `installer.py status` reported `Axiom, dependencies, and local Envoy: READY`.
- HTTPS through the existing Envoy edge and CA passed: readiness `UP`, exact issuer
  `https://identity.meridian.com:8443`, token-exchange grant advertised, JWKS at the discovery-advertised
  `/oauth2/jwks`, and Admin HTML served successfully.
- A first manual probe used an incorrect `/oauth/jwks` path and returned 404; the corrected probe used the advertised
  URI and passed. This was a probe-path correction, not an application change.
- All four PVC UIDs and backing volume names were identical before and after the upgrade.
- PostgreSQL, Redis, Admin and Cerbos pod UIDs and restart counts were unchanged. Their workloads were not rolled.
- Runtime credential and signing-key Secret UIDs/resource versions were unchanged.
- The dependency Helm release remained at revision 1.

Database counts were identical before and after:

| Entity | Count |
|---|---:|
| Tenants | 1 |
| Principals | 79 |
| Applications | 36 |
| Application clients | 33 |
| Customers | 0 |
| Workloads | 27 |
| Exchange routes | 27 |

Detailed build, upgrade, smoke and HTTPS verification records are in the private temporary directory above.
The [source review](resource-route-review-2026-10-26.md) records the Java 25 test matrix: 462 unit tests and
256 integration tests passed, with three intentional external-namespace skips.

## Recovery and boundary

Revision 1 and its local image remain available. If the application must be rolled back, use an image/release rollback
and recheck readiness and Helm smoke; no database restore or schema downgrade is required for this change:

```bash
helm --kube-context docker-desktop rollback axiom 1 -n axiom --no-hooks --wait --timeout 10m
```

Rollback was documented, not executed. No production acceptance or live Argus remote-MCP exchange is claimed.
The owner-managed `argus-mcp` registration/RESOURCE-route configuration remains a separate change. Existing local
hostname resolution, CA trust and port-forward requirements still apply. Existing unrelated source edits were
preserved. At deployment time this record was not committed or pushed; it was incorporated into the local baseline
later, without changing the running image.
