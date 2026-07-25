# 05 — Rollout, Rollback and Operations

## 1. Configuration

Introduce explicit configuration; do not infer production behavior from hostname:

```text
UAC_IDENTITY_PROVIDER=local|axiom
UAC_BROWSER_AUTH_MODE=demo_password|oidc_pkce
UAC_PLATFORM_AUTHZ_PROVIDER=code|axiom_shadow|axiom
UAC_PLATFORM_AUTHZ_CUTOVER_MANIFEST=
UAC_AXIOM_BASE_URL=
UAC_AXIOM_JWKS_URL=
UAC_AXIOM_ISSUER=
UAC_AXIOM_AUDIENCE=probata-api
UAC_AXIOM_TENANT_ID=
UAC_AXIOM_SERVICE_CLIENT_ID=
UAC_AXIOM_SERVICE_CLIENT_SECRET_REF=
UAC_AXIOM_SOURCE_REVISION=
UAC_AXIOM_PLATFORM_POLICY_BUNDLE=
UAC_AUTHZ_CACHE_TTL_SECONDS=0..60
AXIOM_UPSTREAM_OIDC_ISSUER=
AXIOM_UPSTREAM_OIDC_CLIENT_ID=
AXIOM_UPSTREAM_OIDC_CLIENT_SECRET_REF=
AXIOM_UPSTREAM_OIDC_REQUIRED=true
```

Production startup requires:

```text
identity_provider == axiom
browser_auth_mode == oidc_pkce
platform_authz_provider == axiom
persistent signing-key reference exists
issuer/audience/tenant are explicit
service secret is a reference, not inline demo value
upstream customer-IdP issuer/client/secret reference is explicit
source revision and expected contract version match health metadata
```

### 1.1 Route-family cutover manifest

AXM-5 replaces ad hoc per-route flags with one reviewed, detached-signature-verified manifest:

```yaml
schema_version: probata.platform-authz-cutover.v1
manifest_id: axm-cutover-2026-07-23-01
route_inventory_hash: sha256:...
axiom_source_revision: 9fa1c948...
contract_version: "1.0"
policy_bundle_id: b_platform_20260723_01
issued_at: 2026-07-23T12:00:00Z
issued_by: platform-release
approval_ids: [architect-review-id, security-review-id, product-owner-review-id]
families:
  navigation:
    provider: axiom
    route_ids: [me.capabilities, navigation.read]
    owner: identity-platform
    rollback_runbook: runbooks/axiom-route-family-rollback.md
  resource_reads:
    provider: code
    route_ids: [agents.list, agents.get]
    owner: probata-api
    rollback_runbook: runbooks/axiom-route-family-rollback.md
signature_ref: deployment-secret://axiom-cutover-signature
```

The closed route-family vocabulary is navigation/capability hydration, pure lists, disclosure-sensitive
resource reads, ordinary mutations, workflows/certification, and administration/audit/API-key
management. Every gate-inventory route appears exactly once; duplicate, missing, unknown or
hash-mismatched routes fail startup. The manifest cannot select a provider not allowed by the global
deployment mode. A rollback is a newly approved/signed manifest revision, never a caller header or an
in-place edit. AXM-6 replaces transitional mixed manifests with an all-Axiom production invariant.

## 2. Environment topology

The reference deployment adds/updates:

```text
axiom-db
axiom-redis                  # isolated DB/key prefix
axiom                       # pinned source/image
axiom-admin                 # separate Axiom identity/platform-policy console
axiom-platform-cerbos/store # distinct from Probata governance Cerbos
probata-api
probata-frontend
```

One customer deployment still equals one Probata isolation boundary. Axiom's multi-tenant hardening is
retained, but the configured token tenant must equal the one deployment tenant.

The AXM-1 platform-policy store is split into two mounts: the pinned curated package is read-only at
Cerbos `/policies/base`, while the durable writable runtime volume is `/policies/runtime` and is the only
target of Studio promotion (`/app/runtime-policies` in Axiom). Publication writes temporary same-directory
objects, atomically replaces each target, and reads each object back before the serving-readiness probe. A
Cerbos restart therefore retains promoted versions without allowing a stale one-time copy to overwrite the
curated source. The one-shot bootstrap creates the first signing key only with its explicit non-HTTP mode;
normal runtime fails startup when the key volume is empty.

## 3. Release sequence

### R0 — Baseline

- capture current CodeMatrix golden corpus and live persona proof;
- capture current Axiom identity source/DB state;
- back up Axiom DB and signing material;
- freeze the approved source pins.

### R1 — Parallel refreshed Axiom

- launch refreshed Axiom service, Axiom Admin and platform Cerbos against a fresh DB/Redis/key/policy namespace;
- provision the Probata tenant/personas through supported APIs;
- compile/probe the curated platform-policy bundle and smoke identity/Policy Studio/audit routes;
- compare identity, roles, domains, clients and issuer metadata;
- do not change the Probata issuer yet.

### R2 — Authentication switch

- register Probata clients and redirects;
- enable PKCE in a non-production environment;
- run full auth/browser tests;
- switch Probata to the refreshed issuer;
- keep platform authorization on `code`.

### R3 — Authorization shadow

- deploy the Axiom decision endpoint and approved platform bundle;
- select `axiom_shadow`;
- observe the required traffic window;
- resolve every mismatch;
- sign the zero-unexplained-divergence report.

### R4 — Controlled platform cutover

- cut over route families in the AXM-5 order;
- run focused and full gates after each family;
- rehearse rollback;
- cut the next family only after acceptance.

### R5 — Production closure

- set all production startup guards;
- retire legacy paths after the compatibility window;
- complete DR, security and user acceptance;
- update the release ledger.

## 4. Rollback

### 4.1 Axiom source/authentication rollback

Use blue/green issuer rollback:

- retain the prior Axiom service and database read-only during the rollback window;
- do not point an older binary at a newer schema;
- switch the Probata issuer/JWKS/client configuration as one versioned deployment change;
- invalidate sessions if issuer/key compatibility cannot be guaranteed;
- verify identity/persona scope before reopening traffic; and
- record the rollback in both operational and security audit.

### 4.2 Platform authorization rollback

Before AXM-6 removes production `code` mode, an operator may revert a route-family manifest to CodeMatrix
only under the approved rollback runbook:

- declare incident and route families;
- preserve Axiom decision/audit evidence;
- switch the deployment configuration, never a request header;
- run the focused no-disclosure/RLS/SoD gate;
- record start/end/reason/approver; and
- reopen shadow comparison before attempting cutover again.

This is a signed deployment transition that ends Axiom authority for the named route families; it is not
a request-time fallback. While a route family remains in `axiom` mode, every Axiom outage, timeout or
invalid response denies.

Rollback is not automatic on Axiom outage. Automatic fallback could convert an outage into an access
grant. The runtime behavior remains fail closed until a human executes the governed rollback.

### 4.3 Policy rollback

A platform-policy rollback is a new candidate/review/approval/activation of a prior immutable bundle. It
does not mutate a bundle or directly rewrite an active pointer.

### 4.4 Database rollback

- Flyway down-migrations are not assumed safe.
- Prefer forward repair or blue/green database replacement.
- Never delete customer identity/audit data.
- Demo reset may replace only the named demo Axiom volume through `scripts/reset.sh`; preserve base images.

## 5. SLOs and alerts

Initial values are hypotheses and must be measured:

| Signal | Initial objective |
|---|---|
| JWKS cache refresh success | 99.9% |
| subject-context p95 | ≤100 ms on local deployment network |
| decision-batch p95 | ≤100 ms for representative batch |
| entitlement revocation propagation | ≤60 s |
| platform-policy activation propagation | ≤60 s |
| unexplained shadow mismatch | 0 |
| decision batch missing/malformed result | 0 |
| authorization cache stale-revision use | 0 |
| cross-tenant allow | 0 |

Alerts distinguish:

- identity/JWKS unavailable;
- subject-context unavailable;
- platform-decision unavailable;
- policy bundle missing/stale;
- Redis OAuth/cache unavailable;
- invalidation lag;
- parity mismatch;
- authorization latency;
- rejected cross-tenant request; and
- startup contract/version mismatch.

## 6. Runbooks

AXM-6 produces:

- Axiom source refresh and pin verification;
- client/redirect/audience registration;
- tenant/persona provisioning;
- signing-key creation, rotation and restore;
- Redis OAuth backup/outage recovery;
- platform-policy promotion and rollback;
- authorization shadow divergence investigation;
- route-family cutover/rollback;
- subject disable/role/domain revocation;
- Axiom outage and degraded Probata behavior;
- blue/green Axiom database migration; and
- correlated Axiom/Probata authorization audit reconstruction.

## 7. Demo

```text
1. Open Probata.
2. Sign in through Axiom as Daniel, Banking Steward.
3. Show /api/auth/me and the Banking-scoped estate.
4. Open one Banking Agent and show an allowed governed action.
5. Attempt a hidden Wealth Agent and show no-disclosure.
6. In Axiom, remove Daniel's Banking assignment using an authorized administrator.
7. Return to Probata without renewing the original access token.
8. Show the entitlement revision changed and Banking access disappeared.
9. Show the Axiom decision call ID and correlated Probata audit entry.
10. Stop or isolate Axiom decision service.
11. Show Probata's honest authorization-unavailable state and prove no grant.
12. Restore Axiom and show recovery.
```

The demo does not touch a clearance, evidence score, assurance obligation or attestation. Its purpose is
to prove the platform access loop while keeping governance authority separate.
