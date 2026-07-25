# 04 — Acceptance Matrix

## 1. Universal story contract

Every AXM story must provide:

1. observable user/operator result;
2. named positive and negative tests;
3. tenant and no-disclosure proof where applicable;
4. failure/outage behavior;
5. audit/correlation evidence for consequential actions;
6. migration and rollback evidence;
7. no change to Probata governance clearance; and
8. an independent reviewer disposition for security/authority changes.

“Endpoint exists,” “tests added,” “service starts,” and “diff complete” are not acceptance outcomes.

The separate governance-policy realization acceptance and Definition of Done are normative in
`06-policy-realization.md` §10. AXM acceptance cannot be used to claim that Enterprise,
Business-line or Use-case agent-governance policy is decision-provable.

## 2. AXM-0

| Story | Given / When / Then | Negative proof | Evidence |
|---|---|---|---|
| 001 | Given the approved Axiom ref, when the manifest is generated, then commit, subtree, tree hash and exclusions reproduce exactly. | dirty/untracked/generated source cannot silently enter the pin. | manifest, Git tree transcript |
| 002 | Given both implementations, when disposition runs, then every identity/authz/config/test/runtime file is keep/evolve/replace/retire/exclude. | no unclassified conflicting file. | disposition report |
| 003 | Given every gate call, when normalized, then it has exact permission, resource kind, domain/owner inputs and disclosure class. | unknown/untyped gate fails architecture test. | route inventory |
| 004 | Given contract fixtures, when Java/Python serializers run, then request/response/event JSON is byte-compatible. | unknown effect, attribute, missing result, tenant mismatch reject. | cross-language contract report |
| 005 | Given the current matrix and fixture principals/resources, when generated twice, then corpus and hash are identical. | no hand-maintained expected decisions or skipped permission. | corpus hash, coverage report |
| 006 | Given current production mode, when baseline flows run, then login, domain scope, no-disclosure and M2M behavior are captured unchanged. | no claim that Axiom decisions are live. | baseline harness/screens |
| 007 | Given a Probata release, when examined, then exact Axiom source/policy/client contract versions are reconstructable. | incompatible pair fails startup/CI. | version-pair ledger |

## 3. AXM-1

| Area | Required acceptance | Required negative/failure proof |
|---|---|---|
| source refresh | service/admin/policy files equal their pinned trees or canonical policy allowlist after explicit overlays | generated jar/dist/node_modules, `.wolf`, gateway, registry, demo users, Conduit policies and unknown files rejected |
| Java build | clean multi-stage source build on pinned JDK/Spring/dependencies | local `target/` absence cannot break build |
| Axiom Admin | clean locked-package build and live identity/Policy Studio/audit routes in `probata-platform` mode against imported Axiom | no browser secret; no gateway call, hardcoded `agent` default, excluded Conduit route/vocabulary or mock data |
| platform Cerbos | exact curated IAM/Policy Studio/templates/meta-authz allowlist compiles and its live probe succeeds | Conduit agent/domain/relationship/insights or Probata governance policy in the bundle fails the manifest gate |
| Studio grounding | exact AXM contract hash, approved Axiom catalogue and active platform ceiling produce a deterministic grounding snapshot bound to review/promotion | missing/stale/hash-mismatched contract, Conduit registry reference or unknown resource/action blocks readiness and promotion |
| database | fresh V1–V14 schema validates and API provisioning creates Probata tenant/personas | checksum mismatch blocks; no customer DB destructive reset |
| migration disposition | every V1–V14 statement is classified and the UAC overlay hash is reproducible | fresh pre-provision database contains any demo/default/Meridian identity, grant, agent, relationship/book row or policy bundle |
| source denylist | import/build manifest contains only approved product components and recorded overlays | legacy policy APIs, relationship/book routes, Admin `Policies`, Gateway/Registry/Agent/Insights dependency or denied Cerbos file fails CI/startup |
| Redis OAuth | authorization code/consent/token state survives IAM process restart | wrong DB/prefix or Redis outage fails readiness/token flow safely |
| signing key | same `kid` and valid existing token after restart; documented rotation works | missing production key fails startup; invalid old key cannot mint |
| clients | public/no-secret/S256-only `probata-spa` and durable confidential tenant-bound `probata-api` survive restart with allowlisted redirects/audiences/scopes | browser secret, non-PKCE/plain challenge, wrong redirect, client, audience, scope or tenant-qualified audience rejected |
| compatibility | all approved Probata personas resolve to expected identity and scope | unknown/inactive/legacy-only persona cannot inherit default tenant/grant |
| product parity | CodeMatrix results and all Probata governance decisions remain unchanged | product refresh cannot activate Axiom decisions for Probata actions |

AXM-1 lifecycle hardening also requires V13's audited two-person durable-BUSY reconciliation and V14's
promotion execution fence. A promotion fence is held across external staging/publication, synchronously
rechecks its durable owner immediately before the terminal CAS, and safely replays after a crashed session
only after PostgreSQL confirms the old advisory session is gone. A live owner remains BUSY; no expiry-only
takeover is permitted.

## 4. AXM-2

### 4.1 Authentication

- Valid authorization-code + verifier + state + nonce produces one authenticated Probata session.
- Customer IdP authentication returns through Axiom federation; Probata accepts only the stable Axiom
  issuer and Axiom principal subject.
- Exact `(upstream_issuer, upstream_subject)` maps to one approved tenant principal; unknown, duplicate,
  inactive, email-only and cross-tenant links deny without JIT default grants.
- Reuse of code/state/verifier fails.
- Missing/wrong issuer, signature, `kid`, audience, tenant, expiration or token type fails closed.
- Token tenant and configured deployment tenant mismatch returns a non-disclosing authentication failure.
- Signing-key rotation accepts only the declared overlap window.
- Logout clears the local session and performs the configured OIDC end-session behavior.
- Production configuration refuses `identity_provider=local`, insecure JWT secret, shared demo password or
  password-proxy login.

### 4.2 Live subject context

- Active subject returns allowlisted roles/domains/attributes and stable revision.
- Role, domain, active-state or relevant attribute change changes the revision.
- Probata sees the new context without waiting for the bearer token to expire.
- Unknown/inactive/cross-tenant subject fails closed.
- Axiom outage returns `503 Identity unavailable` with a correlation ID, never an empty role set that might
  have ambiguous semantics.
- JWT/live mismatch records only hashes and bounded reason codes.
- `/me` and `/capabilities` never render permissions decoded by the browser.

### 4.3 Frontend

Playwright covers:

- first login;
- callback/reload;
- expired session;
- logout;
- Axiom unavailable;
- unauthorized redirect;
- deep-link return;
- keyboard and screen-reader status;
- no password form in production mode; and
- demo-mode password form only under the explicit flag.

## 5. AXM-3

### 5.1 Decision contract

For every batch:

- caller is an authorized Probata service client;
- request tenant equals subject tenant;
- decision keys are unique;
- every input has one output;
- output order or keys allow deterministic joining;
- unknown/duplicate/missing/malformed results make the Probata adapter deny;
- outcome, effect and `allowed` agree, including `cosign → require_cosign → allowed=false`;
- exact entitlement revision and active platform bundle are present;
- one call ID exists per result; and
- trace/correlation identifiers survive Axiom and Probata audit.

### 5.2 Platform policy

The live Axiom policy bundle must reproduce:

- every current human permission/effect;
- cross-domain and domain-scoped behavior;
- owner/self behavior;
- Builder relationship semantics;
- independent Risk/Model Validator/Executive/Auditor read boundaries;
- Admin setup boundaries;
- `cosign` workflows;
- unknown permission/resource default deny; and
- M2M separation where human decisions are queried.

The golden corpus includes at least one ALLOW and DENY for every permission and every non-DENY role
effect where logically possible.

### 5.3 Security

- caller-supplied roles/permissions/domains are absent from the public decision request or ignored and
  rejected if present;
- service client cannot administer users/policy;
- decision endpoint cannot be called anonymously or with a human UI token;
- service tokens with the wrong audience/scope or a client registered to another tenant deny;
- routers cannot substitute a caller-controlled tenant/subject for the immutable verified identity;
- cross-tenant subject/resource/service requests deny;
- hidden resource identifiers are hashed/redacted in the appropriate audit;
- policy default is deny when a required layer/input is absent;
- wildcard grants fail lint/approval;
- author cannot approve;
- stale review hash cannot promote;
- active pointer changes atomically; and
- rollback is independently reviewed and audited.

### 5.4 Reliability/performance

- bounded batch size and request body;
- deadline, circuit breaker and rate limit behavior;
- partial internal evaluation becomes an explicit failed batch, never implicit allow;
- Postgres/Redis/PDP/policy-store outage matrix;
- restart and policy reload proof;
- invalidation outbox atomicity, duplicate delivery, sequence-gap detection and cursor replay for both
  entitlement and policy events;
- replay/idempotency for decision audit where required; and
- p95 latency/load envelope recorded for representative navigation, list and mutation traffic.

## 6. AXM-4

| Proof | Pass condition |
|---|---|
| gate coverage | 100% current authorization calls use the typed port; architecture test finds no direct bypass |
| batch behavior | navigation/capabilities/list operations are bounded batches, not per-row remote calls |
| golden parity | zero unexplained mismatch across frozen corpus |
| live parity | zero unexplained mismatch across representative personas/actions/resources for the observation window |
| error classification | timeout, unavailable, malformed, policy missing and semantic mismatch are distinguishable |
| diagnostics | bounded reason/counters; no hidden key, raw entitlement list or high-cardinality subject in metrics |
| cache | exact contract/revision/bundle/permission/resource/context key, TTL ≤60s, invalidation, no stale-if-error grant |
| RLS | Axiom allow cannot cross tenant or bypass PostgreSQL RLS |
| no-disclosure | hidden direct reads remain 404 and hidden list counts/facets do not leak |
| governance parity | eligibility, evidence, decision and attestation hashes remain unchanged |

Any mismatch is classified:

```text
implementation defect
policy defect
resource-normalization defect
approved intentional semantic change
fixture defect
```

An “approved intentional change” requires Product Owner, Architect and Security signatures and a new
golden-corpus version. It cannot be self-approved by the implementer.

## 7. AXM-5

For each route-family cutover:

1. shadow report is green;
2. cutover manifest lists routes, policy bundle, adapter version, owner and rollback;
3. Axiom is the sole response authority;
4. CodeMatrix mismatch is telemetry only;
5. Axiom deny/timeout/malformed/missing denies;
6. product SoD and RLS still run;
7. full focused API/persona/no-disclosure tests pass;
8. live authorized and denied examples are captured; and
9. rollback is rehearsed before the next family.

Required outage truth table:

| Condition | Result |
|---|---|
| valid Axiom allow | continue to Probata SoD/RLS |
| valid Axiom deny | 403 or no-disclosure 404 as resource contract requires |
| Axiom timeout/unavailable | 503/degraded, no grant |
| malformed/incomplete response | deny/degraded, alert |
| stale/unknown policy bundle | deny/degraded |
| cache hit at current revisions | honor cached exact decision |
| cache entry at old entitlement/policy revision | miss and re-evaluate |
| CodeMatrix says allow but Axiom denies | deny; parity alert |
| CodeMatrix says deny but Axiom allows | Axiom result proceeds only after cutover, but critical parity alert and incident policy apply |

The last row is not silently ignored: if it breaches the approved parity policy, the route-family cutover
is rolled back through the declared operator procedure.

## 8. AXM-6

- production startup guard rejects all transitional modes/secrets;
- source manifest and SBOM match the built Axiom image;
- Axiom database, Redis OAuth state, signing key and policy bundles have backup/restore proof;
- restore preserves or intentionally rotates `kid` with documented session consequence;
- entitlement and platform-policy invalidation SLOs have dashboards/alerts;
- no direct-DB provisioning path remains;
- legacy mappings show zero observed use for the approved window before removal;
- security scan finds no demo password, private key, client secret or generated binary in Git;
- independent critic returns no unresolved P0/P1;
- from-zero reference reset passes without deleting third-party/base images;
- full Probata validation, Axiom tests and cross-repository contracts are green; and
- user completes the live access-loop demo and explicitly accepts it.

## 9. Required final evidence index

The final certification record links:

- Probata and Axiom commits/tree hashes;
- active platform policy bundle;
- golden-corpus version/hash;
- Java/Python/TypeScript/OpenAPI contract results;
- parity and route-coverage reports;
- OIDC/JWKS/key-rotation transcript;
- database migration and rollback/blue-green transcript;
- Redis/outage/restart/invalidation transcript;
- RLS/no-disclosure/SoD security report;
- Playwright/axe/screenshots;
- latency/load results;
- Axiom and Probata correlated audit IDs;
- SBOM/signature/secret sweep; and
- exact URL, user, clicks and user-acceptance date.
