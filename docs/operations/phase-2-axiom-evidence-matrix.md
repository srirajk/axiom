# Phase 2 — Axiom-side evidence matrix (shared-Agent invocation authority)

**Status: evidence for Codex review. Phase 2 is NOT accepted, in whole or in part.** Codex owns architecture review and
acceptance. Scope: the uncommitted `hardening/phase-0-baseline` working tree of the isolated clone (`axiom-changes`).
Nothing was deployed. Contract: `docs/architecture/phase-2.1-invocation-context-contract.md`.

## Build and test record (2026-10-02, Java 25.0.3, Maven 3.9.9 offline)

```bash
cd server && JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home mvn -o -B verify \
  -Dit.test='InvocationContextEstablishmentIT,InvocationContextDefaultDenyIT,InvocationContextContinuationIT,InvocationContextRevocationIT,InvocationContextOutageIT,SharedAgentIsolationIT,OperatorSuppliedClientSecretIT,EntryAgentGatewayScenarioIT,ExchangeEdgeScenarioIT,SyntheticGatewayReceiverScenarioIT,ApplicationAudienceEscalationIT,UserDisableSessionRaceIT,BrokerWorkloadRegistrationServiceRaceIT,BrokerWorkloadRegistrationLockIT' \
  -Dfailsafe.failIfNoSpecifiedTests=false        # exit 0
python3 -B scripts/test_kubernetes_secret_delivery.py        # 43/43
python3 -B deploy/helm/test_axiom_chart_secret_access.py     # 21/21
python3 -B deploy/helm/test_recover_hook_service_accounts.py # 6/6
helm lint deploy/helm/axiom                                   # clean
```

- After the identity-kind repair (2026-10-02): unit **405/405** (137 classes); integration **96/96** (15 classes;
  `InvocationContextRepairIT` 10).
- After the first repair (2026-10-02): unit **405/405** (137 classes); integration **95/95** (15 classes, adds
  `InvocationContextRepairIT` 9 to the run below). Before the repair:
- Unit (Surefire): **405/405**, 137 classes, 0 failures/errors/skips.
- Integration (Failsafe, disposable PostgreSQL 16 + Redis 7 via Testcontainers): **86/86**, 14 classes. Phase 2:
  `InvocationContextEstablishmentIT` 5, `InvocationContextDefaultDenyIT` 1, `InvocationContextContinuationIT` 9,
  `InvocationContextRevocationIT` 5, `InvocationContextOutageIT` 2, `SharedAgentIsolationIT` 1 (23); Phase 1 suites 63.
- Mutation check: disabling the context status/version/deadline check makes `InvocationContextRevocationIT` fail
  (2 of 5); source restored byte-identical.
- No new dependencies (`server/pom.xml` unchanged). Containers removed by Testcontainers' Ryuk; no dangling volumes.
- **Not run / environment-gated:** the ITs listed as unrunnable in Phase 0 (`ProvisioningSagaConcurrencyIT`,
  `PromotionReachesRuntimeEnforcementIT`/`BlobIT`, `PromotionExecutionLockStoreIT`, `TenantLifecycleLockStoreIT`,
  `SelfContainedBundleIT`, `LocalPdpParityIT`, `Phase03PersistenceIT`); the local-stack Python harness (H-6) was not re-run.

**Measured, not generalized** (one run, `target/phase2-token-sizes.json`): human session token 1320 B; Gateway
authorization 1416 B; Agent token without context 1398 B, with context 1492 B (**+94 B** for `ctx`/`ctx_ver`/`ctx_depth`);
continuation 1474 B; resource 1464 B; one representative header set (bearer + cookies + `traceparent`/`tracestate` +
`Forwarded`/`X-Forwarded-For`) 1886 B. No latency, throughput, proxy header-limit or real-path size claim is made.

## Repair (Codex review findings)

1. **Resume and idempotent retry are bound to every immutable establishment fact** — broker client *and* broker id,
   Gateway security scope, Gateway route, Use Case, entry workload, subject, root session and destination audience
   (stored by migration `V32`; legacy rows with no destination can no longer be resumed or retried). The request
   fingerprint covers the same facts. Negative tests use a genuinely different valid route (replacement R1), a second
   registered broker and Gateway, and a second routed destination.
2. **Branch creation is serialized with every revocation path.** Branch creation, single-context/subtree revoke,
   session revoke and subject (identity-disable) revoke all take the root row lock (`SELECT … FOR UPDATE`, roots in id
   order for session/subject); the cascade `UPDATE` runs afterwards, so it sees any branch committed while it waited.
   The post-lock re-check is a scalar status read, because an entity re-read returned the transaction's cached, stale
   rows — the deterministic test exposed this before the fix. Barrier tests hold one transaction at a named point
   (test-only `InvocationContextRaceProbe` bean) and wait until PostgreSQL reports the competitor blocked on the lock
   (`pg_stat_activity`), not on elapsed time.
3. **The ancestor query orders self-first explicitly** (`ORDER BY hop`), and the service verifies the chain shape
   (self, then each parent, ending at the root) and fails closed otherwise.

4. **Resume and idempotent retry are bound to the original identity kind** (follow-up repair). `identity_kind` is
   compared in the establishment match and included in the request fingerprint; a missing kind never matches. Because
   Axiom derives the kind from the subject, the test calls the service directly with a copy of a genuine
   Gateway-authorization token that differs only in `identity_kind`: resume and retry are both denied, and the
   unmodified claims resume/retry the same context (one row). Fingerprints stored before this change no longer match, so
   such rows cannot be idempotently retried (fail closed; V31/V32 have only run in disposable databases). Phase 1
   exchanges are untouched (no context, no change).

Evidence: `InvocationContextRepairIT` 10/10. Mutation: removing the root lock from the revoke path fails 3 of 9;
removing the identity-kind comparison (alone, or together with the fingerprint field) fails the identity-kind test.

## Story matrix

Status: **Source done** (Axiom code + tests) · **Fixture-proven** (Axiom with synthetic counterpart) · **Partial** ·
**Parked external** (another component) · **Blocked** (needs a decision).

| Story | Status | Evidence (plain English) | Remaining dependency |
|---|---|---|---|
| **2.1** Context contract | **Source done (proposed)** | Contract defines session, run, context and branch lifecycles; immutable and mutable fields; what Axiom verifies vs what the external authorization must supply; examples E1–E10 are each exercised by the ITs | Joint agreement with the Gateway/runtime owner; Codex acceptance |
| **2.2** Establish via verified authorization | **Partial — production denies by design** | Establishment requires the authenticated broker, a valid Gateway-authorization token (route, subject, scope, tenant) **and** evidence that a pluggable verifier binds to subject, root session, Use Case, entry, destination, scopes and validity. Forged, foreign-key, rebound (other subject/destination), widened, expired, reused and label-only attempts all fail; the deployed verifier denies every establishment (`InvocationContextDefaultDenyIT`) | **Blocked on a decision:** the verifiable authorization mechanism and its trust anchor. The synthetic HMAC verifier is test-only |
| **2.3** Persist minimal state | **Source done** | Flyway `V31`: immutable authority + `status`/`version` only, no "current actor"; conditional updates; idempotent issuance (8 concurrent retries → 1 context); concurrent runs and branches independent; state read back by a second application start against the same database | Deployed upgrade path for V31 |
| **2.4** Compact context-bound tokens | **Source done; sizes measured** | `ctx` (opaque UUID), `ctx_ver`, `ctx_depth` added to existing `sub`/`act`/`aud`/`scope`/`jti`/`exp`; `exp` ≤ context deadline | Measurement on the real supported path (proxies, Gateway, browsers) |
| **2.5** Preserve and restrict continuation | **Source done** | Every continuation re-checks edge, recipient, ownership (subject + root session), version, status of the whole ancestor chain, attenuation ⊆ ceiling, deadline and depth (max 2 in tests); cross-user, cross-Use-Case, cross-tenant, wrong actor/audience, widening, depth and expiry all refused | — |
| **2.6** Resolve with bounded freshness | **Partial** | Axiom reads PostgreSQL on every continuation/introspection: no cache, no allow-on-miss, missing/unreadable state fails closed (outage IT). Context facts are projected through introspection **only to the token's recipient**; anyone else gets `active:false` | The receiver-side lookup/cache contract with consumers (Phase 0.5), latency/SLO measurement |
| **2.7** Scoped assignments (Cerbos/Gateway) | **Parked external** | Axiom carries the Use Case and ceiling; it does not evaluate assignments | Argus/Cerbos |
| **2.8** Agent runtime isolation | **Parked external** | Not an Axiom concern; the IT proves only token/context isolation | Agent runtime |
| **2.9** Context revocation | **Source done (Axiom-side)** | Durable revoke (status + version in one conditional statement, subtree cascade, idempotent, never re-activates); admin API; supported logout and admin session revoke end the session's runs; identity disable (user, SCIM, CIAM suspend) ends the subject's runs; assignment removal deliberately does not; audit events | OIDC end-session does not revoke the Axiom session today (pre-existing gap); "declared SLO" for downstream stop needs receivers (2.10) |
| **2.10** Enforce revocation on all routes | **Parked external** | Introspection reports revoked contexts inactive; offline receivers cannot see revocation before `exp` (≤ 300 s) | Gateway/receivers |
| **2.11** Retries and fan-out | **Source done** | Repeated exchanges allowed and bounded by context status/deadline; idempotency keys; fan-out cap (4 in tests) enforced atomically under concurrency; per-session active-context cap; races of revoke vs continuation, branch creation and issuance retry never yield usable authority after the revoke commits | Production values for the limits; request-rate controls are not implemented |
| **2.12** Correlated security audit | **Source done (Axiom-side)** | Synchronous `audit_log` rows for establishment, branch, every continuation (`token_id`, subject, actor, context id/version/depth, decision), revocation and denials (with internal reason); no bearer token, signature or evidence stored; reconstructable without traces | Joining with the Gateway/runtime's own audit (2.12 "Both") |
| **2.13** Prove shared-Agent isolation | **Fixture-proven (Axiom only)** | Two users, two Use Cases, one Agent identity, concurrent: each keeps its own subject/context; substitution attempts fail; revoking Wealth stops Wealth while Claims continues | The full cross-system exit (real Gateway, Cerbos, Agent memory/budget/data and cost attribution) |

## Risks and open points

1. **Establishment is unusable in production until 2.2's mechanism is chosen** (by design). Contexts are optional, so
   Phase 1 broker exchanges continue unchanged; making contexts mandatory is a separate decision.
2. **Revocation window for tokens issued during a revoke.** A token issued in the same instant as a revoke is unusable
   at its next continuation or introspection; an offline receiver may accept it until `exp` (≤ 300 s).
3. **Database dependence.** Every context-bound continuation and introspection performs a recursive ancestor read; no
   latency was measured. A PostgreSQL outage stops all context-bound traffic (fail closed); audit writes also need it.
4. **Orphan contexts.** If token generation fails after a context commits (e.g. Redis down), the context exists without a
   token; an idempotent retry with the same key reuses it, otherwise it counts toward the session cap until its deadline.
5. **Revocation API is administrator-only.** A broker cannot yet end a run it started.

## Recovery

- **Forward recovery (preferred):** the feature is inert without a configured verifier and contexts are optional; leave
  V31 in place and roll back code.
- **Code rollback in this clone:** delete `server/src/main/java/com/openwolf/iam/invocation/`, the Phase 2 tests under
  `server/src/test/java/com/openwolf/iam/invocation/`, and revert the hunks listed in the change list of the hand-off
  report (token-exchange constants/token/converter/provider, claims customizer, introspection provider, security config,
  exchange-authority and session services, converter test).
- **Schema:** V31 has only run in disposable test databases. Before it is applied anywhere real, deleting the file is
  safe; after that, roll forward (a new migration) instead of editing or deleting V31. Never drop the table in a live
  database without review.
