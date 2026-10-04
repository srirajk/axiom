# Phase 3 — Axiom-side evidence matrix (advanced authority and lifecycle patterns)

**Status: evidence for Codex review. Phase 3 is NOT accepted, in whole or in part.** Codex owns architecture review and
acceptance. Scope: the uncommitted `hardening/phase-0-baseline` working tree of the isolated clone (`axiom-changes`).
Nothing was deployed; Argus, Cerbos, the Gateway, Agent runtimes and receivers were not touched. Contract and
decisions: `docs/architecture/phase-3-authority-lifecycle-contract.md`.

Status vocabulary: **Axiom source done** (code + tests in Axiom) · **Fixture-proven** (Axiom with a synthetic, test-only
counterpart) · **Partial** · **Deferred decision** (needs a choice that existing contracts do not make) · **External
work** (another component). No story is complete because an interface or a document exists.

## Build and test record (2026-10-02, Java 25.0.3, Maven 3.9.9 offline)

```bash
cd server && JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home mvn -o -B verify \
  -Dit.test='OperatorSuppliedClientSecretIT,EntryAgentGatewayScenarioIT,ExchangeEdgeScenarioIT,SyntheticGatewayReceiverScenarioIT,ApplicationAudienceEscalationIT,UserDisableSessionRaceIT,BrokerWorkloadRegistrationServiceRaceIT,BrokerWorkloadRegistrationLockIT,InvocationContextRepairIT,InvocationContextEstablishmentIT,InvocationContextDefaultDenyIT,InvocationContextContinuationIT,InvocationContextRevocationIT,InvocationContextOutageIT,SharedAgentIsolationIT,InvocationBranchCancellationIT,CustomerCodeDeliveryIT,CustomerCodeNoProviderIT,ConsentPurposeIT,StandingGrantIT,DurableTaskIT,TaskCallbackIT,ActionApprovalIT,WorkloadLifecycleIT,WorkloadFederationIT,AuthorityMeasurementIT' \
  -Dfailsafe.failIfNoSpecifiedTests=false
```

Exit code 0. **Unit (Surefire): 408/408**, 138 classes, 0 failures/errors/skips (405 before Phase 3, plus
`ActionCanonicalizerTest` 3). **Integration (Failsafe, disposable PostgreSQL 16 + Redis 7): 134/134**, 26 classes, 0
failures/errors/skips:

- Phase 3 (38): `CustomerCodeDeliveryIT` 8, `CustomerCodeNoProviderIT` 1, `ConsentPurposeIT` 4, `StandingGrantIT` 7,
  `DurableTaskIT` 3, `TaskCallbackIT` 1, `InvocationBranchCancellationIT` 3, `ActionApprovalIT` 5,
  `WorkloadLifecycleIT` 4, `WorkloadFederationIT` 1, `AuthorityMeasurementIT` 1.
- Phase 2 (33): Repair 10, Establishment 5, DefaultDeny 1, Continuation 9, Revocation 5, Outage 2, SharedAgentIsolation 1.
- Phase 1 (63): OperatorSuppliedClientSecret 9, EntryAgentGateway 7, ExchangeEdge 20, SyntheticGatewayReceiver 10,
  ApplicationAudienceEscalation 4, UserDisableSessionRace 8, BrokerWorkloadRegistrationServiceRace 3,
  BrokerWorkloadRegistrationLock 2.

**Not run / environment-gated:** the ITs listed as unrunnable in Phase 0 (`ProvisioningSagaConcurrencyIT`,
`PromotionReachesRuntimeEnforcementIT`/`BlobIT`, `PromotionExecutionLockStoreIT`, `TenantLifecycleLockStoreIT`,
`SelfContainedBundleIT`, `LocalPdpParityIT`, `Phase03PersistenceIT`); the break-glass ITs were not re-run (break-glass
code is unchanged); the Python credential/chart harnesses were not re-run (no deploy or script changes); no real
provider, partner, Gateway, receiver or Argus was exercised.

**Mutation checks** (each control removed, the named test run, source restored byte-identical):

| Control removed | Test that failed |
|---|---|
| Approval consumption status guard (`AND status = 'CONFIRMED'`) | `ActionApprovalIT.approvedConfirmedActionIsRedeemedOnceAndExecutedOnce` |
| Renewal-handle reuse ⇒ grant withdrawal | `StandingGrantIT.ownerApprovesTheWorkloadRedeemsAndRenewsWithRotatingHandles` |
| Live workload-ownership check | `WorkloadLifecycleIT.ownershipIsEnforcedLiveAndOwnerDepartureSuspendsUntilReassignedAndReactivated` |
| One-use code consumption guard (`used_at IS NULL`) | `CustomerCodeDeliveryIT.concurrentUseOfOneCodeSucceedsExactlyOnce` |
| Callback replay rejection | `TaskCallbackIT` |

**Measured, not generalized** (`target/phase3-measurements.json`; one machine, in-process MockMvc, Testcontainers;
latency includes BCrypt-12 client authentication, which dominates): Axiom admin token 1006 B; workload
client-credentials token 823 B; standing-grant token 1334 B; approved-action token 1555 B; renewal handle 43 B;
representative header set with an approved-action token 1949 B. Standing renewal p50 237 ms / p95 245 ms (30); standing
token introspection p50 235 ms / p95 247 ms (30); task resume p50 11 ms / p95 19 ms (30); approved-action redemption
p50 232 ms / p95 237 ms (10). No production latency or throughput claim is made.

**Bugs found by the new tests and fixed before the final run:** (1) the one-use code `UPDATE` cleared the persistence
context, silently dropping the customer's verified status; (2) the reuse-detection exception crossed a transactional
boundary and rolled back the very withdrawal it was meant to commit; (3) Spring Authorization Server keeps only the
last client-authentication provider customizer, which silently dropped the federation provider; (4) client-credentials
tokens carry no Axiom session, so the workload API must check client liveness, not a session.

## Repair: approved-action use-time validation and the issuance commit boundary (2026-10-02)

- **Defect:** introspection of an approved-action token checked only the approval row and that the initiator was
  active. Suspending the Agent workload, disabling its client, revoking its route, or removing the initiator's permission
  left an issued token active. `ApprovedActionUseTimeIT` (5) failed 5/5 on the affected-token assertion before the fix.
- **Fix (one method):** `ActionApprovalService.requireCurrent` now also runs the same live-authority check used at
  redemption (`requireLiveAuthority`: workload usable incl. ownership, client active in the same application with the
  scopes, RESOURCE route usable to the receiver with the scopes, initiator active and holding the scopes). Each change
  stops only the affected token; tokens for another workload, another route or another permission stay active.
- **Wording corrected:** "commit together" was wrong across stores. The guarantee is ordering: PostgreSQL (state
  change, the token's Axiom session row, audit) commits only after the token is signed and its Redis record written.
  `IssuanceCommitBoundaryIT` (2) injects a PostgreSQL commit failure with a deferred constraint trigger created only in
  the disposable test database: no token is returned; the approval stays CONFIRMED / the handle is not rotated; an
  orphan Redis record exists (TTL ≤ token TTL + the store's 60 s grace); its session row does not exist, so
  introspection rejects it, including after the same approval is later redeemed with otherwise identical claims.
  Residual: an offline, signature-only validator that obtained the orphan from Redis would accept it until `exp`; a
  committed redemption whose response is lost consumes the approval (or rotates the handle, which then withdraws the
  grant on the next renewal) — both fail closed for the caller. No cross-store atomicity is claimed.
- **Results:** unit 408/408 (138 classes); integration 141/141 (28 classes = the 134 above plus
  `ApprovedActionUseTimeIT` 5 and `IssuanceCommitBoundaryIT` 2). No migration added.
- **Recovery:** revert the `requireCurrent`/`requireLive` hunk in `ActionApprovalService` (restores the previous,
  weaker validation); the Javadoc/doc wording changes and the two test classes can be removed independently.

## Gates A–C hardening (2026-10-02, after the repair above)

**Gate A — 3.15 suspension and retirement.** Every authority path of one Agent workload was traced
(`WorkloadSuspensionPathsIT` 2): client-credentials issuance; the workload API and token exchange with an existing
client-credentials token; the exchanged Gateway token; standing-grant renewal and token; approved-action redemption
and token; task creation and resume. Before the fix the trace failed on exactly one path: **a suspended or retired
workload's client could still obtain new client-credentials tokens** (every existing token and every other new path
already refused). Client sharing was checked first: `UNIQUE (tenant_id, oauth_client_id)` on workloads, the
broker/workload exclusivity and a client's single tenant mean an OAuth client backs at most one Agent workload; clients
never registered as workloads are outside the workload lifecycle. Fix: issuance is refused (`unauthorized_client`)
for a client whose workload is not usable (`WorkloadLifecycleService.clientMayIssue`, called from the token
customizer); the OAuth client row is **not** disabled, so reactivation needs nothing else. Proven: existing-token
denial, new-token denial, another workload and an ordinary non-Agent service client unaffected, reactivation restores
every new path, retirement terminal (no reactivate, no suspend, the client cannot be registered again, client row left
ACTIVE). Note: client-credentials tokens carry no Axiom session, so introspection never reports them active for any
client (existing behaviour). Behaviour change: the same refusal applies to `REVOKED` (Phase 1) workloads and to
workloads whose assigned ownership is invalid.

**Gate B — 3.10 ownership lifecycle.** `WorkloadOwnershipConcurrencyIT` (4): four workers continuously use one owned
workload (client-credentials issuance, Phase 1 exchange, standing-token introspection, task resume) while the owner is
removed from the team, the team is deleted, or the owner is disabled. No request that started after the change
committed succeeded, the earlier standing token stopped at introspection, membership restoration / reassignment (and,
after a departure, explicit reactivation) restored use, re-enabling the departed person did not. Disabling the owner
also revoked that person's sessions, so standing tokens issued before the departure stay dead after reactivation.
No team id appears as a subject or actor in any token, and a team has no credential. The only source gap these
scenarios exposed was the Gate A issuance path (mutation: removing that gate fails 3 of these 4 and both Gate A tests).
Not proven here: departure through SCIM deactivation (same hook, `IamSessionService.revokeAllForPrincipal`, but not
exercised by an IT); the "started after commit" ordering is observed from the client side, not barrier-forced.

**Gate C — 3.1 customer-code safety.** Before the fix (`CustomerCodeLocalDemoIT` 2, failed 2/2): with the demo
setting on, recovery challenges returned a usable recovery code for any known address (account takeover for anyone
able to reach the endpoint — `compose.yaml` publishes port 8180 on all interfaces and enables the setting by default),
and the setting was accepted with any issuer. Fixes: (1) recovery codes are never disclosed in any configuration;
without a real provider recovery is refused with 503 for every address and no recovery challenge is created; (2)
`LocalDemoDisclosureGuard` refuses to start when the setting is on unless the issuer is a loopback host and no real
provider is configured (`LocalDemoDisclosureGuardTest` 1); (3) `configuration/README.md` names the property correctly.
The verification-code disclosure remains a local fixture (`codeDelivery = LOCAL_DEMO`). Production default, uniform
503 without a provider, and absence of codes from logs/audit remain proven by `CustomerCodeNoProviderIT` and
`CustomerCodeDeliveryIT`.

**Decision needed (Gate C, not made here):** the local compose stack still publishes on all interfaces with the
verification-code disclosure on by default (issuer `localhost:8180`, so the guard allows it). Anyone on the network can
register an account for any e-mail address and verify it without owning the mailbox. Options: bind compose to
`127.0.0.1`, default the setting to off in compose and `.env.example`, or accept for local demos. Consequence of fix
(1): `scripts/verify-ciam-agent-delegation.py` `credential_recovery` can no longer obtain a recovery code from a
demo stack and will fail there until a local delivery fixture (for example a loopback-only outbox provider) is chosen.
Deployment and compose files were not changed.

**Results (final run after the last source edit):** exit 0. Unit 409/409 (139 classes; adds
`LocalDemoDisclosureGuardTest` 1). Integration 149/149 (31 classes; adds `WorkloadSuspensionPathsIT` 2,
`WorkloadOwnershipConcurrencyIT` 4, `CustomerCodeLocalDemoIT` 2 to the 141 above). The first full run after Gate C
failed 2 tests in `WorkloadLifecycleIT`: its helper assumed client-credentials issuance always succeeds, which Gate A
now refuses by design. The helper now counts issuance as a checked path; the class passed 4/4 before the final run.

**Recovery:** Gate A — remove the issuance check in `JwtClaimsCustomizer` and `clientMayIssue`; Gate C — restore
`requestRecovery`'s demo path and remove `LocalDemoDisclosureGuard` (both restore the unsafe behaviour); the README
correction is independent. No migrations were added in Gates A–C.

## Story matrix

| Story | Status | Evidence (plain English) | Remaining dependency |
|---|---|---|---|
| **3.1** Customer-code delivery | **Partial — Axiom source done, fixture-proven; real delivery is a deferred decision; demo disclosure restricted (recovery never disclosed, loopback-only startup guard)** | Durable, encrypted, leased delivery state; retry with backoff; abandonment erases the code; resend; per-customer issuance limit; one-use under 8-way concurrency; expiry and superseded codes fail; delivery failure never verifies; survives restart; DB outage registers nothing; no code in logs, audit, lifecycle events or responses; **with no provider, registration/resend/recovery are refused (503) identically for known and unknown addresses** (`CustomerCodeDeliveryIT` 8, `CustomerCodeNoProviderIT` 1) | **D-1** provider selection; "real customers receive codes" is not met. Compose exposure of verification disclosure: decision pending (see Gates A–C) |
| **3.2** Customer-consent delegation | **Partial — Axiom source done, fixture-proven** | Operator-registered purposes (scopes, max validity, retire); purpose-bound consent only by the customer, within purpose scopes/validity; wrong purpose, wrong scope, wrong Agent, onward delegation to another Agent, retired purpose, withdrawal (stops renewal and introspection immediately) and DB outage fail; ambiguous consent refused; legacy consent unchanged (`ConsentPurposeIT` 4) | Real customers depend on 3.1; resource/action modelling beyond audience+scopes is Argus/Cerbos (external); offline receivers keep a withdrawn token ≤ 5 min |
| **3.3** Standing offline authority | **Axiom source done; fixture-proven** (workforce owners, RESOURCE routes) | Explicit owner approval with fresh authentication; only unconditional (`allow`) entitlements; bound workload only; rotating single-use handle; reuse ⇒ withdrawal; no access token accepted as renewal input; tokens bounded by grant expiry and not exchangeable; withdrawal, expiry, owner disable, entitlement removal stop renewal and tokens; restart; Redis and PostgreSQL outages fail closed without consuming the handle (`StandingGrantIT` 7) | **D-7** Gateway route class for standing tokens; **D-10** customer owners |
| **3.4** Long-running task resume | **Axiom source done; workflow runtime external** | Tasks bind authority + version; resume re-checks; owner/admin/workload cancellation; cancelled task stops task-bound renewals and tokens; restart cannot revive; withdrawn authority refuses resume; context-bound tasks stop when the run is cancelled (`DurableTaskIT` 3, `InvocationBranchCancellationIT` 1 of 3) | Workflow runtime adoption |
| **3.5** Authenticated callbacks | **Deferred decision (trust anchor); intake fixture-proven** | Default verifier denies every callback (`DurableTaskIT`); with a synthetic anchor: accepted once; unsigned, tampered, replayed, stale, wrong-task, wrong-tenant, unbound-provider and ended-task callbacks change nothing; no callback resumes work (`TaskCallbackIT` 1) | **D-3** per-provider trust anchor; receiver/integration side |
| **3.6** Branch-specific cancellation | **Axiom source done** | Establishing broker cancels a branch: it and its descendants stop; sibling, root, another run of the session and the human session continue; non-establishing caller refused; idempotent; distinct from revocation; no live child survives a cancel racing branch creation (`InvocationBranchCancellationIT` 3) | Argus use of the cancel API; the race test checks the invariant, it does not force the interleaving |
| **3.7** Exact-action approval | **Axiom source done; fixture-proven** | Canonical form with an independent known-answer vector; approval bound to type, receiver, every field, deadline and required assurance; self-approval, role-less approver, Agent, stale approver and wrong digest refused; changed amount/recipient needs a new approval (`ActionApprovalIT` 5, `ActionCanonicalizerTest` 3) | **D-6** approver eligibility/assurance per action type (Argus/Cerbos policy) |
| **3.8** Single use and business idempotency | **Axiom single use source done; receiver contract fixture-proven** | One conditional consume: 6 concurrent redemptions ⇒ 1 token; replay refused; a Redis failure or outage rolls the consumption back; a PostgreSQL commit failure after the Redis write leaves the approval unconsumed and an orphan Redis record whose rolled-back session makes it unusable at introspection (`IssuanceCommitBoundaryIT`); after issuance, workload suspension, client disable, route revocation, or removal of the initiator's permission stop the token while unrelated tokens stay valid (`ApprovedActionUseTimeIT` 5); synthetic receiver: 8 concurrent deliveries ⇒ 1 effect, retries return the established outcome, changed request refused | **No end-to-end exactly-once claim**: real receivers must implement the contract |
| **3.9** Step-up authentication | **Partial** | `auth_time`/`acr`/`amr` recorded for interactive password logins, preserved (never upgraded) through exchange; approval and confirmation require fresh authentication; old authentication fails; re-authentication confirms only that approval; unsatisfiable assurance fails closed | **D-5** stronger authenticator and assurance vocabulary; BFF/workflow adoption (external) |
| **3.10** Team representation | **Partial — ownership lifecycle proven under concurrent use (`WorkloadOwnershipConcurrencyIT`)** | Team + accountable owner; live enforcement on Phase 1 exchange, standing grants and workload API; owner leaving the team, owner disable and team deletion stop authority; reassignment then reactivation restores (`WorkloadLifecycleIT`) | **D-8** teams as acting subjects; directory (SCIM) lifecycle beyond group membership |
| **3.11** Partner federation | **Deferred decision** | No partner selected. Existing inbound OIDC workforce federation unchanged; the generic workload-federation contract (3.12) applies to partner workloads | **D-4** per-partner profile and evidence; source-disable session sweep (existing gap) |
| **3.12** Hosted-Agent federation | **Fixture-proven generic contract; provider profiles deferred** | Default denies; with a synthetic profile the assertion authenticates only the bound workload's client — never a human (extra claims ignored), never another workload; replay, expiry, long lifetime, wrong audience, unbound identity, bad signature, suspended workload and revoked binding fail; cannot redeem another workload's standing grant (`WorkloadFederationIT` 1, `WorkloadLifecycleIT`) | **D-4** provider profile selection |
| **3.13** Structured invocation intent | **Axiom source done; Argus/Cerbos derivation external** | Authority comes from the approved action type, scopes and digest: an invoice-summary approval cannot obtain the pay scope although the initiator holds it, and the receiver refuses it for a payment; free-text memo inside the action is data only | Argus/Cerbos deriving approved workflows |
| **3.14** Emergency authority | **Reconciled, not rebuilt — deferred decision** | Existing C6 break-glass: allow-listed tuple, ≤ 60 min, two-person (author ≠ approver), signed approval, idempotent promotion, `break_glass.granted/used` audit. No second system built | **D-9**: incident binding, explicit revocation, durable pending requests, token marking — tied to Policy Studio placement |
| **3.15** Identity lifecycle automation | **Partial — suspension/retirement proven on every Axiom authority path (`WorkloadSuspensionPathsIT`); review/rotation overlap source done** | Suspension reversible; retirement terminal (revokes consent and standing grants, keeps history); access reviews recorded; rotation keeps exactly the declared overlap then fails; revocation clears overlap; default overlap 0 preserves existing behaviour (`WorkloadLifecycleIT` 4) | Review campaigns/scheduling (operator); offline signature-only validators still accept a suspended workload's unexpired tokens |

## Flyway recovery

V33–V38 are additive (new tables/columns, two widened status checks) and have only run in disposable test databases.

- **Before any real database applies them:** deleting the files and their code is safe.
- **After:** roll forward only. To disable a feature, leave its tables; the code paths are inert without callers
  (no provider ⇒ 3.1 refuses; no verifier/profile ⇒ 3.5/3.12 deny; no approvals/standing grants ⇒ grants unused). Do not
  drop `standing_grants`, `action_approvals` or `durable_tasks` while tokens could reference them.
- **Constraint changes:** V36 and V38 replace `invocation_contexts_status_check` and
  `agent_workload_identities_status_check`; reverting requires first moving any `CANCELLED`/`SUSPENDED`/`RETIRED` rows,
  which would change their meaning — roll forward instead.

## Recovery notes per gate

- **A:** documentation only (`phase-3-authority-lifecycle-contract.md`).
- **B:** remove `authority/delivery`, `authority/consent`, V33/V34 (pre-deployment) and revert the CIAM service,
  controller, DTO, repository, validator and exchange-parameter hunks. Customer flows then return to the previous
  behaviour, including silent code loss.
- **C:** remove `authority/standing`, `authority/task`, the workload/owner/admin controllers, `AuthoritySecurityConfiguration`
  (its chains and grant), V35/V36 and the cancellation hunks in `invocation/`. Standing tokens already issued expire
  within 5 minutes.
- **D:** remove `authority/approval`, V37 and the approved-action branch in `AgentExchangeAuthorityService`; the
  assurance claims (`AuthenticationAssurance`, form-login details, exchange propagation) are additive and may stay.
- **E:** remove `authority/lifecycle`, `authority/federation`, V38 and the setter hooks (session service, exchange
  service, tenant application service, `SecurityConfig` client-authentication block).
