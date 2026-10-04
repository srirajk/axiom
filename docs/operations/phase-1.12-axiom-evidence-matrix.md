# Phase 1.12 — Axiom-side evidence matrix (1.1–1.5, 1.9, 1.10)

**Status: evidence for review. Phase 1 is NOT accepted.** Codex retains review and acceptance.

Scope: source and test evidence from the `hardening/phase-0-baseline` working tree of the isolated clone
(`axiom-changes`), uncommitted. Nothing here was deployed. All runtime evidence comes from disposable PostgreSQL 16 and
Redis 7 containers (Testcontainers, random 127.0.0.1 ports) driving Axiom's real filter chains through MockMvc, or
from offline unit tests. No Argus component, code or fixture is involved; the "Gateway broker" is a confidential
client registered in Axiom, and the Gateway/receivers of 1.9/1.10 are synthetic test fixtures.

Last full run (2026-10-02, Java 25.0.3, Maven offline, exit 0): unit **404/404** (137 classes, 0 failures/errors/
skips); integration **63/63** (8 classes: `ExchangeEdgeScenarioIT` 20, `SyntheticGatewayReceiverScenarioIT` 10,
`OperatorSuppliedClientSecretIT` 9, `UserDisableSessionRaceIT` 8, `EntryAgentGatewayScenarioIT` 7,
`ApplicationAudienceEscalationIT` 4, `BrokerWorkloadRegistrationServiceRaceIT` 3, `BrokerWorkloadRegistrationLockIT` 2);
credential delivery **43/43**; chart render **21/21**; hook-account recovery **6/6**; `helm lint` clean.

Legend — **Axiom-proven**: asserted against Axiom's real APIs and token endpoint. **Fixture-proven**: asserted with
synthetic receivers against real Axiom tokens. **Needs**: what must still happen before the row can be claimed.

| Phase | Exit criterion (strategy) | Axiom source | Tests (class → cases) | Evidence | Still needs |
|---|---|---|---|---|---|
| **1.1** Distinct identities | Entry, Agent and broker identities are distinct, owned and independently manageable; no client is both broker and workload | `AgentExchangeAuthorityService.registerBroker` (client row lock), `CiamDelegationService.registerWorkload` (rejects a broker client), `TenantApplicationService.lockClientForIdentityRegistration` | `EntryAgentGatewayScenarioIT.brokerAndWorkloadRegistrationsCannotOverlapInEitherOrder`; `ExchangeEdgeScenarioIT.entryAgentAndBrokerAreDistinctRegisteredIdentities`; `BrokerWorkloadRegistrationServiceRaceIT` (3), `BrokerWorkloadRegistrationLockIT` (2); `CiamDelegationServiceBrokerExclusivityTest` | Axiom-proven, including concurrent registration | Deployed-environment inventory of the real entry, Agent and broker clients; **gap**: a broker client can still mint a `client_credentials` workload-kind token (unusable as an exchange subject — `ExchangeEdgeScenarioIT.brokerClientCredentialsTokenIsNotAnExchangeSubject` — but its `aud` equals the Gateway audience, so receivers must check `token_use`) |
| **1.2** Environment-local credentials | Only authorized runtimes obtain credential material; configuration and evidence contain no secrets | Operator-supplied secrets: `OperatorSuppliedClientSecrets`, `TenantApplicationService.createClient/rotateClientSecret`, `IdentityControlApplyService` (two-person rotation), DTO redaction, `GlobalExceptionHandler.handleNotReadable`; `scripts/configure_axiom.py` (escrow → create → possession proof → conditional `kubectl create`/`replace` with resourceVersion → verify); chart: per-workload Secret projection, 0400 modes, separate ServiceAccounts. Supplied rotation exposes a hash of an independent recovery ID, not a hash of the secret; syntactic validation does not prove caller entropy. Identity-source secret rotations (externally issued, unknown entropy) are bound by a keyed HMAC (`SecretProtector.keyedDigest`, `IdentityControlPayloads`); every action's payload is validated at proposal; migration `V30` removes legacy unkeyed digests of secret-bearing payloads and expires legacy requests that could still be applied. | `OperatorSuppliedClientSecretTest` (13), `IdentityControlCredentialBoundaryTest` (5), `OperatorSuppliedClientSecretIT` (9, incl. identity-source digest and V30 semantics); `scripts/test_kubernetes_secret_delivery.py` (43); `deploy/helm/test_axiom_chart_secret_access.py` (21), `test_recover_hook_service_accounts.py` (6) | Axiom-proven (API, approval, redaction, audit); script and chart proven offline | Deployment of the narrowed chart and of the new Axiom build; re-provisioning the live signing-key Secret (still carries the `apply` annotation); Redis auth/encryption and per-component NetworkPolicies (Track C package); live Secret delivery is untested by design |
| **1.3** Explicit exchange profiles | Wrong token use, wrong redeeming workload, excessive scope and unapproved destination fail; no unrestricted recursive exchange | `AgentExchangeAuthorityService.resolve*`, `requireValidNonCustomerSubject`, `activeRoute`; `TokenExchangeAuthenticationProvider` (client-scope check) | `ExchangeEdgeScenarioIT`: `onlyTheExactRedeemingClientMayAdvanceEachEdge`, `tokensReplayedIntoTheWrongEdgeAreRefused`, `eachEdgeReachesOnlyItsRoutedDestination`, `scopesNarrowAtEveryEdgeAndNeverWiden`, `brokerAndAgentEdgesAreTenantBound`, revocation/expiry cases (6); `EntryAgentGatewayScenarioIT` (E1/E2 denials); harness H-2/H-6 (31 cases, local stack) | Axiom-proven for all five edges (E1 entry, E2 entry→Gateway, E3 broker→Agent, E5 Agent→Gateway, E4 broker→resource), with exact error codes | Profiles configured for the real Use Case routes (R1–R4 here are fixtures). **Bound (by design)**: a subject token may be redeemed more than once; every derived token expires no later than the subject, shares its root session and dies with it (`repeatRedemptionIsBoundedBySubjectLifetimeAndRootSession`); recursion is route-bounded, ambiguous routes fail closed (`ambiguousRoutesToOneAudienceFailClosed`) and `delegated_access` is terminal |
| **1.4** Workforce entry binding | A workforce token from an unrelated application cannot be laundered through the BFF or Agent | `AgentExchangeAuthorityService.resolveWorkforce` (source application = actor application), `requireWorkforceAuthority` (entitlement revision in `authority_id`) | `EntryAgentGatewayScenarioIT.humanTokenFromADifferentSourceApplicationIsRefused`; `ExchangeEdgeScenarioIT.lostEntitlementStopsTheEntryContinuation`, `onlyTheExactRedeemingClientMayAdvanceEachEdge` (other-application workload at E2), `lostEntitlementStopsNewEntryContinuationsAndBoundsTheInFlightChain`; `AgentExchangeAuthorityServiceTest` | Axiom-proven at E1/E2 | Deployed confirmation. **Bound (contract)**: assignment removal stops every new entry continuation immediately; tokens already derived expire no later than the entry-side token they came from (≤ 300 s after the last entitlement check). Immediate cut-off is user disable or session/route/workload revocation |
| **1.5** Subject and actor semantics | Receiver evidence shows correct subject and actor through every exchange | `JwtClaimsCustomizer` (sub, `subject_sid`, `act{sub,client_id,workload_id}`, `azp`) | `ExchangeEdgeScenarioIT.allFiveEdgesPreserveTheHumanSubjectAndNameTheWorkloadActorNeverTheBroker`, `autonomousAgentChainPreservesTheServiceSubjectThroughTheBroker`; `SyntheticGatewayReceiverScenarioIT.humanBffEntryReachesTheResourceWithTheCredentialReplacedAtEveryHop`, `autonomousAgentReachesTheResourceAsItsOwnServiceSubject` (receiver-side principals) | Axiom-proven at token level for human and service subjects; fixture-proven at synthetic receivers | Evidence from real receivers; **note**: after E5 the token names only the current actor (the Agent); the entry workload is recoverable only through route provenance, not a nested `act` |
| **1.9** Destination authentication | Gateway tokens fail at receivers; destination tokens fail at the Gateway; denied requests produce zero downstream calls | Test fixture `scenario/receiver/SyntheticGatewayFixture` (ordered verifier: one bearer, RS256 + `typ at+jwt`, configured keys only, issuer, time, single audience, tenant, `token_use`/profile, redeemer, actor, scope, identifiers) | `SyntheticGatewayReceiverScenarioIT` (10): wrong-audience/token-use and 13 direct-bypass cases, caller-written headers, Axiom-refused onward exchange (zero forwards), no fallback to the inbound token, revocation-aware receiver (introspection) rejecting a revoked token an offline receiver still accepts, introspection outage failing closed (503, zero downstream), two independent client sets; `SyntheticReceiverContractTest` (6): 25 malformed token shapes, header allowlist, workforce `subject_sid` rule, revocation-check modes | Fixture-proven with real Axiom tokens; zero downstream calls asserted by exact counts | **Real receivers and the real Gateway** (another component); deployed receiver counts; network-level bypass (NetworkPolicy/mTLS); introspection caller-to-audience binding (Phase 0.5) |
| **1.10** BFF path (Axiom side) | BFF calls work without substituting service identity for human delegation or asserting authority through headers | Workforce exchange (E1) and continuation (E2); fixture `SyntheticBff` | `SyntheticGatewayReceiverScenarioIT`: `humanBffEntryReachesTheResourceWithTheCredentialReplacedAtEveryHop`, `bffCannotSubstituteItsOwnServiceIdentityForTheHuman`, `callerWrittenAuthorityHeadersNeverAuthorizeAnything` | Fixture-proven: human subject preserved to the resource; BFF service token refused at Gateway and as a human session; header-only and header-plus-wrong-token requests refused | The real BFF and browser flow; deployed revision; subject/actor authorization decisions belong to the Gateway/policy component |

## Authority continuity (Phase 0.5 freshness contract)

- **Re-evaluated at every exchange and introspection** (source change in
  `AgentExchangeAuthorityService.requireActiveActor` / `activeBrokerByClient`): the actor workload, its OAuth client,
  the broker entity and the broker's OAuth client must be active in the tenant. Disabling the entry client stops every
  continuation naming it (`disabledSourceClientStopsEveryContinuationThatNamesIt`); disabling the broker client
  invalidates broker-issued tokens (`disabledBrokerClientInvalidatesBrokerIssuedTokens`).
- **Assignment removal is not logout or revocation** (bound above, row 1.4). Disabling the human, revoking a broker,
  route or workload, or disabling a resource application stops the chain mid-way (`ExchangeEdgeScenarioIT` revocation
  cases).
- **Repeat redemption** is allowed and bounded (row 1.3); it is not treated as an attack.
- **Receivers validating offline** (JWKS) cannot see revocation before `exp`; a receiver that needs current
  revocation must use a revocation-aware boundary (shown with introspection in
  `revocationAwareReceiverRejectsWhatAnOfflineReceiverStillAccepts`).

## Requires real components or deployment

1. A deployed Axiom revision containing these changes (and migration `V30`), then the narrowed chart.
2. Real Gateway, BFF and receivers configured to the receiver contract, with deployed receiver allow/deny counts.
3. The Use Case's real entry, Agent and broker clients and routes (R1–R4 here are fixtures).
4. Network-level bypass controls (per-component NetworkPolicy, mTLS) and Redis authentication/encryption.
5. Re-provisioning the live signing-key Secret that still carries the `apply` annotation.

## Open decision

- Historical `audit_log` rows for identity-source secret rotations proposed before `V30` contain the old unkeyed
  `payloadHash`. Audit rows are not hash-chained, but rewriting audit history is a governance choice; this package
  leaves them unchanged pending a decision (redact the field in those rows, or retain and restrict audit-export access).

## Reproduce

```bash
cd server && JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home mvn -o -B verify \
  -Dit.test='OperatorSuppliedClientSecretIT,EntryAgentGatewayScenarioIT,ExchangeEdgeScenarioIT,SyntheticGatewayReceiverScenarioIT,ApplicationAudienceEscalationIT,UserDisableSessionRaceIT,BrokerWorkloadRegistrationServiceRaceIT,BrokerWorkloadRegistrationLockIT' \
  -Dfailsafe.failIfNoSpecifiedTests=false
python3 -B scripts/test_kubernetes_secret_delivery.py
python3 -B deploy/helm/test_axiom_chart_secret_access.py
python3 -B deploy/helm/test_recover_hook_service_accounts.py
```
