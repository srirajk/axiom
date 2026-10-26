# Direct RESOURCE exchange review — 2026-10-26

Scope: Axiom clone `/Users/srirajkadimisetty/projects/axiom-changes`, branch
`hardening/phase-0-baseline`, baseline `85b7ec4f3d4ca865c4730fe152c03a9a8b890bd4` plus this change.
Contract: `/Users/srirajkadimisetty/projects/control-plane/architecture/build/AXIOM-RESOURCE-ROUTE-SPEC-2026-10-26.md`.

## Behavior

A workload may redeem a person's workforce or customer browser-session token for another active application in the
same tenant only through an explicit, active RESOURCE route. The original sign-in client must still be active,
belong to the same application as the workload, and match the token's single audience. Workforce application access
and customer identity/token-version checks remain mandatory. Scope ceilings remain the route, the subject token,
the workload client, and the person's existing authority (workforce entitlements or customer sign-in grant).

Both first hop and continuation issue `delegated_access` under `workforce` or `customer_session`, retain the person
as `sub`, identify the requesting workload in `act`, and carry exactly the target audience. Authority expiry is the
minimum of route and subject expiry; the existing issuer also caps tokens by the configured exchange TTL (five
minutes by default). Same-application exchanges retain `exchange_subject`. Person continuations look up all matching
route types and accept only GATEWAY or RESOURCE. An AGENT route alone does not become a direct-person path.
Gateway broker resolution, including broker-owned targets, keeps its existing authority and scope behavior.

Direct RESOURCE tokens have a separate introspection validation branch checking current route, source workload and
client, target application, scopes, and person authority. They remain terminal: the subject decoder and continuation
resolver still refuse `delegated_access` as an input to another exchange. No JWT claims customizer changes were needed.

Exchange success and denial audit details now include `routeId` and `destinationType`. Resolved routes populate both;
denials after route selection retain that route context. A missing, unselected, or ambiguous route has no selected
route ID, represented as JSON null. The type is null when unresolved. Same-application and consent-grant exchanges
have no route; broker-owned targets have their destination type and no per-source destination route ID.
RESOURCE scope mismatch on the new person paths returns `invalid_scope`; existing Gateway scope-matching errors
retain their previous behavior.

## Changed files

- `server/src/main/java/com/openwolf/iam/service/AgentExchangeAuthorityService.java`
- `server/src/main/java/com/openwolf/iam/auth/TokenExchangeAuthenticationProvider.java`
- `server/src/test/java/com/openwolf/iam/service/AgentExchangeAuthorityServiceTest.java`
- `server/src/test/java/com/openwolf/iam/service/ResourceRouteExchangeIT.java`
- `server/src/test/java/com/openwolf/iam/service/ExchangeEdgeScenarioIT.java` (one stale Gateway error expectation; see validation)
- `docs/operations/resource-route-review-2026-10-26.md`

## Required test mapping

`ResourceRouteExchangeIT` runs each four-way matrix for workforce/customer-session × first hop/continuation unless
noted. It exercises the real token, route-management and introspection endpoints through MockMvc and real disposable
PostgreSQL/Redis. Workforce browser authentication and customer browser authentication are simulated at the session
boundary; authorization-code + S256 PKCE redemption and subsequent token authority validation run normally.

| Spec case | Evidence |
|---|---|
| Active RESOURCE route; exact audience, person, actor, token use | `activeResourceRouteIssuesOneAudienceWithPersonSubjectWorkloadActorAndBoundedExpiry` (4); unit `resourceExpiryIsTheMinimumOfRouteAndSubject` (2) also checks subject-shorter expiry |
| No route | `noExplicitRouteDeniesAnOtherwiseActiveTarget` (4), including null audit context |
| Expired or revoked route | `expiredRouteDeniesExchange` (4); `revokedRouteDeniesAndReplacementRouteRecoversWithoutRevivingOldTokens` (4) |
| Another tenant | `anotherTenantsApplicationIsRefusedAtRouteCreationAndExchange` (4); exchange also rejects an intentionally injected tenant-local route row targeting the foreign application |
| Target deactivated | `deactivatedTargetIsRefusedAndAuditNamesTheSelectedRoute` (4); also invalidates an already-issued token online |
| Scope outside route | `scopesOutsideRouteAreRefused` (4), with selected route ID in denial audit |
| Scope outside person authority | `scopesOutsideThePersonsTokenAreRefused` (4); `workforceEntitlementsAreRecheckedAfterLogin` (2); unit actor-client scope ceiling (2) |
| Two matching routes | `twoMatchingRouteTypesDenyContinuation` (2); unit `duplicateMatchingResourceRoutesFailClosedOnFirstHop` (2). The database already forbids two ACTIVE routes with the same tenant/source/type/audience; the integration case uses AGENT + RESOURCE, while the unit case proves defensive refusal of duplicate RESOURCE matches |
| Issued token exchanged again | `delegatedAccessIsTerminalEvenWithAnotherActiveResourceRoute` (4); introspection remains active while the exchange is denied |
| CUSTOMER_SESSION same matrix | Every four-way matrix above, plus two-profile ambiguity and Gateway regression checks |
| Gateway, continuation, same-application regressions | `sameApplicationAndGatewayContinuationKeepTheirExistingProfiles` (2), plus existing `ExchangeEdgeScenarioIT`, `EntryAgentGatewayScenarioIT`, and `IdpBaselineIT` |

Additional unit matrices retain source-client activity, same-application, same-tenant and single-audience checks and
refuse direct AGENT-only destinations. Continuation after workforce entitlement removal may be denied earlier by the
subject decoder as `invalid_grant`; first hop returns `invalid_scope`. Both issue no token.

## Validation

Focused validation used Java 25.0.3:

- Authority unit tests: **43 passed**, zero failures/errors/skips (`AgentExchangeAuthorityServiceTest` 32,
  `AgentExchangeTokenAuthorityValidatorTest` 1, `JwtClaimsCustomizerTokenExchangeTest` 5,
  `TokenExchangeSessionValidatorTest` 5).
- New endpoint matrix: **42 passed**, zero failures/errors/skips.
- Existing Gateway/login focused run: `EntryAgentGatewayScenarioIT` **10 passed**, `IdpBaselineIT` **13 passed**;
  `ExchangeEdgeScenarioIT` initially **19 passed / 1 failed** because its final unknown-scope assertion expected
  `invalid_scope`. The unmodified `85b7ec4` source, extracted to a temporary directory and run against fresh disposable
  stores, reproduced that exact failure (**1 run / 1 failed**, expected `invalid_scope`, actual `invalid_target`).
  The existing broker profile intentionally uses subject/destination scope authority rather than its own client scope
  ceiling. The stale assertion now expects its existing `invalid_target`; its focused method rerun **passed 1/1**.
  No Gateway production behavior was changed to accommodate the test.
- The first new-matrix run had four fixture errors because an expired route still had a later creation time (violating
  the existing database check), and one expectation mismatch for earlier continuation subject validation. Fixture
  timestamps and the expected denial were corrected before the passing matrix run; no production control was relaxed.

Final full verification: **Maven exit 0**, **462 unit tests passed** (144 classes), **256 integration tests passed**
(49 integration classes, 259 tests including 3 skipped), **zero test failures or errors**. All four focused integration
classes passed in this full run: RESOURCE 42, exchange edges 20, entry/Gateway 10, issuer baseline 13.
The 3 skips are the existing `Phase03PersistenceIT` external-namespace tests; their opt-in variable was explicitly
removed for this run, as required by the no-Kubernetes/no-existing-data boundary.

```bash
cd /Users/srirajkadimisetty/projects/axiom-changes/server
JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home \
  env -u AXIOM_PHASE03_TEST_NS mvn -o -q verify
```

The full run logged `Surefire is going to kill self fork JVM. The exit has elapsed 30 seconds after System.exit(0)`
after tests completed. It also logged background scheduled/connection-watchdog attempts against already-stopped test
stores. Maven still exited 0 and every executed test passed; a clean test-JVM shutdown is **not** claimed. Post-run
inspection of the 49 distinct container IDs recorded across the focused, baseline-reproduction and full-run logs
found **zero containers remaining**. No unrelated container was stopped or removed.

`git diff --check` passed, and an explicit whitespace scan of the new files found no trailing whitespace. The original
uncommitted diff (all eight pre-existing changed/deleted files, including logout and deployment documentation) was
compared byte-for-byte with the initial saved patch and is unchanged.

Local detailed evidence is in `/private/tmp/axiom-resource-full.log`,
`/private/tmp/axiom-resource-full-summary.json`, `/private/tmp/axiom-resource-baseline-regression.log`,
`/private/tmp/axiom-resource-gateway-regression.log`, and `/private/tmp/axiom-resource-container-cleanup.json`.
The summary includes per-class results and SHA-256 hashes of the five changed Java files.

**Ready for Axiom source review.** The test-JVM shutdown diagnostic, three external-namespace skips, and the external
rollout/Argus configuration boundary remain explicit limitations; none is a claim of deployed acceptance.

## Dependency, isolation and recovery review

No dependency, schema, migration, default configuration, or Kubernetes resource changed.
The new paths use the existing tenant-scoped route query, application service, authority checks, token issuer,
authorization store, signing keys, session validation and required audit writer. No new service or network destination
is introduced. Maven runs offline against the existing dependency cache with Java 25.0.3 / Maven 3.9.9.

Fixtures use Testcontainers-owned PostgreSQL 16 and Redis 7, random mapped ports, disposable signing keys and generated
principals/clients. No deployed database, Redis keyspace or Kubernetes namespace is a test target. Tests insert or
update only their own isolated rows; the revoked-route recovery test creates a replacement route through the admin
API and verifies old tokens remain inactive. No existing application data is reset. Testcontainers/Ryuk handles owned
container cleanup, confirmed by the post-run inspection above. The full suite passed existing shared-path
`InvocationContextOutageIT` (PostgreSQL/Redis fail-closed and recovery), `IssuanceCommitBoundaryIT`,
`SharedAgentIsolationIT`, and the user/workload ownership race suites. No separate direct-RESOURCE-specific dependency
outage injection was added; its mandatory database authority reads and existing required authorization-store/audit
writes have no allow-on-failure fallback. Existing environment-gated `Phase03PersistenceIT` must remain disabled for this run because it
expects an external namespace.

Rollback is a source/image change only; there is no database rollback. Revert only this task's six files/hunks through
a reviewed change, preserving the pre-existing logout and deployment-document edits. Older code will stop admitting
these direct RESOURCE exchanges and reject the new direct RESOURCE tokens at online introspection. A signature-only
receiver may continue accepting an already-issued token until expiry; this change does not introduce immediate offline
revocation. Route revocation cuts off online validation under the new code; route replacement restores issuance
without reviving the revoked route's tokens, as tested. No rollback or deployment was performed.

## Boundaries

No control-plane/Argus file or `mcp-clients.yaml` was edited. The owner must separately move/configure `argus-mcp` and
its read-only route after release. This is local Axiom evidence, not an Argus remote MCP or production rollout test.
The implementation and test run did not deploy, push, merge, change Kubernetes, or reset data. Source publication
was authorized separately afterward; deployment and Argus configuration remain separate.
