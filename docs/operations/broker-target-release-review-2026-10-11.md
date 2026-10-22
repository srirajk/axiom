# Broker-target release review — 2026-10-11

Scope: `hardening/phase-0-baseline` at `475ca72` plus the current uncommitted Axiom clone changes. Source/test review was followed by a disposable Docker Desktop deployment in namespaces `axiom`, `gateway-demo` and `envoy-gateway-system`; this is not a production release.

## Behavior and compatibility

- A broker target is tenant- and broker-specific. It grants the broker permission to exchange for one target audience, but does not authorize the source workload's business action. The inbound workload-to-gateway route remains mandatory and caps the issued token's lifetime.
- The issued token retains the original `sub`; the broker appears in `client_id`, not in `act`. A self-acting workload has no `act`; a person chain retains its signed actor chain. These are Axiom's RFC 8693 profile rules, not universal requirements for every identity provider.
- Each broker-target token pins the source workload and gateway-entry route with signed `source_workload_id` and `source_gateway_route_id`. Online introspection and continuation recheck the active workload/client, route type/source/audience/scopes, broker and target. Revoking either route or target fails closed for those online paths.
- Older broker-target tokens lacking `source_gateway_route_id` fail closed and must be reissued. Offline JWT-only receivers cannot observe revocation until token expiry; immediate revocation requires introspection.

## Verification

| Gate | Result |
|---|---|
| HTTP-level broker-target route revocation (`EntryAgentGatewayScenarioIT`) | Passed: active introspection before revocation, inactive afterward; continuation denied with `invalid_grant`. |
| Previously failing integration fixtures (`SelfContainedBundleIT`, `ProvisioningSagaConcurrencyIT`, `PromotionReachesRuntimeEnforcementBlobIT`) | Passed 8/8 on targeted rerun. The S3 test uses Adobe S3Mock, which is an S3 API test double, not production object-storage proof. |
| Java 25 `mvn -o -q verify` | Exit 0; 463 unit tests passed, 214 integration tests with 0 failures/errors and 3 skipped. The 3 skips are `Phase03PersistenceIT` checks gated by `AXIOM_PHASE03_TEST_NS`. |
| Python `AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1 ./.venv/bin/python -m pytest -q tests/` | 76 passed, 0 failed/skipped; owned local PostgreSQL/Redis/Cerbos estate cleaned up, log scan found 0 token-shaped values. Evidence: `examples/identity_scenarios/evidence/last-run.json`. |
| Source whitespace | `git diff --check` passed. |
| Fresh local deployment | `axiom-dependencies` and `axiom` Helm releases revision 1 deployed in `axiom`; Envoy Gateway `v1.9.1` revision 1 deployed in `envoy-gateway-system`. Server/admin 1/1 Ready; both Helm tests passed. |
| Database and network | Flyway V41–V44 succeeded; PostgreSQL/Redis/Cerbos are Ready; the unlabeled-pod canary resolved Redis DNS but could not reach Redis, and was removed. |
| Local HTTPS edge | GatewayClass Accepted, Gateway Programmed, all four HTTPRoutes Accepted/ResolvedRefs; data-plane Service is ClusterIP. Verified local-CA TLS, readiness UP, exact OIDC issuer, Admin HTTP 200 and HTTP-to-HTTPS redirect through a loopback-only port-forward. |

The running image IDs are `axiom-server@sha256:8fe7bdbf1660ca2a717bf8dd3f815c228881a99ddca04a42f8632e55a02fc220`
and `axiom-admin@sha256:06886db54bc9b0a1c3935ec3e3db9b81233b474ba1e067830cf9b5f53ee6943e`.
The source checkout contains uncommitted changes, so the image digests—not HEAD alone—identify these exact local builds.
The operator-owned runtime and signing credentials were reused; only the disposable edge TLS certificates were renewed,
with the prior TLS files retained under `private/certs/previous-*`.

## Remaining release boundary

The Kubernetes rollout is **local and disposable only**. It does not prove production object-store behavior, external consumer enforcement, or production readiness. A receiver requiring immediate revocation still must introspect. The local issuer URL works only while its foreground `127.0.0.1` Envoy port-forward remains running, and the local CA is test-only. Keep the original Axiom and Argus checkouts untouched; no merge or push was performed.
