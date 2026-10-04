# `axiom-test` Helm rebuild evidence — 2026-10-03

Scope: Docker Desktop context `docker-desktop`, new namespace `axiom-test` only. The earlier isolated namespace
`axiom-phase0-test` and its four PVC/PV-backed volumes were removed after the owner explicitly authorized a
greenfield tear-down. The original `axiom` namespace and Argus namespaces were not changed. No production,
GatewayClass, public ingress, NodePort or LoadBalancer resource was installed. No merge or push.

## Render and packaging

- `deploy/helm/axiom-dependencies` release is installed first; it owns namespaced PostgreSQL, Redis, Cerbos,
  ConfigMaps, four claims (two StatefulSet templates), quota, limit range and eight NetworkPolicies.
- Existing `deploy/helm/axiom` release is installed second; its pre-install Secrets check and tenant bootstrap
  completed, followed by the readiness/issuer verify hook.
- Both charts linted with their `deploy/axiom-test/*.yaml` values; dependencies rendered without a Namespace or
  cluster-scoped object and passed Kubernetes server dry-run. The app's server dry-run accepted all ordinary
  resources; its Helm-test pod could not be server-dry-run as one atomic stream because its ServiceAccount did not
  yet exist. The actual Helm install and test succeeded.
- Runtime and signing-key Secrets were created by operator scripts, not by Helm. The signing key Secret is immutable.
  Credentials were not displayed or added to a values file.
- Server image was built from this clone as `axiom-server:axiom-test-20261003a` and ran with image ID
  `sha256:c92976ce8a952f1b38bf20918bad28f02f77b8f4a5ec7aaa3bcc128ca04f5595`. The Admin image is the
  unchanged `axiom-admin:phase0-codex-74e7e56`.

## Live acceptance observed

| Check | Observation |
|---|---|
| Dependencies | PostgreSQL, Redis and Cerbos pods 1/1 Ready; four PVCs Bound on `desktop-worker` |
| Dependency Helm test | `axiom-dependencies-test` Succeeded, PostgreSQL TCP, Redis PONG and Cerbos HTTP health |
| App Helm install | `axiom` release deployed, preflight and bootstrap hooks completed, server/Admin pods 1/1 Ready |
| App Helm test | `axiom-smoke` Succeeded: server readiness, exact issuer discovery, Admin UI and CIAM runtime config |
| Read-only port-forward | `/actuator/health/readiness` reported UP; OIDC metadata issuer exactly `http://axiom.axiom-test.svc.cluster.local:8084`, code/refresh/token-exchange grants advertised, JWKS had one key |
| Live negative HTTP checks | A fabricated Basic client at `/oauth/token` returned 401; `/auth/login` with dummy credentials returned 404 with the legacy-login switch off |
| Network-policy canaries | Unlabeled pod and Admin-labeled pod both failed to reach Redis; each canary completed its expected-denial assertion, then was deleted |
| Exposure | Five ClusterIP Services, no externally exposed Service; quota shows zero NodePorts and LoadBalancers |
| Java 25 source tests | `JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home mvn -o -B test`: 410 run, 0 failures, 0 errors, 0 skipped; BUILD SUCCESS |

The dependency policy was tightened after the initial install so Admin-labeled pods no longer have database, Redis
or Cerbos egress. Dependency release revision 2 and app release revision 2 are both `deployed`; both Helm tests passed
after the policy update. The app release was upgraded to replace domain-specific demo scopes/client name with
generic example values; its bootstrap/verify hooks, smoke test and server/Admin rollout passed again. The live server
environment shows `IAM_AUTH_LEGACY_PASSWORD_LOGIN_ENABLED=false` and `IAM_AUTH_IMPERSONATION_ENABLED=false`.

## Deliberate limits

This is an isolated **deployment** smoke, not certification of the full IDP-01–12 contracts or external client
readiness. The reusable Python cookbook runs against its own disposable local Axiom/PostgreSQL/Redis estate; its
target guard intentionally refuses Kubernetes Service DNS names. The in-cluster HTTP issuer cannot be resolved by a
normal browser or external relying party, and no public TLS/issuer design is installed here. Browser PKCE/CIAM
proof is the separate cookbook evidence, not a claim made by this Helm test. The prior 74/74 Python and 410/410
Java source tests were rerun during this chart work; the current checkout passed 410/410. The Python cookbook's
74/74 full-suite result is prior evidence and was not rerun against this Kubernetes release. This release adds no
new application source changes.

This local profile retains one server replica, uses a single-node ReadWriteOnce policy-runtime PVC and relies on the
Docker Desktop NetworkPolicy implementation. Those are not production architecture claims. The old Phase 0 harness
and Argus-specific quickstart fixtures still target the retired namespace; use the new profile and the generic
cookbook instead of treating those historical files as this release's test suite.

## Revision 3: current Axiom baseline image

On 2026-10-03, the server was rebuilt from the later Axiom IDP-01–12 source and loaded as
`axiom-server:axiom-test-20261003b` (image ID
`sha256:0543a0cd8f6161f74c7934c57cc63645b33087d77ffdd5e1f47ff5e17c0791a4`). The image tag in
`deploy/axiom-test/values.yaml` is unique to this build. The dependency release and its four existing PVCs were not
replaced. The application chart linted, and a Helm server-side dry run succeeded before an atomic upgrade of only
release `axiom` in namespace `axiom-test` from revision 2 to revision 3.

After the upgrade, the server, Admin, Cerbos, PostgreSQL and Redis pods were all 1/1 Ready; the four claims remained
Bound. `helm test axiom -n axiom-test --logs` completed `axiom-smoke` successfully. A read-only live discovery request
from the server pod returned the expected internal issuer, `userinfo_endpoint`, code/refresh/client-credentials/token-
exchange grants, and `scopes_supported` containing `openid`, `profile`, `email`, `offline_access`, `roles`,
`example:read` and `example:write`. The running server pod reported the same image digest above. The original `axiom`
namespace still had its existing Axiom, Admin, Cerbos, PostgreSQL and Redis pods Running with zero restarts.
The unchanged dependency release was retested after the upgrade: `axiom-dependencies-test` succeeded and reported
“Axiom dependency connectivity passed.”

Before the image build, Java 25 unit tests passed 410/410, and the focused `IdpBaselineIT` passed 12/12, including a
new regression assertion that an ID token is refused as a UserInfo bearer token. Claude's previous local Python
cookbook result was 74/74 against this server source before that test-only assertion and the image-tag change; the
full cookbook was **not** rerun against this Kubernetes release. This remains an isolated deployment smoke, not a
claim of production readiness, external-browser issuer reachability or full in-cluster IDP contract execution.

Recovery: Helm revision 2 remains in release history. If revision 3 needs reversal, use
`helm --kube-context docker-desktop rollback axiom 2 -n axiom-test --wait`; do not delete the namespace or its PVCs.
