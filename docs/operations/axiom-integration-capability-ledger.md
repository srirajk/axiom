# Axiom integration capability ledger (IDP-01–15)

**Status: implementation complete for review; NOT accepted.** Codex owns review and acceptance. Target: the *Identity
provider integration checklist* (IDP-01–12 baseline; IDP-13–15 conditional) and the *Axiom standards-based integration
workstream* (updated 2026-10-03). Checkout: `/Users/srirajkadimisetty/projects/axiom-changes`, branch
`hardening/phase-0-baseline`, HEAD `74e7e560d3df4a2efd22377c81301a07ae4867cd`; 132 dirty entries before this work (all
preserved). Nothing was committed, pushed, merged or deployed.

Cross-references: the earlier B/O/C catalogue and its evidence (`axiom-integration-scenario-ledger.md`) and the Phase
0–3 matrices remain unchanged; old B/O ids are given per row. The consumer scenario mapping created earlier the same day
was moved out of the cookbook to `docs/history/superseded-consumer-scenario-mapping-2026-10-03.json` (no runtime, test or
schema uses it; the workstream forbids a business-scenario index in Axiom — owner may delete it).

Contract: `docs/architecture/axiom-identity-provider-contract.md`. Profile: `examples/identity_scenarios/provider-profile.example.json`.
Deployment readiness (not applied): `docs/operations/axiom-phase0-test-deployment-readiness.md`.

## 1. Gaps reproduced before repair

Probe against the pre-change jar (SHA-256 `a82d3b37…`, the jar of the earlier 60/60 run), fresh isolated estate:

| Gap | Observed before repair |
|---|---|
| Customer browser login | `population` silently ignored (201, no field); customer credentials refused by the only (workforce) login page; a workforce person signed into the "customer" client |
| Confidential web client / refresh | `CONFIDENTIAL_WEB` → 400; no refresh token issued; `grant_type=refresh_token` → 401 |
| Interactive lifetime | `accessTokenTtlSeconds` silently ignored; tokens always 3600 s |
| `private_key_jwt` | `tokenEndpointAuthMethod`/`jwks` silently ignored: a *secret* client was created instead (201) |
| Secure defaults | source: `iam.auth.legacy-password-login.enabled` and `iam.auth.impersonation.enabled` default `true`; `IdpBaselineIT.legacyPasswordLoginAndImpersonationAreOffByDefault` fails on that default (mutation M1) |
| Customer continuation | customer-delegated tokens terminal (earlier B08 evidence); no customer browser token existed to continue |

Found and reproduced during this work (each with a failing regression first):

| Defect | Reproduction | Repair |
|---|---|---|
| Business scope issued beyond entitlement (a person entitled to `orders.read` got `orders.write` in the token) | Python IDP-04; `IdpBaselineIT.aBusinessScopeIsIssuedOnlyWhenThePersonHoldsThatPermission` failed | scope claim narrowed to held permissions at every issuance (incl. refresh); response `scope` follows the token |
| Token-type confusion: an **access token accepted as a refresh token** (HTTP 200, new tokens) | Python IDP-06 probe; `IdpBaselineIT` refresh test failed | Redis store: a typed lookup matches only a token of that type |
| Consent submission refused (400) by Axiom's PKCE filter | Python IDP-12 | PKCE parameters enforced on authorization requests only, not on the consent POST |
| RP-initiated logout by cross-origin form POST refused (403) by CORS | Playwright browser test | CORS not applied to the OIDC logout endpoint (navigation) |
| Unauthenticated authorization errors surfaced as 401 instead of 400 | Python IDP-02 | `/error` dispatch permitted |

## 2. Code changes (server)

`entity/TenantApplicationClient` (types `CONFIDENTIAL_WEB`, `interactive()`, `Population`), `dto/CreateTenantApplicationClientRequest`,
`dto/TenantApplicationClientResponse`, `service/TenantApplicationService` (postures, lifetimes, keys, `replaceClientKeys`,
`signInPopulation`), `service/ClientAssertionKeys` (new), `auth/RegisteredKeyClientAssertionDecoderFactory` (new),
`auth/CustomerAuthenticationToken`, `auth/CustomerLoginFilter`, `auth/PopulationLoginEntryPoint`, `auth/OfflineAccess`,
`auth/IssuedScopeTokenResponseHandler` (new), `auth/JwtClaimsCustomizer` (customer claims, population checks, scope
narrowing, refresh-family session lifetime, session-ended → `invalid_grant`), `auth/RedisOAuth2AuthorizationService`
(typed lookups, refresh reuse detection), `auth/AuthorizationCodeRedemptionLockFilter` (refresh serialization),
`auth/AuthorizationTenantResolver` (customers), `auth/CustomerTokenAuthorityValidator` (browser-login customer tokens for
exchange/introspection only), `config/SecurityConfig` (customer login, entry point, consent store, token generator,
`private_key_jwt`, discovery, CORS on logout, `/error`, admin TTL property), `config/S256PkceEnforcementFilter`
(population boundary, consent POST), `service/AgentExchangeAuthorityService` (`CUSTOMER_SESSION` profile and continuation),
`service/ApplicationAccessService`, `service/IamSessionService` (`revokeAllForPrincipalAndClient`),
`service/CiamCustomerAuthenticationService` (`current`), `service/CustomerOAuthConsentService` +
`controller/CiamOAuthConsentController` (new), identity-control `REPLACE_APPLICATION_CLIENT_KEYS`
(`entity/IdentityControlRequest`, `IdentityControlRequestService`, `IdentityControlApplyService`, `IdentityControlPayloads`),
`controller/AuthController` (secure defaults + startup warning), `controller/LoginController` + `templates/customer-login.html`,
migration `V40__interactive_client_population_and_consent.sql`.

Configuration and dependent migrations: Helm `values.yaml` and `_helpers.tpl` (`config.auth.*`, `config.oauth2.*`),
`deploy/phase0-isolated/values.yaml` (explicit `legacyPasswordLogin: true` for the harness), `compose.yaml` (opt-in
variables), Java IT fixtures (shared fixture moved to the authorization-code flow with the form-login assurance; five
suites declare an explicit legacy opt-in). Not migrated (documented): `scripts/configure_axiom.py`,
`publish-ciam-demo.py`, `verify-*.py` still call `/auth/login` and need the explicit opt-in.

## 3. Capability table

Legend — Implementation: Done / In progress / Not started / Blocked. Evidence: Passed (fresh run, §4) / Fixture only /
Not run / Not selected.

| ID | Profile / standard | Endpoint / configuration | Population | Positive | Denials | Impl. | Evidence | Old refs |
|---|---|---|---|---|---|---|---|---|
| IDP-01 | OIDC Discovery 1.0, RFC 8414, RFC 7517 | `/.well-known/*`, `/oauth2/jwks` | — | issuer pinned; endpoints on origin; grants/methods exactly as supported | unadvertised grants/methods refused; substituted key refused | Done | Passed (`idp01`, O01, O09, `IssuerLifecycleRepairIT`) | B01, O01, O09 |
| IDP-02 | OIDC Core, RFC 7636 (S256) | `/oauth/authorize`, `/login`, `/login/customer`, `/oauth/token` | workforce, CIAM | both populations sign in; ID token + nonce | wrong verifier, redirect mismatch, replay (session ended), missing PKCE (400), unregistered redirect, disabled client, cross-population credentials and sessions, unverified/suspended customer | Done | Passed (`idp02`, `test_idp_browser`, `test_o02_browser`, `IdpBaselineIT`) | O02, O03 (was blocked: D-O03 closed) |
| IDP-03 | RFC 6749 §4.4, RFC 7523 §2.2 | client credentials; `private_key_jwt` RS256/ES256 | software | secret and key clients get own-identity tokens | bad key, wrong aud, expired, >5 min, no jti, replay, wrong secret, excess scope, disabled | Done | Passed (`idp03`, `IdpBaselineIT`) | O04 |
| IDP-04 | RFC 9068 shape, RFC 8693 `resource` | single `aud`; per-client `accessTokenTtlSeconds`; scope policy | workforce | typ/alg/kid; claims; 300 s client TTL; `resource` target | wrong aud, edited, alg=none, ID token as access token, unentitled scope **narrowed**, TTL above ceiling, both resource+audience | Done | Passed (`idp04`, `IdpBaselineIT`) | O01 |
| IDP-05 | RFC 8693 (Axiom delegation profile) | token exchange; explicit edges | workforce, CIAM, software | chains preserve `sub`, `act` = workload, `client_id` = exchanger; customer continuation | other application, widening, no edge, `actor_token`, terminal resource, unaddressed token, other tenant | Done | Passed (`idp05`, `idp10`, C03, `IdpBaselineIT`) | O05, D-C2 (closed: continuation via customer-facing client of the same application + explicit edges) |
| IDP-06 | RFC 6749 §6, OIDC `offline_access`, RFC 9700 §4.14 | `CONFIDENTIAL_WEB`; rotation; reuse detection | workforce, CIAM | rotation; same subject; customer renewal | no offline_access, public client, wrong client, access/ID token as input, reuse withdraws family, 5 concurrent → 1, logout, disable, consent withdrawal, expiry | Done | Passed (`idp06`, `IdpBaselineIT`) | O07 (standing grant remains an optional extension) |
| IDP-07 | RFC 7662 | `/oauth/introspect` | all | active with claims; software without session | unknown, revoked, expired, logged-out → `{active:false}`; unauthenticated/wrong caller 401; other tenant `{active:false}`; Redis/PostgreSQL outage never active | Done | Passed (`idp07`, `idp10`, disruptive) | O06 |
| IDP-08 | RFC 7009, OIDC RP-Initiated Logout 1.0 | `/oauth/revoke`, `/connect/logout` (POST) | workforce (customers via IDP-06) | logout redirects to registered URI; independent logins continue | revoked access/refresh, descendants, renewal after logout, foreign revocation ineffective; browser session ended | Done | Passed (`idp08`, `test_idp_browser`, `IdpBaselineIT`) | O06, B10 |
| IDP-09 | Axiom lifecycle APIs (provider-specific) | signing keys; two-person secret/key rotation; disable/retire; `/admin/audit` | software | overlap; new key; audit read-back redacted; restart keeps keys/sessions/withdrawals | proposer self-approval, old key after overlap, disabled/retired issuance and status | Done | Passed (`idp09`, O08, disruptive) | O08, B10 |
| IDP-10 | acceptance property | — | all, two tenants | 40 concurrent exchanges, 0 mix-ups by (iss, sub); selective logout | customer token at admin/customer API; other tenant introspection and exchange; disable vs. racing issuance | Done | Passed (`idp10`, C02) | — |
| IDP-11 | SCIM 2.0 (RFC 7643/7644) + Axiom management API | `/scim/v2`, `/users`, memberships/roles, `/ciam/customers` | workforce, CIAM | SCIM user/group/membership; user CRUD/disable; role effect; truthful customer status | duplicate, non-admin, no SCIM bearer, stale If-Match (412), other tenant, disabled login, pending customer | Done | Passed (`idp11`) | B02, B04, B05, B06 |
| IDP-12 | Axiom client API (RFC 7591 not offered); standard OAuth consent | client postures; `requireConsent`; consent self-service | workforce, CIAM | each posture; access on/off; consent page; approved scope only; withdrawal; asked again | bad redirects, public secret, private key in jwks, offline_access on public, no access, declined consent, operator withdrawal | Done | Passed (`idp12`, `test_idp_browser`, `IdpBaselineIT`) | B03, B07, B08 |
| IDP-13 | RFC 9449 / RFC 8705 | — | — | — | DPoP ignored (bearer); not advertised | Not selected | Refusal only (`idp13_15`) | — |
| IDP-14 | RFC 7523 grant / chaining drafts | — | — | — | jwt-bearer and federation assertions refused | Not selected | Refusal only (`idp13_15`, C04) | — |
| IDP-15 | OIDC acr/amr/auth_time, RFC 9470 | password-level claims | workforce | asserted and preserved through exchange | caller-written acr ignored; software has none | Partial (profile not selected; MFA deferred) | Passed for what exists (`idp13_15`, C05) | — |

Remaining receiver obligations per capability: contract §7.

## 4. Fresh execution evidence (2026-10-03)

Sanitized copies (0 token-shaped values, checked): `docs/operations/evidence/idp-baseline-2026-10-03/`
(`python-full-run.json`, `java-full-run-summary.json`, `java-mutation-checks.txt`, `gap-reproduction-before-repair.txt`).

**Python (real isolated Axiom + PostgreSQL 16 + Redis 7 + Cerbos 0.53.0, HTTP only):**

```bash
cd examples/identity_scenarios
AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1 .venv/bin/python -m pytest -q -rs tests/
#   74 collected: 74 passed, 0 failed, 0 errors, 0 skipped, 0 xfail — 570.7 s, finished 2026-10-03T23:06:04Z
```

Composition: IDP-01..12 + conditional report 13 (`test_idp_baseline.py`), browser 2 (`test_idp_browser.py`,
`test_o02_browser.py`, Playwright 1.63.0 headless Chromium, no screenshot/trace/video), earlier packages A–D 25,
disruptive 2 (Redis/PostgreSQL outage fail-closed and recovery; restart keeps keys, sessions, withdrawals), offline 32.
42 live outcomes with 183 positive and 272 denial assertions. Server-log scan: 0 token-shaped matches. Cleanup:
nothing skipped; 0 cookbook containers and no `artifacts/` afterwards. Source fingerprint
`468798a0535b47452482b3b943e7be26ad6f95bdb12cf208592260d9da38c999` over 595 files (independently recomputed, equal);
server jar SHA-256 `1296b372…`; HEAD `74e7e560`. Versions: Python 3.12.7, requests 2.34.2, PyJWT 2.15.1,
cryptography 50.0.2, pytest 8.4.2, Java 25.0.3, Docker 29.8.0. An identical earlier run of the same source (jar
`bfc03ac9…`, before the last Java rebuild) also passed 74/74.

**Java (offline Maven, Java 25.0.3):**

```bash
cd server && mvn -o -B clean verify
#   surefire 410 / 410 passed
#   failsafe 192 tests (44 classes): 183 passed, 1 failure, 5 errors, 3 skipped (counts from the reports after the rerun below)
mvn -o -B verify -Dtest=NoSuchTest -Dsurefire.failIfNoSpecifiedTests=false -Dfailsafe.failIfNoSpecifiedTests=false -Dit.test=ExchangeEdgeScenarioIT
#   20 / 20 passed
```

* `IdpBaselineIT` (new) 10/10; `IssuerLifecycleRepairIT` 7/7; `LegacyLoginSwitchIT` 1/1; all Phase 1–3 authority ITs pass.
* `ExchangeEdgeScenarioIT.scopesNarrowAtEveryEdgeAndNeverWiden` failed in the full run because it asserted the defect
  repaired here (an unentitled scope present in the person's token). The assertion now requires narrowing (stricter);
  the class reran 20/20.
* Not passing, environmental, in committed classes not modified by this work (HEAD `b70c276`):
  `PromotionReachesRuntimeEnforcementBlobIT` (2 errors: `minio/minio` image cannot be pulled),
  `ProvisioningSagaConcurrencyIT` (3 errors: its context has no `iam.secrets.master-key`), `SelfContainedBundleIT`
  (1 failure: expects `policies/business_derived_roles.yaml` in the captured bundle). Skipped 3:
  `Phase03PersistenceIT`, gated on `AXIOM_PHASE03_TEST_NS=axiom-phase0-test` (Kubernetes; correctly not run).
  These were excluded from the earlier evidence of record as environment-gated; they remain open as such.
* Regression found and fixed during the run: the shared IT fixture's token lacked the password assurance that the real
  form login records (owner approvals then got 403); the fixture now reproduces the real form login's
  `AssuranceAuthenticationDetails`.

**Mutation checks** (each repair reverted alone, its regression run, source restored byte-identical; jar rebuilt
afterwards): M1 secure default, M2 typed token lookup, M3 refresh reuse withdrawal, M4 CORS on logout, M5 consent POST,
M6 scope narrowing, M7 population boundary, M8 single-use `jti` → the regression failed each time. **M9 survived:**
removing the customer-status re-check on delegated resource tokens does not fail the test, because customer
suspension also revokes the customer's sessions and the session check already stops the chain; the re-check is
defence-in-depth without an isolated regression.

## 5. Dependency and recovery behaviour

Redis down: introspection never active, no issuance, refresh redemption and `private_key_jwt` refused (jti store
unavailable → refuse). PostgreSQL down: no exchange. Recovery observed (active again) without reviving withdrawn
sessions or grants; restart keeps signing keys and sessions (disruptive tests). Refresh families end at the refresh TTL
from sign-in and on any session end.

## 6. What is simulated

Customer verification code delivery (loopback-only local-demo aid, labelled `LOCAL_DEMO (simulated delivery)`);
receiver/gateway fixtures in `axiom_cookbook/receiver.py`; the loopback callback server in the browser tests. No
external IdP, partner, platform or consumer product was used.

## 7. Open items (not claimed)

* Owner-deferred: native MFA/passkeys; customer verification and account-recovery delivery.
* Conditional profiles not selected: IDP-13 (DPoP/mTLS), IDP-14 (external assertions); IDP-15 assurance profile.
* Story 0.6: a machine operator client; until then `scripts/configure_axiom.py`, `publish-ciam-demo.py` and the
  `verify-*.py` scripts and the Phase 0 harness need the explicit legacy-login opt-in (Helm/compose values).
* Customer self-service (consent list/withdraw) authenticates with Axiom's JSON customer sign-in (an Axiom-specific
  password-to-token endpoint, still on by default); a browser-session account page would allow switching it off.
* The default consent page loads Bootstrap from a third-party CDN; replace with a self-hosted page before
  customer-facing use. `scopes_supported` lists only `openid`.
* Mutation M9 survived (see §4).
* Pre-existing environment-gated Java ITs (see §4).
* Kubernetes: not executed; see the readiness assessment (stop points: cluster-scoped Namespace document, dynamic PVs,
  shared Docker host image build).

---

## Acceptance pass (2026-10-03, second pass)

Checkout re-verified: `hardening/phase-0-baseline`, HEAD `74e7e560`; all earlier dirty work preserved. Paths changed by
another writer during this session and left untouched: `README.md`, `deploy/kind/README.md`, `deploy/axiom-test/`,
`deploy/helm/axiom-dependencies/`, `docs/operations/axiom-test-helm-evidence.md`.

### Reproduced before repair (`evidence/idp-acceptance-pass-2026-10-03/gap-reproduction-before-repair.txt`)

| Issue | Observed |
|---|---|
| Discovery `scopes_supported` | `["openid"]` only, while `profile`, `email`, `offline_access`, `roles` and business scopes are enabled |
| **UserInfo** (advertised) | **401 for workforce and customer application tokens** (the authorization-server chain validated bearer tokens with the `axiom-api`-audience decoder) |
| Consent page (both populations) | loaded its stylesheet from `stackpath.bootstrapcdn.com` |
| Workforce login page | loaded `fonts.googleapis.com` / `fonts.gstatic.com` |
| Operator scripts | require the legacy password endpoint (see below) |

Failing regressions first: `IdpBaselineIT.discoveryNamesTheEnabledScopesAndUserInfoServesBothPopulations` and
`IdpBaselineIT.loginAndConsentPagesLoadNoThirdPartyAssets` failed (2/2) before the repair and pass after it.

### Repairs

* `config/SecurityConfig`: `scopes_supported` = `openid`, `profile`, `email`, `offline_access`, `roles` + approved
  business scopes; new `userInfoJwtDecoder` (issuer, signature, `at+jwt`, active session; no audience restriction) for
  the authorization-server chain; custom consent page wired; `/oauth2/consent` in the chain.
* `controller/ConsentController` + `templates/consent.html` (new): Axiom's own consent page, local assets only, same form
  contract (`client_id`, `state`, `scope`).
* `templates/login.html`: Google Fonts links removed (system font stack).
* Tests: the two regressions above; the earlier consent IT now follows the redirect to `/oauth2/consent`.
* Cookbook: helper follows the consent redirect; IDP-01 asserts `scopes_supported` and UserInfo (workforce and customer
  200, software refused); IDP-03 adds `private_key_jwt` at introspection and revocation (own token); the browser test
  adds a workforce consent flow and asserts no third-party request.

### Operator scripts: missing contract (not designed)

No supported machine/CLI operator authentication path exists: the admin API accepts only legacy-endpoint tokens or
`axiom-admin` tokens, and `axiom-admin` has a single browser redirect URI; client-credentials tokens are workload
identities without operator roles. The exact contract options and required routes are in the provider contract §10.
The scripts therefore still need the explicit legacy opt-in; they were not changed.

### Fresh evidence (source fingerprint `ab775ec6a91262122ddd968ef95043f82b23fd07803a2546cc6aea1d0ca0d1e6`, 597 files; jar `c4ecac5e…`)

```bash
cd server && mvn -o -B clean verify
#   surefire 410/410
#   failsafe 194 tests: 185 passed, 1 failure, 5 errors, 3 skipped (after the rerun below)
mvn -o -B verify -Dtest=NoSuchTest -Dsurefire.failIfNoSpecifiedTests=false -Dfailsafe.failIfNoSpecifiedTests=false -Dit.test=UserDisableSessionRaceIT
#   8/8 (in the full run its Testcontainers PostgreSQL connection timed out during context start: infrastructure)
cd examples/identity_scenarios && AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1 .venv/bin/python -m pytest -q -rs tests/
#   74 collected: 74 passed, 0 failed, 0 skipped — 566.3 s, finished 2026-10-04T01:29:17Z
```

Python: 42 live outcomes, 189 positive and 275 denial assertions; server-log token scan 0; cleanup nothing skipped;
0 cookbook containers afterwards; browser third-party hosts: none. Java not passing (unchanged, environmental, committed
classes not modified by this work): `PromotionReachesRuntimeEnforcementBlobIT` (minio image unavailable),
`ProvisioningSagaConcurrencyIT` (no master key in its context), `SelfContainedBundleIT` (expects a policy file absent
from the bundle); skipped: `Phase03PersistenceIT` (Kubernetes-gated). Recovery evidence: the disruptive tests (Redis and
PostgreSQL outage fail closed and recover; restart preserves keys, sessions and withdrawals) passed in this run.

Invalid run disclosed: one browser reproduction attempt against a debug estate was invalidated because a Maven build
replaced the jar under the running JVM (`ClassNotFoundException`); it was discarded, not counted.

### Later isolated Helm packaging

The earlier “Kubernetes: not executed” statement applies to the first local IDP baseline pass. A later, separate
Docker Desktop deployment smoke of this source was completed in namespace `axiom-test` as application Helm revision 3.
The running server image is `axiom-server:axiom-test-20261003b`; the chart smoke test and live discovery passed.
The full 74-test Python cookbook was **not** run against that Kubernetes release. See
`docs/operations/axiom-test-helm-evidence.md` for image digest, namespace isolation and rollback evidence.

### Delegation chain (RFC 8693 `act`, 2026-10-05)

Corrected contract: `docs/architecture/axiom-token-delegation-chain.md` (R3 and R5 corrected, R6/R7 made precise,
R2 for exchanged software-only tokens left as an open owner decision, Argus impact unverified). Exchanged tokens now
nest prior actors verbatim on an actor change; malformed or over-deep (more than 5 levels) chains are refused with
`invalid_grant` and audited, never truncated. Evidence: `evidence/delegation-chain-2026-10-05/` (source fingerprint
`e4c0b269…`, 606 files; jar `1b2694a4…`).

```text
# focused: DelegationChainTest 6/6, JwtClaimsCustomizerTokenExchangeTest 3/3, DelegationChainIT 4/4
# mvn -o -B clean verify: surefire 419/419; failsafe 204 tests: 195 passed, 1 failure, 5 errors, 3 skipped
#   (SelfContainedBundleIT, PromotionReachesRuntimeEnforcementBlobIT, ProvisioningSagaConcurrencyIT: environmental, as before)
# Python cookbook: 76 passed, 0 failed (includes C06 delegation chain)
```

R2 decided 2026-10-05 (standards-first): a service acting only for itself has no `act`, including after a self-exchange
and across a broker hop; a takeover names only the new actor. Source binding now uses verified state (route named by
`authority_id`, its registered source workload, client = signed `sub`), not a self-referential `act`; exchange results are
recognised by `token_use`. Evidence: `evidence/delegation-chain-2026-10-05/r2-standards-first.txt` (surefire 424/424;
failsafe 193/206 with the 3 environmental classes plus 2 JDBC-loss classes that pass 5/5 and 12/12 in isolation;
Python 76/76).
