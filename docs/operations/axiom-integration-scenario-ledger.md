# Axiom integration scenario ledger (Python cookbook and HTTP contract suite)

**Status: in progress. Not accepted.** Codex owns review and acceptance. Scope: the consumer-neutral identity
contracts of the Axiom server in the isolated clone `axiom-changes` (branch `hardening/phase-0-baseline`). This ledger
is new; the Phase 0–3 evidence matrices in this directory are historical and unchanged. B/O/S identifiers below
belong only to this catalogue; original phase/story numbers appear as cross-references.

Brief: `axiom-only-python-scenario-workstream.md` (owner scope confirmed 2026-10-03). Starting point:
HEAD `74e7e560d3df4a2efd22377c81301a07ae4867cd`, 122 dirty entries recorded before the first edit
(all earlier Phase 2/3 work, preserved).

Cookbook: `examples/identity_scenarios/` (README there). Consumer contract:
`docs/architecture/axiom-consumer-identity-contract.md`. Scenario mapping: `examples/identity_scenarios/scenario_catalog.json`.

---

## Checkpoint A — contract and cookbook foundation (2026-10-03)

**Files created:** `examples/identity_scenarios/` — `pyproject.toml`, `axiom_cookbook/{__init__,redaction,target,http,
oauth,tokens,estate,context,example}.py`, `basics/b01..b05`, `oauth/o01,o02,o04`, `tests/{conftest,test_package_a,
test_safety_offline}.py`, `.gitignore`; this ledger. No server source changed in Package A.

**Estate (real, isolated):** `axiom_cookbook/estate.py` starts PostgreSQL 16, Redis 7 and Cerbos 0.53.0 containers
(label `axiom.cookbook.run=<id>`, published on 127.0.0.1 only), runs the supported one-shot bootstrap
(`--spring.main.web-application-type=none`, `AXIOM_BOOTSTRAP_*`) and then the Axiom server jar
(`server/target/iam-service-1.0.0.jar`, Java 25). Generated credentials stay in memory and a 0600 state file.
Teardown removes only the run's labelled containers and its run directory; `reap` handles interrupted runs.

**APIs exercised (all over HTTP):** `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`,
`/oauth2/jwks`, `/oauth/authorize` + `/login` (form, CSRF) + `/oauth/token` (authorization_code + S256 PKCE,
client_credentials, password grant refused), `/roles`, `/users`, `/users/{id}/roles`, `/users/{id}/teams`, `/teams`,
`/teams/{id}/members`, `/api/me/sessions`, `/admin/tenants/{t}/applications`, `.../clients`, `.../access/roles`,
`.../access/memberships`, `.../memberships/{m}/roles`, `/admin/tenants/{t}/ciam/agent-workloads` (+ suspend,
reactivate, retire), cross-tenant `/admin/tenants/{other}/sessions`.

**Operator path:** root `platform_admin` exists only via bootstrap; it logs in through the browser authorization-code
flow (public client `axiom-admin`, S256 PKCE, CSRF-protected form) once to create two `tenant_admin` operators. No
`/auth/login` password-to-token call is used by the cookbook. Gap: Axiom has no machine operator client (story 0.6).

**Commands and counts:**

```bash
cd examples/identity_scenarios
python3 -m pytest -q tests/                      # 28 passed (8 live examples, 20 offline safety tests)
python3 -m pytest -q tests/test_package_a.py     # one family
python3 -m pytest -q "tests/test_package_a.py::test_example[oauth.o02_workforce_authorization_code]"   # one example
```

Python 3.12.7, requests, PyJWT, cryptography, pytest (versions in the evidence file); Java 25.0.3.

**Positive / negative assertions (per example, recorded in `evidence/last-run.json`):**
B01 issuer/JWKS/operator token validated; password grant, tenant-role escalation, unauthenticated and forged calls
refused. B02 user create/read/update/own sessions; duplicate id, cross-tenant administration, disabled user's token and
re-login refused. B03 identifier distinctions, PKCE-required public client, one-time secret; secret re-read, public
client credentials grant and insecure redirect registration refused. B04 role permission in token and audience;
non-member login, cross-application role, removed permission refused; freshness boundary observed (pre-removal token
keeps its claim). B05 team membership listed/removed; team `defaultRoles` grants nothing; non-admin team creation
refused. O01 signature/iss/aud/exp/typ validation; wrong audience, edited claims, `alg=none`, ID token as access token
refused (locally and by Axiom). O02 code+PKCE+state+nonce; wrong verifier, redirect mismatch, code replay, unregistered
redirect, missing PKCE, disabled client refused. O04 workload token without person/actor; wrong secret, excess scope,
suspended workload and disabled client refused; reactivation restores.

**Security fix in the cookbook (from Codex review, before further live credential-bearing tests):**
`axiom_cookbook/http.py` accepted an absolute URL as `path`, so a bearer token, Basic credentials or a form could be
sent to a host other than the guarded target. Fixed: every request resolves through `AxiomHttp.resolve`, which only
accepts paths and same-origin absolute URLs (scheme, host and port must equal the verified target; `//host` refused);
the HTTP library never follows redirects itself, and each redirect hop is resolved through the same check;
`Validator.discover` also requires the discovered issuer to equal the target and the JWKS to live on it. Regression
tests (offline, no network): bearer to five foreign forms, Basic auth to two, cross-origin redirect with credentials,
same-origin hop-by-hop redirects, no library auto-redirect, discovery pointing keys or issuer elsewhere — all pass
(within the 28 above).

**Isolation / recovery:** each run leaves zero `axiom.cookbook.run` containers (verified after runs); cleanup disables
or revokes only records in the run's `ckbk-<hex>` namespace through the API (users soft-deleted, applications/clients/
memberships disabled, workloads retired, teams deleted) and reports residuals; no SQL deletion.

**Open after A:** machine operator client (0.6); B06–B11, O03, O05–O09 and S01–S21 are later packages.

---

## Interim note B-1 — O06 failure diagnosed and fixed; logout token kept out of URLs (2026-10-03)

**Observed:** the Package B run collected 3 tests and failed 1 (`oauth.o06_introspection_revocation_logout`), with
no outcome: the client timed out at line 69, `POST /admin/tenants` (creating a second tenant for the disclosure
check). A longer client timeout (180 s, then 240 s) did not help.

**Diagnosis (evidence, not inference):** a virtual-thread dump (`jcmd <pid> Thread.dump_to_file`) of the running
estate showed the request blocked in `ProvisioningLedgerTransactions.startProvision` →
`ProvisioningOperationRepository.lockIdempotencyKey` (`pg_advisory_xact_lock(hashtextextended(:key, 0))`). The
tenant lifecycle saga had already taken a *session* advisory lock on a second pooled connection with
`hashtextextended(tenantId, 0)` (`TenantLifecycleLockStore.openAdvisorySession`). The example sent
`Idempotency-Key` equal to the tenant id, so the request waited on its own lock forever, pinning a connection and the
tenant's lifecycle lock. This is a real Axiom defect: any caller choosing the tenant id as its idempotency key hangs
provisioning of that tenant.

**Fix (minimal, no assertion weakened):** `ProvisioningOperationRepository.lockIdempotencyKey` now locks
`hashtextextended('provisioning-idempotency:' || key, 0)`, a namespace disjoint from the lifecycle lock. Other
advisory locks were checked: invocation-context locks use prefixed keys, Policy Studio locks use different seeds (2,
3). O06 deliberately keeps `Idempotency-Key == tenantId` as the live regression. (The Java provisioning ITs are
environment-gated; the cookbook estate has a real Cerbos, so the Python run is the regression evidence.)

**Logout token handling:** O06 (and the Java regression) now call OIDC RP-Initiated Logout with
`POST /connect/logout` and a form field `id_token_hint`, which OIDC RP-Initiated Logout 1.0 lets the OP accept.
No token appears in any URL. Proof that no token reaches logs or evidence: at teardown the test harness scans the
estate's `server.log` and `bootstrap.log` for JWT-shaped strings and fails the run on any match; the evidence file
records the scan. Errors and assertion messages pass through `scrub`/`scrub_text`, and the evidence file is withheld
if it would contain a token-shaped value.

**Expiry wait bound:** O06 sleeps only for the issued `expires_in`, and fails immediately (no sleep) if that is not
in (0, 60] seconds; the cookbook profile issues 30-second workload tokens (`IAM_OAUTH2_CLIENT_CREDENTIALS_TTL`).

**Rerun result:** `python3 -m pytest -q tests/test_package_b.py -k o06` → 1 passed (collected 1 of 3, the other two
deselected), 87.98 s. `evidence/last-run.json`: `collected 1, failed 0`,
`server_log_scan {logs_scanned: [bootstrap.log, server.log], token_shaped_matches: 0}`. Java:
`IssuerLifecycleRepairIT` 7/7 with the POST logout. The full Package B result is recorded in checkpoint B.

---

## Checkpoint B — issuer lifecycle and exchange (2026-10-03)

**Server files changed (Package B):** `service/IamSessionService.java` (session id for an authorization; revoke one
authorization's session; revoke all of a client's sessions), `repository/IamSessionRepository.java` (locked lookup of
a client's active sessions), `auth/RedisOAuth2AuthorizationService.java` (session revoked when the access token is
invalidated — RFC 7009 and code replay — and on `remove`), `config/OAuth2AuthorizationStoreConfig.java`,
`config/SecurityConfig.java` (OIDC logout ends the durable session; discovery advertises only supported grants,
methods and PKCE S256 — no DPoP/mTLS/device/PAR), `auth/SessionAwareIntrospectionAuthenticationProvider.java`
(sessionless client-credentials tokens active only for an active confidential workload client of the same tenant;
cross-tenant introspection returns only `active=false`), `auth/JwtClaimsCustomizer.java` (client-credentials lifetime
capped by `iam.oauth2.client-credentials.ttl`, default 5 min, max 1 h), `service/TenantApplicationService.java`
(disabling an application/client or revoking a secret ends that client's sessions),
`controller/AuthController.java` (`iam.auth.legacy-password-login.enabled`, `iam.auth.impersonation.enabled`; off →
404), `controller/SigningKeyController.java` (signing-key changes are `platform_admin` only),
`tenancy/ProvisioningOperationRepository.java` (idempotency lock namespaced; interim note B-1).
**Tests added:** `IssuerLifecycleRepairIT` (7), `LegacyLoginSwitchIT` (1), `AuthorityITSupport.pkce(…)` helper.
**Cookbook added:** `oauth/o05–o09`, `basics/b09–b11`, `tests/test_package_b.py`, `tests/test_disruptive.py`.

**Mutation checks (M1–M6):** six repairs were reverted one at a time: token invalidation ends the session (code
replay / RFC 7009); OIDC logout ends the session; live client status for client-credentials tokens; cross-tenant
introspection disclosure; client disable ends sessions; honest discovery. The matching `IssuerLifecycleRepairIT` test
failed each time (`rc=1`), and sources were restored byte-identical. The platform-admin-only signing-key rule and the
legacy-login switch are covered by their regressions but were not mutation-checked.

**APIs exercised (Python, HTTP):** `/oauth/token` (token-exchange, client_credentials, `refresh_token` refused,
standing-grant extension), `/oauth/introspect`, `/oauth/revoke`, `POST /connect/logout` (form `id_token_hint`),
`/admin/tenants` (second tenant), `/admin/tenants/{t}/sessions` (+ revoke), `/api/me/sessions` (+ revoke),
`/api/me/standing-grants` (+ revoke), `/admin/tenants/{t}/agent-exchange/brokers|routes` (+ revoke),
`/admin/tenants/{t}/ciam/agent-workloads/{w}/suspend|reactivate|retire`, client secret rotation (two-person),
`/admin/.../signing-keys` (create/activate/retire), `/.well-known/*`, `/oauth2/jwks`.

**Java (Java 25.0.3, offline Maven), full regression of the Package B source** (`mvn -o -B verify` with the 33
Phase 1–3 and Package B IT classes): surefire **409/409**, failsafe **157/157**, 0 failed, 0 errors, 0 skipped,
`rc=0`. Reports kept outside the tree.

**Build-hygiene finding:** `target/classes` still held `V39__action_approval_token_binding.sql`, an abandoned
migration from 2026-10-02 whose source had been deleted (it added an unused nullable column `consumed_token_id`; no
source references it). Builds before 2026-10-03 15:40 (local time), including the run above and the Package A/B
Python runs, therefore applied that extra column. It surfaced when Package C added a real `V39`; all later evidence
comes from `mvn clean` builds.

**Disruptive recovery wait (Codex review):** the outage test's recovery loop stopped when introspection *raised*,
because `_safe` returns the exception object, which is not `None`. Fixed: the loop now waits up to 60 s for a
response that is a dict with `active is True` (`_active`), records the elapsed time, and fails if recovery never
happens. Offline regression `test_recovery_wait_accepts_only_a_genuinely_active_result` covers exceptions,
`None`, `{}`, `active=false`, `active="true"`, error bodies and lists. Rerun:
`AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1 python3 -m pytest -q -rs tests/test_disruptive.py` → **2 passed, 0 skipped**
(106 s); recovery observed as genuinely active after 0.2 s; server-log token scan 0 matches
(`evidence/disruptive-run.json`).

**Full Python suite covering Packages A–C (and C01):**
`AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1 python3 -m pytest -q -rs tests/` → **44 collected, 44 passed, 0 failed,
0 skipped** (273 s; 2026-10-03T19:51:36Z; HEAD `74e7e56`, 132 dirty entries, dirty fingerprint `b801b93b77d341c2`;
server-log token scan 0 matches; `evidence/full-run-1.json`). Composition: 21 offline safety tests, Package A 8,
Package B 8, Package C 4, Package D 1 (C01), disruptive 2.

**Positive / negative highlights:** O05 person on-behalf-of through an intermediary to a resource, workload-only,
and an authorized workload-to-workload continuation; 7 denials (other workload, widening, unknown audience,
`actor_token`, terminal resource token, unaddressed token, outsider). O06 logout/session revocation/RFC 7009/expiry
inactive online, residual offline window shown, cross-tenant disclosure `{"active": false}`. O07 rotation, reuse
withdraws the grant, exactly one of 5 concurrent redemptions wins, withdrawal and 8 s expiry refused;
`refresh_token` → `invalid_grant`. O08 signing-key rotation by root only, `tenant_admin` 403, retiring the previous
key 409; two-person secret rotation with a 15 s overlap. O09 discovery lists only supported capabilities and the
refused ones are refused. B09–B11 workload lifecycle, edges, session lifecycle and rerun/cleanup.

**Isolation / recovery:** each run leaves zero `axiom.cookbook.run` containers; Redis and PostgreSQL outages fail
closed (no active introspection, no issuance, no exchange) and recover; a restart keeps signing keys, keeps active
sessions, does not revive a revoked session, and (added in Package D) does not revive a withdrawn standing grant.

**Open after B:** none in the B scope beyond the machine operator client (0.6).

---

## Checkpoint C — CIAM identity and delegation (2026-10-03)

**Server files changed:** `db/migration/V39__customer_provisioning_source.sql` (new column `provisioning_source`,
`SELF_REGISTRATION` default, `ADMINISTRATOR`), `entity/CustomerIdentity.java`, `dto/CiamContracts.java`
(`ProvisionCustomerRequest`; `CustomerResponse.provisioningSource`), `service/CiamCustomerService.provision(…)`,
`controller/CiamAdminController.java` (`POST /admin/tenants/{t}/ciam/customers`). An administrator-provisioned
customer starts `PENDING_VERIFICATION` with `emailVerifiedAt=null`. No challenge or code is issued to, or
returned to, the administrator. The customer verifies through the ordinary customer-requested challenge. Nothing
else about the status model changed.
**Test added:** `CustomerAdministratorProvisioningIT` (2): pending/ADMINISTRATOR/unverified with no code, challenge
or delivery row; no sign-in while pending; duplicate 409; other tenant's admin 403; unauthenticated 401; short
password 400; pre-existing rows default to SELF_REGISTRATION.
**Cookbook added:** `axiom_cookbook/ciam.py`, `ciam/b06_customer_identity.py`,
`ciam/b07_customer_application_access.py`, `ciam/b08_consent_grants.py`, `ciam/o03_customer_login.py`,
`tests/test_package_c.py`. The estate now enables `IAM_CIAM_LOCAL_DEMO_CHALLENGE_DISCLOSURE=true`. **Simulated
delivery:** Axiom's loopback-only local-demo aid returns the verification code to the *customer's own* request.
Axiom refuses to start with it on a non-loopback issuer or beside a real provider. Every such verification is
labelled `LOCAL_DEMO (simulated delivery)`. It proves the verification endpoint, not mailbox delivery. Recovery codes
are never disclosed; recovery stays deferred.

**Java:** `mvn -o -B clean verify -Dtest='Ciam*Test,*Customer*Test' -Dit.test='CustomerAdministratorProvisioningIT,
CustomerCodeNoProviderIT,CustomerCodeLocalDemoIT,CustomerCodeDeliveryIT,ConsentPurposeIT'` → unit 7/7, IT 17/17,
`rc=0` (after the clean build noted in checkpoint B; the first attempt failed to start because of the stale
duplicate V39).

**Python:** Package C ran inside full run 1 (4/4). APIs: `/admin/tenants/{t}/ciam/customers` (POST, GET,
suspend, reactivate), `/ciam/tenants/{t}/customers/registrations|verification-challenges|verifications|tokens|{id}`,
`…/delegation-grants` (create, list, revoke), `/admin/tenants/{t}/ciam/delegation-grants`,
`/admin/tenants/{t}/ciam/agent-workloads/{w}/purposes`, token exchange with `delegation_purpose`, introspection.

**Positive / negative:** B06 both creation paths and verification; refused: sign-in before verification, code reuse,
duplicate e-mail (both paths), customer reading another customer, customer token on workforce and admin APIs,
workforce operator credentials as a customer, another tenant's administration, suspended customer (token and
sign-in); reactivation does not revive the pre-suspension token. B07 customer token bound to the customer-facing
client's scope ceiling; refused: unregistered scope, unapproved scope, confidential client, unknown client, disabled
client (issuance and outstanding token). B08 customer-recorded consent with and without a registered purpose, operator
inspection, exchange producing `sub`=customer, `act`=workload, `delegation_id`=grant; refused: operator recording or
withdrawing consent (401), ambiguous match of two grants, other workload, widening, other customer's token, other
customer withdrawing, onward exchange, withdrawn grant (outstanding token inactive at once), expired grant. An
independent grant stays usable. O03 the supported customer endpoint issues one customer token and no ID token;
refused: customer credentials on the workforce browser login, wrong password, unverified customer.

**Findings recorded, not changed:**
- The `/ciam/**` chain decodes only customer tokens. The `tenant_admin` branch of the delegation controller's
  `@PreAuthorize` is unreachable over HTTP. Consent is therefore customer-only in practice
  (`consentSource=ADMINISTRATOR` cannot be produced via HTTP), and operators cannot withdraw a customer's consent:
  they inspect it, suspend the customer or revoke the workload. Making the code match this, or adding an operator
  withdrawal API, is an owner decision.
- `scope` is a space-separated string in login tokens and a JSON array in exchanged tokens; receivers must accept
  both.

**Open after C (owner decisions, nothing implemented):**
- **D-O03** standard customer browser login (authorization code + PKCE, ID token, customer session). Today's
  customer endpoint is Axiom-specific JSON.
- **D-C2** customer downstream continuation. Axiom deliberately makes customer-delegated tokens terminal
  (`AgentExchangeAuthorityService`: "not transitive"). Continuing to a resource through an operator-registered edge
  would extend the customer's consent to an audience the customer never named. Options: (a) consent must name each
  downstream resource audience, with continuation allowed only to those; (b) operator edges may extend scope-bounded
  consent, re-checking the grant by `delegation_id` at every hop and at introspection. Recommended: (a). Not
  implemented, so S02's "permitted downstream continuation" remains open.

---

## Checkpoint D — advanced issuer contracts and integrator handoff (2026-10-03)

**Files:** `examples/identity_scenarios/axiom_cookbook/receiver.py` (a generic receiver fixture with offline and
online modes), `consumer_contracts/c01_receiver_enforcement.py`, `c02_one_workload_many_subjects.py`,
`c03_workload_chains.py`, `c04_untrusted_issuers.py`, `c05_authentication_assurance.py`, `tests/test_package_d.py`,
`tests/test_disruptive.py` (S12: standing grant survives a restart; a withdrawn one is not revived),
`scenario_catalog.json` (all 21), `README.md` (developer guide), and
`docs/architecture/axiom-consumer-identity-contract.md`. The empty `workforce/` package was removed (workforce flows
live in `basics/` and `oauth/`). No server change in Package D.

**Observed facts:** C01 offline residual window 297 s after session revocation (bounded by token lifetime). The
online receiver and model-route fixture refuse at once, and denied requests recorded no protected action. C02 40
concurrent exchanges on one workload client for two people and two customers, 0 mix-ups; selective revocation left B
untouched. C03 chain person→portal-svc→edge→reports-svc→edge stops where edges end; substitution and unaddressed
tokens refused. C04 negative-only: a forged signature claiming Axiom's issuer, a partner issuer, `jwt-bearer`,
`private_key_jwt`, the workload-federation assertion (no provider profile), and id_token/jwt/saml2 subject types are
all refused. Discovery advertises no sender-constrained tokens. C05 password-level `acr`/`amr`/`auth_time` on
interactive login, preserved through exchange. Caller-supplied `acr`/`amr` parameters are ignored (request accepted,
`acr` not raised). Workload and customer tokens carry no assurance.

**Mutation check (Package C):** `CiamCustomerService.provision` made to verify the customer at creation →
`CustomerAdministratorProvisioningIT` failed (`expected "PENDING_VERIFICATION"`); source restored byte-identical
(`cmp`), jar rebuilt with `mvn clean package`.

**Final runs (fresh, from clean builds of the current tree):**

```bash
cd server && mvn -o -B clean verify -Dit.test='<34 IT classes: Phase 1–3, IssuerLifecycleRepairIT, LegacyLoginSwitchIT, CustomerAdministratorProvisioningIT>'
#   surefire 409/409, failsafe 159/159 (34 classes), 0 failed, 0 errors, 0 skipped, rc=0   (Java 25.0.3)
cd examples/identity_scenarios && AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1 python3 -m pytest -q -rs tests/
#   48 collected, 48 passed, 0 failed, 0 skipped, 317.9 s, finished 2026-10-03T20:12:19Z
```

Python evidence `evidence/full-run-final.json`: HEAD `74e7e560`, 132 dirty entries, dirty fingerprint
`b801b93b77d341c2`, Python 3.12.7, 27 live outcomes (97 positive and 144 denial assertions) + 21 offline safety
tests, server-log token scan 0 matches. Composition: offline 21, Package A 8 (B01–B05, O01, O02, O04), Package B 8
(O05–O09, B09–B11), Package C 4 (B06–B08, O03), Package D 5 (C01–C05), disruptive 2. After the run, 0
`axiom.cookbook.run` containers remain.

### Three totals (kept separate)

1. **Scenarios mapped: 21 / 21** (`scenario_catalog.json`). Titles are verbatim from the brief.
2. **Required generic Axiom identity contracts implemented (by scenario):** Done 13 (S01, S03, S04, S05, S06, S09,
   S11, S12, S13, S14, S15, S19, S20). *(S14 was single-tenant at this point; the cross-tenant part was added in the acceptance
   repair below.)* Partial 2: S02 (customer downstream continuation, D-C2, and standard customer
   login, D-O03, open) and S18 (password assurance only; MFA/passkeys deferred). Open decision with negative-only
   evidence 4 (S07, S08, S16, S17). Retained optional extension with Java evidence only 1 (S10:
   `ActionApprovalIT`, `ApprovedActionUseTimeIT`, `IssuanceCommitBoundaryIT`; no Python contract). Outside a generic
   IdP 1 (S21: Axiom has no emergency token-issuance profile; Policy Studio break-glass is separate).
3. **Applicable Python issuer contracts executed and passed:** 27 / 27 live examples and contracts (B01–B11 = 11,
   O01–O09 = 9 including O03 under `ciam/`, C01–C05 = 5, disruptive = 2) in the final run; plus 21 / 21 offline
   safety tests. S10 has no Python contract, S21 is not applicable, and S07/S08/S16/S17 prove refusal only.

### Simulated, not real

Customer code delivery (`LOCAL_DEMO`, simulated: proves the endpoint, not mailbox delivery). Receivers, the
intermediary's downstream API, the model-route gateway and the "protected actions" (`receiver.py` fixtures). No
Argus component, model, partner or external workload platform was used.

### Open decisions for the owner (nothing implemented)

D-O03 customer browser login · D-C2 customer downstream continuation (recommend: consent names the resources) ·
D-S07 workload proof / sender-constrained tokens · D-S08/S16 partner and cross-boundary issuer trust · D-S17 external
workload identity provider profile · D-S18/D-5 authenticators and assurance vocabulary · 0.6 machine operator
client · customer code delivery provider and recovery (owner-deferred) · whether operators may record or withdraw
customer consent (the unreachable `tenant_admin` branch on `/ciam/**`, checkpoint C).

**Not claimed:** Codex acceptance, production readiness, real Argus integration, full 21-scenario business support.
Nothing was committed, pushed, merged or deployed.


---

## Addendum — O02 browser check (2026-10-03)

**Added:** `examples/identity_scenarios/tests/test_o02_browser.py`; optional extra `browser = ["playwright==1.63.0"]`
and the `browser` marker in `pyproject.toml`; `.gitignore` adds `.venv/`, `artifacts/` and `evidence/`; a README
section. No server change. Playwright runs from a cookbook-local `.venv`. Its Chromium build 1243 was already cached
locally, so nothing was downloaded.

**What it does:** against the same disposable estate as the suite (`estate`/`ctx` fixtures; or an existing one via
`AXIOM_COOKBOOK_STATE`):

1. Headless Chromium opens `/oauth/authorize` (code, S256 PKCE, state, nonce) and lands on `/login`.
2. It fills the real CSRF-protected form and follows the redirect chain to a real `127.0.0.1` callback server. That
   server keeps the query in memory only, never logs it, and never renders it.
3. The test asserts that the state round-trips and that a code arrives with no error.
4. It redeems the code with `oauth.redeem_code`, then validates the access and ID tokens with the existing validator
   (sub = person, `identity_kind=workforce`, nonce).

**Browser-only denials:**
- A form auto-posted from another origin to `/login` without the CSRF token → **403**; the next authorization
  request still asks for a login, and no code reaches the callback.
- `/login` framed by another origin: the response arrived with `X-Frame-Options: DENY` and the browser did not
  render it.
- The session cookie `JSESSIONID` is HttpOnly (SameSite=Lax); `document.cookie` on Axiom's origin does not
  expose it.
- The password appears in none of the 8 request URLs.

Observed: the login form carries the CSRF field twice (the template adds one explicitly and Thymeleaf injects one).
This is harmless and was not changed.

**Results:**
- `.venv/bin/python -m pytest -q -rs tests/test_o02_browser.py tests/test_safety_offline.py` → **22 passed**
  (1 browser + 21 offline), 0 failed, 0 skipped, 2026-10-03T20:38:04Z, server-log token scan 0 matches
  (`evidence/browser-o02-run.json`).
- Without the extra, the test reports **skipped** (`install the 'browser' extra`). That means not run, not passed.

**Artifact guarantee (checked):**
- A successful run writes no `artifacts/` directory.
- A deliberately forced failure placed after the callback (a temporary probe file, deleted afterwards) wrote one
  screenshot. It showed only the callback page text. The pytest error read `code=[redacted]&state=[redacted]`, and 0
  code- or state-shaped values appeared in the output. The probe screenshot was deleted.
- The evidence files contain no JWT- or code-shaped values.

**Cleanup:**
- 0 `axiom.cookbook.run` containers after each run, and no Playwright profile directories left.
- Two run directories from interrupted runs earlier today (15:06 and 15:11, during the O06 diagnosis) were found
  and removed with `python -m axiom_cookbook.estate reap`.
- Records created by the test (application, client, role, membership, user) were disabled through the API by the
  `ctx` fixture.


---

## Acceptance repair — cleanup safety, reproducible evidence, handoff text (2026-10-03)

Checkout verified: `/Users/srirajkadimisetty/projects/axiom-changes`, branch `hardening/phase-0-baseline`, HEAD
`74e7e560`, 132 dirty entries before and after (all preserved). **No server source changed.** The Java evidence of
record remains the final clean run in checkpoint D: surefire 409/409, failsafe 159/159 (34 classes), 0 skipped.

**1. Cleanup safety (`axiom_cookbook/estate.py`).**
- **Before:** `reap` sent `killpg(pid, 9)` to any PID found in a prefix-matching directory's state file and deleted
  every `axiom-cookbook-*` directory and every cookbook-labelled container, including those of other live runs.
  `down` signalled the state's PID and deleted any prefix-named directory.
- **Now — runs carry ownership evidence:** each run writes a 0600 ownership marker (`run_id`, random 128-bit
  `owner_tag`, uid), saves its state immediately, and starts the server with `-Daxiom.cookbook.owner=<run>.<tag>`,
  recording its `ps` start time.
- **Signalling:** the server is signalled only when this process holds the child handle, or `ps` shows a process with
  the same uid, its own process group, the recorded start time and this run's tag.
- **Deleting directories:** a run directory is deleted only when it is a real directory directly in the temp dir,
  named for the run id, owned by the user with mode 0700, and its marker's run id and tag match the state.
- **Containers:** they are removed only when their label carries the run id.
- **Unproven items:** they are skipped and reported for manual review. `reap` leaves live runs to `down --state` and
  reports containers that no verified interrupted run owns. `down` keeps the directory if the server could not be
  proven stopped, and a restart refuses rather than starting a second server. The test fixture fails the session if
  its own `down` skips anything, and records the notes in evidence (`cleanup`).

**Offline tests (`tests/test_cleanup_safety.py`, 9).** These mock signals, deletion, Docker and `ps`, and never kill
a real process. They cover:
- a stale PID: not signalled, and the owned dead run is reaped;
- forged or reused PIDs — an unrelated command, a different start time, another uid, not the process-group leader,
  another run's tag (5 cases): never signalled, nothing deleted, reported;
- a running PID with an old state file lacking ownership evidence: not signalled;
- unrelated same-prefix entries — no marker, a mismatched tag, mode 0755, a symlink to outside data, a non-run name —
  plus a foreign-labelled container and a forged state pointing elsewhere: nothing deleted or removed;
- a valid live run: `reap` leaves it, while `down` sends exactly one SIGTERM, removes its container and deletes its
  directory.

**Mutation checks:** ignoring the PID checks → 5 tests fail; ignoring the directory checks → 1 fails. Sources restored
byte-identical.

**2. Reproducible evidence (`axiom_cookbook/evidence.py`, `tests/conftest.py`).**
- **Counts:** `evidence/last-run.json` records real counts from `pytest_runtest_logreport`
  (passed/failed/skipped/xfailed/xpassed/errors), the skipped test ids, the command and opt-ins.
- **Versions:** Python packages, Java, Docker, image IDs and the server jar's SHA-256.
- **`source_fingerprint`:** SHA-256 over sorted (path, length, content) of every file under
  `examples/identity_scenarios`, `server/src/main`, `server/pom.xml`, `platform-policy` and `platform-contract`,
  tracked or untracked. It excludes virtualenvs, caches, `evidence/`, `artifacts/`, logs, `target/`, egg-info and
  secret-like files (`.env*`, `env-*`, `estate.json`, `signing-key.json`, `server.env.json`, the ownership marker,
  `*.pem`, `*.key`, keystores).
- **Superseded:** the earlier `dirty_fingerprint` values in this ledger were hashes of `git status` only. Those
  remain as `dirty_status_hash` but are not the reproducibility evidence.
- **Offline tests (`tests/test_evidence_offline.py`, 2):** the fingerprint is deterministic; changing one file's
  content changes it; restoring the content restores it; a rename changes it; an untracked file counts; excluded and
  secret-like files neither change it nor are read into it.
- **Mutation:** hashing paths without content makes the regression fail.

**3. Handoff text.**
- **URLs** (consumer contract §3/§7, README, O02 browser test): passwords, client secrets and tokens never go in
  URLs, and logout uses a POST form. The authorization code does arrive in the registered callback URL, as the code
  flow requires. Clients must not log, cache or retain that URL (no access logs, analytics, history or `Referer`) and
  should redeem the code at once. The README's cleanup and evidence descriptions were updated to match.
- **S14:** C02 now provisions a second tenant through `POST /admin/tenants` (root platform admin), with its own
  customer-facing client, workload, customer (simulated local-demo verification delivery) and grant. Run concurrently
  on 8 threads:
  - 60 legitimate exchanges across both tenants (two people, three customers): 0 mix-ups of subject, grant
    (`delegation_id`), actor or `tenant_id`;
  - 10 cross-tenant attempts (each tenant's workload presenting the other's customer token): all 400;
  - cross-tenant introspection: only `{"active": false}` in both directions;
  - tenant A's revocations leave tenant B unaffected.

  Axiom clients are tenant-scoped, so "one workload client in two tenants" cannot exist. The catalog marks S14 Done
  with that qualification. The literal form is not applicable, not proven. The second tenant itself is a residual
  until estate teardown.

**Runs:**

```bash
.venv/bin/python -m pytest -q tests/test_cleanup_safety.py tests/test_evidence_offline.py tests/test_safety_offline.py
#   32 passed (9 + 2 + 21), offline
AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1 .venv/bin/python -m pytest -q -rs tests/     # .venv has the 'browser' extra
#   60 collected: passed 60, failed 0, errors 0, skipped 0, xfail 0 — 346 s, finished 2026-10-03T21:01:17Z
```

Evidence: `evidence/full-run-repair.json`.
- **Composition:** 28 live outcomes (A 8, B 8, C 4, D 5, disruptive 2, O02 browser 1) with 104 positive and 150
  denial assertions, plus 32 offline tests.
- **Source fingerprint:** `7001a0ff938ec2b04c205bfb1547a6701663bc9960709a296d0fbc280e166de9` over 567 files,
  recomputed afterwards with an identical result.
- **Dependencies:** Python 3.12.7, requests 2.34.2, PyJWT 2.15.1, cryptography 50.0.2, pytest 8.4.2,
  Playwright 1.63.0, Java 25.0.3, Docker 29.8.0. Image IDs postgres:16 `1a6ab3f5…`, redis:7-alpine `858f009f…`,
  cerbos 0.53.0 `c3fe6420…`. Server jar SHA-256 `a82d3b37…`.
- **Server-log scan:** 0 token-shaped matches.
- **Cleanup:** `estate_down_skipped: []`. Afterwards there were 0 `axiom.cookbook.run` containers, 0
  `axiom-cookbook-*` run directories and no `artifacts/` directory. Evidence files contain no JWT- or code-shaped
  values.

**Remaining limitations:**
- `ps`-based ownership is macOS/Linux; elsewhere processes are always "unproven" and skipped.
- Runs created before this repair have no marker, so `reap` reports them instead of removing them; remove them
  manually after review.
- The cross-tenant tenant is left until estate teardown.
- `.venv` package versions differ from the system interpreter's: the evidence records the interpreter actually used.
- Not claimed: Codex acceptance, production readiness, real Argus integration. Nothing was committed, pushed,
  merged or deployed.
