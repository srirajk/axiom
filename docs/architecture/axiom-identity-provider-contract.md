# Axiom identity provider contract (IDP baseline profile)

**Status: draft for Codex review. Not accepted.** This is the integration contract for Axiom as an optional, consumer-neutral
identity provider, written against the *Identity provider integration checklist* (IDP-01–15). It describes what the
isolated `axiom-changes` build on `hardening/phase-0-baseline` does, as verified by the tests named in
`docs/operations/axiom-integration-capability-ledger.md`. It does not certify a deployment, a consumer's enforcement, or
production readiness.

Machine-readable profile: `examples/identity_scenarios/provider-profile.example.json`. Runnable examples:
`examples/identity_scenarios/idp/`.

## 1. What is portable and what is Axiom-specific

* **Portable runtime contract** (what an integrating product may depend on): OIDC Discovery 1.0 / RFC 8414 metadata;
  JWKS; authorization code with S256 PKCE, state and nonce (OIDC Core, RFC 7636); refresh tokens (RFC 6749 §6) for
  confidential web clients with `offline_access`; client credentials with `client_secret_basic` or `private_key_jwt`
  (RFC 7523 §2.2); token exchange (RFC 8693) with `audience` or `resource`; introspection (RFC 7662); revocation
  (RFC 7009); RP-initiated logout (OIDC RP-Initiated Logout 1.0, form POST). Claims a consumer may rely on: `iss`,
  `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `scope`, `act` (exchange), `auth_time`/`acr`/`amr` (interactive),
  and the ID token's `nonce`, `email`, `email_verified`, `name`.
* **Provider-specific setup adapter** (Axiom management APIs; another provider will differ): application and client
  registration, access (memberships/roles), workload registration and exchange edges, customer provisioning, the
  two-person identity-control flow, the audit API, customer consent self-service.
* **Axiom-specific claims** (present, but not required by the portable contract and not to be depended on):
  `tenant_id`, `identity_kind`, `sid`, `subject_sid`, `token_use`, `authority_profile`, `authority_id`, `roles`,
  `permissions`, `entitlement_revision`, `token_version`, `delegation_id`, `purpose`, `ctx*`.
* **Optional Axiom extensions** (retained, not part of the baseline): the standing-grant and approved-action grants
  (`urn:openwolf:params:oauth:grant-type:*`), the CIAM consent-grant delegation profile, invocation contexts, the
  JSON customer sign-in endpoint (`POST /ciam/tenants/{t}/customers/tokens`, used for customer self-service).

## 2. Endpoints (from live discovery)

| Purpose | Endpoint |
|---|---|
| Discovery | `{issuer}/.well-known/openid-configuration`, `{issuer}/.well-known/oauth-authorization-server` |
| Keys | `{issuer}/oauth2/jwks` (RS256) |
| Authorization | `{issuer}/oauth/authorize` (`response_type=code` only) |
| Token | `{issuer}/oauth/token` |
| Introspection | `{issuer}/oauth/introspect` (`client_secret_basic`, `private_key_jwt`) |
| Revocation | `{issuer}/oauth/revoke` (`client_secret_basic`, `private_key_jwt`) |
| Logout | `{issuer}/connect/logout` (form POST with `id_token_hint`; GET is also accepted by the framework but puts the ID token in a URL) |
| UserInfo | `{issuer}/oauth/userinfo` |
| Sign-in pages | workforce `{issuer}/login`; customers `{issuer}/login/customer` (chosen by the client's population) |

Discovery lists exactly: grants `authorization_code`, `refresh_token`, `client_credentials`, token exchange, and two
Axiom-namespaced extension grants; client authentication `client_secret_basic`, `private_key_jwt`, `none`; assertion
algorithms `RS256`, `ES256`; PKCE `S256`. No DPoP, mTLS, device or PAR metadata is published, because none is
enforced. `scopes_supported` lists the scopes a client of this deployment can be registered for: `openid`, `profile`,
`email`, `offline_access`, `roles` and the deployment-approved business scopes; which of them a given client may
request is its registration. UserInfo answers for any session-backed access token of this issuer whose authorization
includes `openid` (workforce and customer application tokens alike); software tokens get 401.

## 3. Client postures

| Type | Who signs in | Authentication | Grants | Notes |
|---|---|---|---|---|
| `PUBLIC_BROWSER` | workforce or customer (`population`) | `none` + S256 PKCE | authorization code | never receives refresh tokens |
| `CONFIDENTIAL_WEB` | workforce or customer | `client_secret_basic` + S256 PKCE | authorization code, refresh token | refresh only if `offline_access` is requested and granted |
| `CONFIDENTIAL_SERVICE` | nobody (software acts as itself) | `client_secret_basic` or `private_key_jwt` | client credentials, token exchange | may be registered as a workload; keys are public JWKs only |

Registration settings: exact `redirectUris` (https, or http on loopback; no fragments), `scopes` (OIDC scopes, the
deployment's approved business scopes, `offline_access` for confidential web clients), `population`,
`requireConsent`, `accessTokenTtlSeconds` (≥ 60, ≤ deployment maximum), `refreshTokenTtlSeconds`,
`tokenEndpointAuthMethod`, `jwks`. A secret is generated and returned once. Unknown or unsupported combinations are
refused with 400 (they were silently ignored before the IDP baseline).

## 4. Capability behaviour

**IDP-02 Sign-in.** Workforce and customers use the same standard flow through different clients and pages. A
browser session of one population never obtains a code for the other population's client: it is cleared and sent to
the right login page. Customers must be ACTIVE (verified); suspension or credential recovery stops issuance and refresh.

**IDP-03 Software.** `sub` = `client_id` = the client; no person, no `act`. `private_key_jwt` assertions: `iss` = `sub` =
client id, `aud` = the token endpoint (or issuer), lifetime ≤ 5 min, `jti` required and single use (Redis-backed; if
Redis is unavailable the assertion is refused).

**IDP-04 Tokens.** One audience per access token (the application, or the exchange target). Lifetimes: interactive
default 1 h (configurable per deployment and per client), client credentials 5 min, exchange ≤ 5 min and never beyond
the subject token. **Scope policy:** a workforce person receives a business scope only if they hold the matching
application permission at issuance (re-evaluated on refresh); the token response reports the issued scope. Customers
receive the scopes the client offers and, if consent is required, those they approved.

**IDP-05 Exchange.** `subject_token` (an access token), `audience` or `resource` (exactly one), `scope`; the exchanging
client authenticates; `actor_token` is refused. Workforce and customer tokens can be redeemed only by a workload of the
same application; further hops follow explicitly registered edges; scope only narrows; resource tokens are terminal.
`sub` is preserved, `act` names the acting workload, `client_id` names the exchanging client. Registration alone
grants nothing.

**IDP-06 Refresh.** Rotation on every use; a spent refresh token presented again withdraws the whole family (current
refresh and access tokens, session); concurrent redemptions: exactly one succeeds (others get `invalid_grant`
immediately; a later retry with the spent token withdraws the family). Wrong client, access/ID token as renewal input,
logout, revocation, disable, customer suspension and customer consent withdrawal all stop renewal. The family's
absolute lifetime is the refresh TTL from sign-in.

**IDP-07 Status.** Authenticated callers of the same tenant only; other tenants and unknown/expired/revoked tokens get
exactly `{"active": false}`; unauthenticated callers get 401. Software tokens have no session; their status is the
client's (and workload's) live status. No cache inside Axiom. Redis or PostgreSQL unavailable → never active.

**IDP-08 Revocation and logout.** Revoking an access token or a refresh token ends that login (session, refresh family,
exchanged descendants) for online checks. RP-initiated logout ends the named login and the browser session; other
logins of the same person continue. A cross-origin form POST to the logout endpoint is accepted (it is a navigation,
not a CORS request). Offline validation keeps accepting already-issued JWTs until `exp`.

**IDP-09 Lifecycle.** Signing keys rotate with a verification overlap (platform administrator only). Client secrets
rotate and `private_key_jwt` keys are replaced through the two-person identity-control flow (key overlap by
registering old and new keys, then only the new one). Disable/retire stop issuance and outstanding-token status at
once. Restart preserves keys, sessions and withdrawals. Audit: `GET /admin/audit` (tenant-scoped, redacted).

**IDP-10 Isolation.** Identity is (`iss`, `sub`); one software client acting for many subjects never mixes them;
revocation is selective; tenants and populations are separate; a client disable cannot be outrun by racing issuance.

**IDP-11 Directory.** SCIM 2.0 (`/scim/v2`, source bearer, ETag/`If-Match`) for workforce users and groups; management
API for users, application memberships/roles (provider-specific; OIDC does not standardize roles); customers are
provisioned PENDING and unverified and become ACTIVE only through the customer's own verification.

**IDP-12 Clients and consent.** See section 3. Consent is shown on Axiom's own consent page (`/oauth2/consent`, all
assets self-hosted; standard OAuth consent semantics, form posting `client_id`, `state` and approved `scope` values to
the authorization endpoint), stored durably; customers list and withdraw consents through Axiom's self-service API, which also ends their sessions
with that client. Operators cannot withdraw a customer's consent (they end sessions instead).

## 5. Conditional profiles

| ID | State | What a consumer must not assume |
|---|---|---|
| IDP-13 sender constraint (DPoP / mTLS) | not selected | tokens are bearer tokens; `private_key_jwt` binds nothing |
| IDP-14 external assertions | not selected | no foreign issuer, partner or platform assertion is accepted |
| IDP-15 assurance | partial, profile not selected | only password-level `acr`/`amr`/`auth_time`; no `acr_values`/`max_age` enforcement, no MFA/passkeys (owner-deferred) |

## 6. Security policies (stated choices)

* Delegation, not impersonation: the actor is the authenticated workload; a caller cannot name an actor; nested actor
  history is not authority.
* Withdrawal is online: introspection and exchange see revocation, logout, disable, suspension and consent withdrawal
  at once; offline JWT validation cannot, and the residual window is up to the token's remaining lifetime.
* Token types are not interchangeable: an access or ID token is never accepted as a refresh token or code.
* Passwords are entered only on Axiom's own pages; the resource-owner password grant does not exist; the legacy
  password-to-token endpoints and impersonation are **off by default** and must be enabled explicitly
  (`iam.auth.legacy-password-login.enabled`, `iam.auth.impersonation.enabled`), which logs a warning.

## 7. Receiver obligations (not enforced by Axiom)

Validate signature, `iss`, `aud`, `exp` (small leeway), `typ=at+jwt` and `scope` on every request; reject ID tokens;
decide resource-level authorization; use introspection (fail closed on error) where withdrawal must take effect before
`exp`; key caches by (`iss`, `sub`) plus the authority used; enforce proof-of-possession yourself if needed; store
refresh tokens server-side and serialize renewals.

## 8. Integrator prerequisites template

| Item | Standard runtime request | Provider-specific setup (Axiom) |
|---|---|---|
| Issuer and discovery URL | configuration | — |
| Sign-in client id, redirect URIs, population | authorization request | client registration |
| Confidential web client secret (reference) | token request (Basic) | returned once at registration |
| Service client secret or public JWK + private key (reference) | client credentials / assertion | registration; rotation is two-person |
| Resource audience and scope vocabulary | token validation | application audience; approved business scopes |
| Exchange relationships | token exchange | workload registration and explicit edges |
| Introspection client (reference) | introspection | a confidential client of the same tenant |
| Post-logout redirect URI | logout | client registration |
| People / customers / groups | — | SCIM 2.0 or management API; customer verification delivery provider |

## 9. Open items

See the ledger: customer verification/recovery delivery (owner-deferred); native MFA/passkeys (deferred); IDP-13/14
profile selection; IDP-15 assurance profile; the missing operator-authentication contract (section 10).

## 10. Missing contract: operator authentication for provisioning scripts

Axiom's administration API (`/admin/**`, `/users`, `/roles`, `/teams`) accepts only `axiom-api` tokens from the legacy
password endpoint or from the platform client `axiom-admin` (`AxiomApiJwtValidator`). `axiom-admin` is a public browser
client with one configured redirect URI (the admin UI callback), so a script cannot complete its flow; client-credentials
tokens are workload identities without operator roles and are refused. Therefore `scripts/configure_axiom.py`,
`scripts/publish-ciam-demo.py` and the `scripts/verify-*.py` utilities still require the legacy endpoint by explicit
opt-in. Migrating them needs one of these contracts (an owner/Codex security decision; not designed or implemented here):

1. **Interactive CLI sign-in (RFC 8252):** a platform-owned public client accepted by `AxiomApiJwtValidator`, with
   loopback redirect URIs and S256 PKCE; the operator signs in on Axiom's page; the token carries that person's roles.
2. **Non-interactive operator client:** a platform-owned confidential client (preferably `private_key_jwt`) whose token
   carries an explicit, tenant-bound operator grant (never workload identity), an audit identity distinct from people,
   per-route method gates matching each script's needs, short lifetime, two-person credential rotation and revocation.

Routes the scripts need (from source): applications, clients, access roles/memberships, `ciam/agent-workloads`,
`ciam/customers` (+ suspend/reactivate), `ciam/events`, `agent-exchange/brokers|routes` (+ revoke), `identity-control-
requests`, `/users`, `/teams`, `/admin/tenants`, `/admin/audit/export`. `configure_axiom.py` also manipulates Kubernetes
Secrets, which is outside any Axiom authentication contract.

## 11. Business-scope vocabulary (deployment baseline and tenant catalog)

* **Baseline:** `iam.oauth2.approved-business-scopes` (Helm `config.approvedBusinessScopes`), approved in every tenant
  and published in `scopes_supported`.
* **Tenant catalog:** `POST`/`GET /admin/tenants/{t}/business-scopes` (Axiom management API; table
  `tenant_business_scopes`, migration V41). Approved only in that tenant, read live (usable at once), never published
  in discovery. Every place Axiom validates a business scope checks *baseline ∪ that tenant's catalog*: client
  registration, exchange brokers and routes, consent purposes, customer delegation and customer sign-in scopes,
  standing and approved-action grants, and issuance-time entitlement narrowing (a person receives a business scope,
  baseline or catalog, only with the matching application permission).
* **Vocabulary only:** registering a name grants no authority. Standard protocol scopes (`openid`, `profile`, `email`,
  `offline_access`, `roles`, …) and `axiom`-prefixed names cannot be registered.
* **Deactivation semantics (decided, not implemented):** there is no delete or disable endpoint. When added, deactivation
  should only stop *new* approvals (client registrations, routes, purposes, grants) and remain visible as an audited
  state change; it must not silently rewrite existing client registrations or revoke issued tokens. Withdrawing
  authority stays with the existing mechanisms (disable the client, revoke the route or grant, end sessions), and
  access tokens already issued remain valid offline until `exp`. Re-registering a deactivated name would need an
  explicit reactivation, not a duplicate row.
