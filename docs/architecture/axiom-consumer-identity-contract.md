# Axiom consumer identity contract

**Status: draft for review. Not accepted.** Codex owns acceptance. This contract describes what an integrating
consumer (a gateway, broker, API, tool server, scheduler or customer-facing application) can rely on from Axiom as
implemented in `axiom-changes` on `hardening/phase-0-baseline`, and what the consumer must enforce itself. It needs no
Argus installation. Executable examples: `examples/identity_scenarios/` (see its README). Evidence:
`docs/operations/axiom-integration-scenario-ledger.md`.

Axiom is a consumer-neutral identity provider. It knows tenants, people (workforce), customers (CIAM), applications,
OAuth clients, workload identities, exchange intermediaries, exchange edges, sessions and grants. It does **not** know
agents, use cases, runs, model routes or business actions. Some API paths carry historical names
(`/ciam/agent-workloads`, `/api/v1/workload`); the records behind them are generic workloads.

## 1. Three identities that stay distinct

| Identity | Where it appears | Meaning |
|---|---|---|
| Authenticated client | `client_id` claim; HTTP Basic on `/oauth/token` | The OAuth client that made *this* token request. |
| Represented person or customer | `sub` (+ `identity_kind` = `workforce` / `customer` / `workload`) | Whose authority the token carries. For workload-only tokens `sub` = the workload's client id. |
| Acting workload | `act` = `{sub: workloadRef, workload_id, client_id}` | The workload acting for `sub`. Axiom records it from the authenticated exchange; callers cannot supply it (`actor_token` is refused). |

Registration alone grants nothing: a client, workload, intermediary or customer can obtain delegated authority only
through an explicit membership, edge (route), consent grant or standing grant, re-checked at every exchange and at
introspection.

## 2. Provisioning (operator APIs, `axiom-api` audience tokens)

Operator tokens come only from the browser authorization-code flow of the public client `axiom-admin` (S256 PKCE,
CSRF-protected login form). Password-to-token login (`/auth/login`) and impersonation can be switched off
(`iam.auth.legacy-password-login.enabled`, `iam.auth.impersonation.enabled`) and are off in the cookbook profile.
There is no machine operator client yet (story 0.6).

| Purpose | Call | Notes |
|---|---|---|
| Workforce person | `POST /users`, `PUT /users/{id}`, `DELETE /users/{id}` (disable) | Tenant from the operator token. |
| Tenant role (platform admin only) | `POST /users/{id}/roles` | `tenant_admin` is the provisioning role. |
| Application | `POST /admin/tenants/{t}/applications` `{applicationKey, displayName, audience}` | `audience` is the resource indicator. |
| Client | `POST …/applications/{a}/clients` `{clientId, clientType: PUBLIC_BROWSER\|CONFIDENTIAL_SERVICE, redirectUris, scopes}` | A confidential secret is returned once (`serviceSecret`). Insecure redirects refused. |
| Application access (workforce) | `…/access/roles` `{roleKey, permissions, permissionEffects}`, `…/access/memberships`, `…/memberships/{m}/roles` | Teams' default roles grant nothing by themselves. |
| Workload | `POST /admin/tenants/{t}/ciam/agent-workloads` `{workloadRef, name, oauthClientId}`; `…/{w}/suspend\|reactivate\|retire` | Retire is terminal. |
| Exchange intermediary | `POST /admin/tenants/{t}/agent-exchange/brokers` `{oauthClientId, gatewayAudience, scopes}` | |
| Exchange edge | `POST /admin/tenants/{t}/agent-exchange/routes` `{sourceWorkloadId, destinationType: GATEWAY\|RESOURCE\|AGENT, audience, scopes, purpose, expiresAt, destinationWorkloadId?}` | No edge = no hop. |
| Customer (administrator) | `POST /admin/tenants/{t}/ciam/customers` `{email, displayName, initialPassword}` | **New.** Created `PENDING_VERIFICATION`, `provisioningSource=ADMINISTRATOR`, `emailVerifiedAt=null`; no code returned. |
| Customer (self) | `POST /ciam/tenants/{t}/customers/registrations` | `provisioningSource=SELF_REGISTRATION`. Needs a code channel. |
| Consent purpose | `POST /admin/tenants/{t}/ciam/agent-workloads/{w}/purposes` | Administrative setup, not consent. |
| Credential lifecycle | client secret rotation (two-person), signing keys (platform admin only) | Old secret valid for the configured overlap. |

## 3. Token requests

All at `POST /oauth/token`, form-encoded, confidential clients authenticate with `client_secret_basic`.
Credentials (passwords, client secrets) and tokens (access, ID, renewal handles) are never put in URLs. The one exception the protocol requires is the authorization code: it arrives as a query parameter of the registered redirect URI (with `state`). It is single-use, short-lived and useless without the PKCE verifier. A client must still treat that callback URL as secret: do not log it (access logs, analytics, error reports), do not keep it in browser history or a `Referer`, redeem the code at once and drop the URL. Logout uses a POST form so the ID token never appears in a URL.

| Flow | Parameters | Result |
|---|---|---|
| Person login | `/oauth/authorize` (code, S256 PKCE, `state`, `nonce`) → `grant_type=authorization_code` | Access token (`aud` = the application audience, `sid`, `acr`, `amr`, `auth_time`) + ID token. No refresh token. |
| Workload | `grant_type=client_credentials`, `scope` | `sub=client_id=workload client`, `identity_kind=workload`, no `act`, lifetime ≤ configured TTL (default 5 min). |
| Exchange (RFC 8693, Axiom profile) | `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, `audience`, `scope`, optional `delegation_purpose` | One hop per call; lifetime ≤ 5 min and ≤ subject's `exp`; scope ≤ subject ∩ edge ∩ client. `actor_token` → `invalid_request`. |
| Customer sign-in (Axiom-specific) | `POST /ciam/tenants/{t}/customers/tokens` JSON `{email, password, clientId, scopes}` | Customer token, `aud=axiom-token-exchange`, no ID token. **Not an OIDC login** (open decision D-O03). |
| Standing grant (Axiom extension) | `grant_type=urn:openwolf:params:oauth:grant-type:standing-grant`, `standing_grant`, `renewal_handle` | Short access token + a new single-use handle. `refresh_token` is not supported. |

Token-use values in exchanged tokens (`token_use`): `exchange_subject` (may be exchanged once more by its audience),
`gateway_authorization` (for an intermediary), `delegated_access` (terminal, for a resource). `authority_profile`
names the rule that issued it (`workforce`, `workload_continuation`, `gateway_backend`, `ciam_customer`, extensions).

## 4. Validating a token (every receiver)

1. Fetch `/.well-known/oauth-authorization-server`; require `issuer` equal to the configured issuer; fetch `jwks_uri`
   from the same origin.
2. Verify RS256 signature by `kid`, header `typ=at+jwt`, `iss`, `aud` = exactly your audience, `exp`/`iat`.
3. Check `scope` covers the action. `scope` may be a space-separated string (login tokens) or an array (exchanged
   tokens); accept both.
4. Read `sub`, `identity_kind`, `act`, `client_id`, `tenant_id` and decide the business action yourself.
5. Decide per route whether offline validation is enough. Offline validation cannot see logout, revocation,
   withdrawal, suspension or disabled clients until `exp` (measured residual window up to the token lifetime; C01).
   For those, call `POST /oauth/introspect` with your own confidential client and fail closed on any error.

Introspection discloses nothing across tenants (`{"active": false}`). Workload tokens are active only while the
client and workload are active.

## 5. Status and revocation

| Event | Effect (online) |
|---|---|
| OIDC logout (`POST /connect/logout`, form `id_token_hint`) | Session ended; its tokens and tokens derived by exchange are inactive. |
| Session revocation (admin or self) | Same. Independent sessions unaffected. |
| RFC 7009 revocation, code replay | The token's session ends. |
| Client disabled / secret revoked / application disabled | Sessions issued to the client end; client tokens inactive. |
| Workload suspended / retired; edge or intermediary revoked | Exchange and introspection refuse; reactivation restores, retirement is terminal. |
| Customer suspended | `token_version` bumps: customer tokens and grants unusable. |
| Consent grant withdrawn or expired | Delegated tokens with its `delegation_id` inactive; no new issuance. Other grants unaffected. |
| Standing grant withdrawn, expired, or a spent handle reused | Renewal refused; reuse withdraws the grant. |

## 6. Customers (CIAM)

Customers are a separate population: separate records and endpoints, customer tokens are refused by workforce and
administration APIs, workforce credentials do not sign in as customers and customers cannot use the workforce login.
Axiom has no customer roles, groups or memberships: customer access is the customer-facing client's scope ceiling;
per-customer business entitlement is the resource's decision. `emailVerifiedAt` is the only verification evidence;
`provisioningSource` records how the identity was created and implies nothing about verification.

Consent is recorded only by the customer (the `/ciam/**` API accepts customer tokens only); operators set up
workloads, scopes and purposes, inspect grants, and can suspend the customer or revoke the workload, but cannot
create or withdraw a customer's consent. A delegated customer token is terminal (D-C2).

No delivery provider ships with Axiom. Production deployments must supply one; without it, registration and
verification are refused (503). The cookbook estate uses Axiom's loopback-only local-demo aid, labelled *simulated
delivery*. Account recovery is deferred.

## 7. What the consumer must enforce

- Business authorization (which order, which amount, which customer record), approval UIs, business canonicalization.
- Freshness: when to introspect; how long to cache; fail closed.
- Proof-of-possession, if a route needs it (Axiom issues bearer tokens only).
- Per-subject isolation of caches, memory and results (key by `sub` + `sid`/`delegation_id`).
- Stopping in-flight work after revocation; Axiom only stops issuing and reports inactive.
- Required assurance per action (`acr`, `auth_time` age); anything above the password level is unavailable today.
- Never forwarding a token to another audience; exchange per hop.
- Callback URLs carrying an authorization code are not logged, cached or retained; the code is redeemed immediately.

## 8. Not supported or open (decisions for the owner)

| ID | Gap |
|---|---|
| D-O03 | Standard customer browser login (authorization code + PKCE, ID token, session) — endpoint, population selection, claims. |
| D-C2 | Customer downstream continuation: whether consent may extend via operator-registered edges to resources the customer did not name, or must name them. Today customer delegated tokens are terminal. |
| D-S07 | Workload proof profile: `private_key_jwt`, mTLS client auth, sender-constrained tokens (DPoP or mTLS-bound). |
| D-S08/S16 | Cross-boundary issuer/partner trust (RFC 7523 assertions or token exchange from partner issuers), mapping and revocation. |
| D-S17 | External workload identity provider profile for the existing workload-federation client assertion framework. |
| D-S18 / D-5 | Authenticators beyond password (MFA, passkeys) and an assurance vocabulary. Password-level `acr`/`amr`/`auth_time` is preserved through exchange today. |
| 0.6 | Machine operator client for provisioning. |
| — | Customer code delivery provider and account recovery (owner-deferred). |
