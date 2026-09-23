# Axiom CIAM and Agent On-Behalf-Of Contract

Status: greenfield product contract

## Argus exchange-profile amendment

RFC 8693 is exposed through one protocol endpoint, but Axiom resolves authority through three
separate, fail-closed profiles. Request parameters never select a profile and never create authority.
The authenticated client, verified subject token, and persisted server-owned records select exactly
one profile.

| Profile | Subject authority | Authenticated client | Permitted result |
|---|---|---|---|
| Direct CIAM customer delegation | Active customer consent grant | The exact registered Agent workload bound to the grant | Existing short-lived resource token for the consented audience. Transitive use remains prohibited. |
| Workforce or workload continuation | Active application membership and role grant for a workforce subject, or active workload and workload route for a workload subject | The exact destination Agent workload | A short-lived Argus Gateway audience token. The caller must be the intended recipient of a continued Agent token. |
| Trusted Argus Gateway backend exchange | Active workload route plus active trusted-broker registration | The registered Argus Gateway broker client | A short-lived token for one exact destination Agent or first-party resource. The business actor in `act.sub` is preserved and the Gateway is never inserted as that actor. |

The profiles share these invariants:

- `sub` is the original workforce human, customer, or originating workload.
- `act.sub` is the current acting Agent workload when delegated execution is present.
- `aud` contains exactly one receiving resource.
- scopes and lifetime can only narrow at every exchange.
- tenant, current workload, destination, scopes, and authority identifier come from active
  server-owned records.
- a destination Agent token can be exchanged only by the workload whose registered receiving
  audience matches that token. A sibling workload cannot replay it.
- an Argus Gateway token can be exchanged only by the registered trusted Gateway broker.
- an Agent-to-Agent route never authorizes an Agent-to-MCP route, and vice versa.

The workload-route model is independent of the OAuth application's primary audience. One workload
identity remains bound to one confidential client, while reviewed routes can authorize multiple
destination audiences. Cloud provider model and runtime credentials are outside this model. Bifrost
uses provider service credentials, and AWS, Azure, or Google runtime identities remain native
workload identities rather than Axiom destination credentials.

## Purpose

Axiom provides customer identity and delegated authorization for an agent that acts for a customer.
The issued credential preserves both principals:

- `sub` identifies the customer whose authority is being exercised.
- `act.sub` identifies the registered agent workload exercising that authority.

This is OAuth 2.0 Token Exchange as defined by RFC 8693. It is not Axiom's administrative
`/auth/impersonate` feature. Impersonation remains a separate, demo-only administrative capability
and is never accepted as customer consent or agent delegation.

## Product boundary

This slice provides:

- customer registration, verification, authentication and credential recovery;
- customer-only subject-token issuance with no workforce or platform authority;
- registered agent workload identities;
- explicit, purpose-bound customer delegation grants;
- RFC 8693 token exchange at the standard token endpoint;
- audience-bound and scope-narrowed delegated access tokens;
- immediate delegation or workload revocation;
- tenant-scoped lifecycle and exchange audit evidence.
- customer self-service and administrator UI surfaces for the full lifecycle.

This slice does not move AI assurance into Axiom. Argus Assured decides whether an exact Agent Use is
contextually cleared. Argus Gateway validates Axiom identity and delegation, obtains the current Argus
Assured decision, and enforces both.

## Actors

| Actor | Responsibility |
|---|---|
| Customer | Registers, verifies, authenticates, grants consent, and revokes consent. |
| Agent workload | Authenticates as a confidential OAuth client and requests only delegated authority. |
| Axiom | Authenticates both principals, resolves active consent, issues delegated tokens, revokes authority, and audits. |
| Resource API | Validates signature, issuer, audience, lifetime, customer subject, actor identity, scopes and delegation identity. |
| Argus Assured | Supplies contextual Agent Use clearance. It does not authenticate the customer or calculate identity authority. |
| Argus Gateway | Requires both valid delegated identity and applicable assurance before dispatch. |

## Customer lifecycle API

Anonymous bootstrap routes:

```text
POST /ciam/tenants/{tenantId}/customers/registrations
POST /ciam/tenants/{tenantId}/customers/verifications
POST /ciam/tenants/{tenantId}/customers/recovery-challenges
POST /ciam/tenants/{tenantId}/customers/recoveries
```

Authenticated customer or authorized tenant-administrator routes:

```text
GET  /ciam/tenants/{tenantId}/customers/{customerId}
POST /ciam/tenants/{tenantId}/customers/{customerId}/delegation-grants
GET  /ciam/tenants/{tenantId}/customers/{customerId}/delegation-grants
POST /ciam/tenants/{tenantId}/customers/{customerId}/delegation-grants/{grantId}/revoke
```

Recovery-challenge responses are enumeration resistant. Local development may return a
`LOCAL_DEMO` verification or recovery action. Production delivery is an adapter boundary and must
never expose a credential-recovery secret in an API response.

## Agent workload administration API

```text
POST /admin/tenants/{tenantId}/ciam/agent-workloads
GET  /admin/tenants/{tenantId}/ciam/agent-workloads
POST /admin/tenants/{tenantId}/ciam/agent-workloads/{workloadId}/revoke
```

An agent workload binds a stable workload reference to one confidential OAuth client. A workload
revocation is terminal and immediately prevents new exchanges. It does not rewrite historical audit
records.

## Argus exchange administration API

Trusted Gateway brokers and reviewed continuation routes are product-owned authority records. They
are created by an authorized tenant administrator and are never accepted as token-request claims.

```text
POST /admin/tenants/{tenantId}/agent-exchange/brokers
GET  /admin/tenants/{tenantId}/agent-exchange/brokers
POST /admin/tenants/{tenantId}/agent-exchange/brokers/{brokerId}/revoke

POST /admin/tenants/{tenantId}/agent-exchange/routes
GET  /admin/tenants/{tenantId}/agent-exchange/routes
POST /admin/tenants/{tenantId}/agent-exchange/routes/{routeId}/revoke
```

A route has one source Agent workload and exactly one destination type: `AGENT`, `GATEWAY`, or
`RESOURCE`. It pins the destination audience, a nonempty scope ceiling, a bounded purpose, and an
expiry. An Agent destination additionally pins the destination workload identity. A Gateway route
must resolve to an active trusted-broker registration, and a resource route must resolve to an active
tenant application audience. Route or broker revocation immediately prevents new exchanges.

## Customer authentication and subject token

Customer authentication is a separate security domain from workforce authentication. A workforce
OIDC token, administrator token or impersonation token is never a valid CIAM subject token.

After verification, the customer authenticates through Axiom's CIAM browser flow and receives a
short-lived access token with at least:

```json
{
  "sub": "<customer UUID>",
  "identity_kind": "customer",
  "tenant_id": "<tenant id>",
  "client_id": "<registered CIAM browser client>",
  "sid": "<customer session id>",
  "scope": "cards:incident.read cards:freeze.propose"
}
```

The customer token contains no workforce roles, platform-administrator role, workforce permissions,
admin domains or impersonation marker. Token exchange rejects a subject token unless
`identity_kind=customer`, `sub` resolves to the same active verified customer that owns the exact
delegation grant, and the customer session is active.

Password recovery invalidates existing customer sessions and subject tokens for new exchange.
Suspending or closing a customer immediately prevents new authentication and new exchange. Historic
delegated-token and audit records remain immutable.

## Delegation grant

A customer delegation grant contains:

```json
{
  "agentWorkloadId": "<registered workload id>",
  "audience": "cards-api",
  "scopes": ["cards:incident.read", "cards:freeze.propose"],
  "purpose": "Resolve the customer's reported lost card",
  "expiresAt": "<bounded future instant>"
}
```

The grant is valid only when all of the following remain true:

- the tenant is active;
- the customer is active and verified;
- the workload is active;
- the grant is active and unexpired;
- audience exactly matches;
- requested scopes are a nonempty subset of the customer public client's approved scopes, the
  Agent confidential client's approved scopes and the granted scopes;
- the authenticated actor matches the workload bound to the grant;
- the subject token identifies the customer who owns the grant.

No implicit or wildcard delegation exists. The direct CIAM profile remains non-transitive. A deeper
Agent chain is possible only through the explicit continuation and trusted Gateway profiles above,
with one active server-owned route checked at every hop.

## RFC 8693 exchange

The workload sends a form-encoded request to Axiom's standard token endpoint:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<customer access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_token_type=urn:ietf:params:oauth:token-type:access_token
audience=cards-api
scope=cards:incident.read cards:freeze.propose
```

The agent workload authenticates the token request as its bound confidential OAuth client. That
authenticated client is the RFC 8693 actor in this deliberately bounded profile, so a separate
`actor_token` is rejected. This avoids accepting an actor asserted inside request data while still
preserving the customer subject and acting workload as separate principals.

Axiom resolves exactly one active delegation from the authenticated customer, authenticated Agent
client, target audience and requested scope subset. Zero matches and multiple matches both fail.
Purpose and delegation identity come only from that server-owned grant and are rejected as request
parameters, so request data cannot author or choose authority.

The response follows RFC 8693:

```json
{
  "access_token": "<opaque in logs and responses outside this exchange>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "cards:incident.read cards:freeze.propose"
}
```

## Delegated access-token claims

The signed JWT contains at least:

```json
{
  "iss": "https://identity.meridian.com:8443",
  "sub": "<customer id>",
  "act": {
    "sub": "<Agent workload reference>",
    "client_id": "<bound Agent OAuth client id>",
    "workload_id": "<Agent workload UUID>"
  },
  "aud": ["card-case-api"],
  "scope": "cards:incident.read cards:freeze.propose",
  "tenant_id": "<tenant id>",
  "purpose": "Resolve the customer's reported lost card",
  "delegation_id": "<grant id>",
  "authority_profile": "ciam_customer",
  "authority_id": "<grant id>",
  "token_use": "delegated_access",
  "iat": 0,
  "exp": 0,
  "jti": "<unique token id>"
}
```

The actual timestamps are Unix times. The delegated token lifetime cannot exceed the remaining
subject-token or delegation lifetime and is short by default.

Continuation tokens use the same dual-principal shape but do not carry a CIAM `delegation_id`.
They carry the persisted route ID in `authority_id` and one of these server-selected profiles:

| Result | `authority_profile` | `token_use` | Exact audience |
|---|---|---|---|
| Workforce to receiving Agent | `workforce` | `exchange_subject` | Receiving Agent audience |
| Agent to Argus Gateway | `workload_continuation` | `gateway_authorization` | Trusted Gateway audience |
| Argus Gateway to destination Agent | `gateway_backend` | `exchange_subject` | Destination Agent audience |
| Argus Gateway to resource | `gateway_backend` | `delegated_access` | Registered resource audience |

For Gateway-minted results, `client_id` and `azp` identify the trusted Gateway broker while `act`
continues to identify the business Agent exercising the original subject's authority. Axiom never
rewrites `sub`, never inserts the Gateway as the business actor, and never accepts an `act` claim from
request parameters.

## Downstream validation contract

An API must fail closed unless it validates all of the following:

1. The JWT signature against Axiom's current JWKS.
2. Exact issuer.
3. Exact intended audience.
4. `exp`, `iat` and any configured clock skew.
5. Tenant identity.
6. Customer identity in `sub`.
7. Bound Agent workload reference in `act.sub`, OAuth client in `act.client_id`, and workload UUID in
   `act.workload_id`.
8. Required scope as a subset of the JWT scope.
9. `delegation_id` presence and, for revocation-sensitive actions, active status or revocation event.
10. Purpose compatibility with the requested operation.

Checking only signature and expiry is insufficient. A normal customer token, client-credentials token,
administrative impersonation token, wrong-audience token or wrong-agent token must be rejected.

## Revocation semantics

- Customer grant revocation is terminal and idempotent.
- Workload revocation is terminal and invalidates every active grant for new exchanges.
- New exchanges fail immediately after either revocation.
- Resource APIs use short token lifetimes plus revocation-aware validation for sensitive operations.
- Axiom preserves issued-token and exchange audit history after revocation.
- Revocation does not silently restore when a workload or customer is registered again.

## Audit contract

The immutable lifecycle events are:

```text
CUSTOMER_REGISTERED
CUSTOMER_VERIFIED
CUSTOMER_RECOVERY_CHALLENGE_ISSUED
CUSTOMER_CREDENTIAL_RECOVERED
AGENT_WORKLOAD_REGISTERED
AGENT_WORKLOAD_REVOKED
DELEGATION_GRANT_CREATED
DELEGATION_GRANT_REVOKED
TOKEN_EXCHANGE_SUCCEEDED
TOKEN_EXCHANGE_DENIED
TRUSTED_EXCHANGE_BROKER_REGISTERED
TRUSTED_EXCHANGE_BROKER_REVOKED
AGENT_EXCHANGE_ROUTE_CREATED
AGENT_EXCHANGE_ROUTE_REVOKED
```

Exchange audit records identify tenant, customer, actor workload, OAuth client, audience, requested
scopes, granted scopes, purpose, delegation ID, correlation ID, outcome and a safe denial reason. They
must never contain passwords, verification or recovery tokens, OAuth client secrets, subject tokens,
actor tokens, delegated tokens or token hashes usable as credentials.

## Transaction and failure rules

- Customer, grant, workload and audit mutations commit atomically.
- Registration retries cannot create duplicate customers.
- Grant creation retries cannot create duplicate active authority.
- Token exchange is read-only except for mandatory audit and protocol state.
- If mandatory audit persistence fails, the exchange fails closed and no token is returned.
- Cross-tenant identifiers resolve as not found or unauthorized without leaking record existence.
- Revocation races resolve in favor of revocation.

## Clean-environment acceptance

The product is accepted only from empty Axiom volumes. The functional harness must prove:

1. A customer registers and verifies.
2. A tenant administrator registers a confidential agent workload.
3. The customer authenticates and creates one bounded delegation grant.
4. The customer supplies the subject token and the Agent workload authenticates independently as the confidential OAuth client actor.
5. The subject token contains `identity_kind=customer`, uses the customer UUID as `sub`, identifies the tenant and session, and contains no workforce or platform roles.
6. RFC 8693 exchange returns a short-lived audience-bound token.
7. A downstream validator accepts the exact audience and scope.
8. The same validator rejects wrong audience, missing scope, missing `act`, wrong actor, workforce tokens and normal impersonation tokens.
9. Grant revocation immediately prevents a new exchange.
10. Workload revocation immediately prevents a new exchange.
11. Customer suspension prevents authentication and exchange.
12. Credential recovery invalidates the previous customer session and active delegations; a new authenticated session requires fresh consent.
13. Audit shows both identities and every lifecycle transition without secret material.
14. A second harness execution is either idempotent or uses unique fixture identities without corrupting the first run.
15. A workforce PKCE token can enter only the exact assigned Agent workload.
16. The Agent can mint only the route-approved Argus Gateway authorization.
17. Only the registered Gateway broker can continue that authority to the exact downstream Agent or
    resource.
18. Wrong target, scope escalation, sibling replay, malformed actor data, revoked route, or revoked
    broker fails closed.

### Browser acceptance

At 1280, 1440 and 1728 pixel widths, prove the following through the running UI:

Customer journey:

1. Register a customer account.
2. Complete local verification without exposing another customer's existence.
3. Sign in as the verified customer.
4. Review the exact Agent, audience, scopes, purpose and expiry before granting consent.
5. Review active delegation grants and customer sessions.
6. Revoke the delegation and observe its terminal state.
7. Sign out and confirm the session is no longer usable.

Administrator journey:

1. Find the customer without seeing credential material.
2. Register and inspect the Agent workload and bound OAuth client.
3. Inspect active and revoked delegation inventory.
4. Inspect the dual-principal audit trail, with customer subject and acting workload shown separately.
5. Confirm a denied exchange records a safe reason without containing tokens.

For both journeys:

- keyboard focus is visible and every operation is keyboard reachable;
- labels and status never rely on colour alone;
- long customer, Agent, purpose, audience and scope values wrap safely;
- no headings, controls, tables, drawers or dialogs overlap or clip;
- no document-level horizontal scrolling occurs;
- loading, empty, validation, denial and revoked states retain a stable layout;
- the browser console contains no errors or warnings.

## Standards grounding

- OAuth 2.0 Token Exchange, RFC 8693: <https://datatracker.ietf.org/doc/html/rfc8693>
- JSON Web Token, RFC 7519: <https://datatracker.ietf.org/doc/html/rfc7519>
- OAuth 2.0 Token Revocation, RFC 7009: <https://datatracker.ietf.org/doc/html/rfc7009>
