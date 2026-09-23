# Control Plane to Axiom Integration

This is the runtime handoff for Control Plane and Argus Gateway. Axiom authenticates the original
human or workload, resolves persisted exchange authority, and mints short-lived tokens. Control
Plane does not construct identity claims, choose an authority profile, or sign a replacement token.

## Endpoints

| Purpose | Cluster endpoint | Local Gateway endpoint |
|---|---|---|
| Issuer and browser authorization | `http://axiom.axiom.svc.cluster.local:8084` | `https://identity.meridian.com:8443` |
| OIDC discovery | `http://axiom.axiom.svc.cluster.local:8084/.well-known/openid-configuration` | `https://identity.meridian.com:8443/.well-known/openid-configuration` |
| JWKS | `http://axiom.axiom.svc.cluster.local:8084/oauth2/jwks` | `https://identity.meridian.com:8443/oauth2/jwks` |
| Token and token exchange | `http://axiom.axiom.svc.cluster.local:8084/oauth/token` | `https://identity.meridian.com:8443/oauth/token` |

The configured issuer remains `https://identity.meridian.com:8443`, including when a pod uses the
cluster-local connection endpoint. JWT validation must require that exact issuer. The local HTTPS
certificate is demonstration-only and self-signed. A production deployment must use a trusted
certificate and the production issuer URL.

The current `axiom/allow-gateway-and-clients` NetworkPolicy accepts Axiom API traffic from every
cluster namespace on TCP 8084, so a Control Plane namespace requires no special label in this local
cluster. A production policy should narrow this to the approved Gateway and platform namespaces.

## Registered Meridian authority

The reviewed package in `configuration/tenants/meridian/ciam` creates:

- public workforce client `card-operator-web`;
- source Agent client and workload `card-assistance-agent` / `agent:card-assistance:development`;
- destination Agent client and workload `card-actions-agent` / `agent:card-actions:development`;
- trusted broker client `argus-gateway-broker` with audience `argus-gateway`;
- resource audience `card-case-api`;
- scope `cards:incident.read`;
- four typed routes: source Agent to Gateway, source Agent to destination Agent, destination Agent to
  Gateway, and destination Agent to resource.

The local card demonstration writes its two Agent credentials with mode `0600` to
`.local/configured-agent-clients.json`. The shared Gateway broker credential is written directly to
`argus-system/argus-gateway-agent-exchange-oauth-client` with keys `client_id` and `client_secret`.
Never copy either source into an image, ConfigMap, repository, log, browser, or UI.

## Exchange request

Every continuation uses RFC 8693 at `/oauth/token`. The caller authenticates with HTTP Basic using
its own registered confidential client.

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<current Axiom access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_token_type=urn:ietf:params:oauth:token-type:access_token
audience=<one exact receiving audience>
scope=cards:incident.read
```

Do not send `actor_token`, `purpose`, `delegation_id`, `act`, tenant, Agent, route, or authority
profile parameters. Axiom derives them from the authenticated client, validated subject token, and
active server-owned records. Caller-supplied authority data is rejected.

## Required flow

1. A workforce user receives an authorization-code token with S256 PKCE for `card-operator-web`.
2. `card-assistance-agent` exchanges it for an `exchange_subject` token with audience `cards-api`.
3. The same Agent exchanges that token for a `gateway_authorization` token with audience
   `argus-gateway`.
4. `argus-gateway-broker` exchanges the Gateway token for an `exchange_subject` token with audience
   `card-actions-api`.
5. `card-actions-agent` exchanges that token for its own `gateway_authorization`.
6. `argus-gateway-broker` exchanges that Gateway token for `delegated_access` with audience
   `card-case-api`.

The customer-consent profile is intentionally shorter. The exact Agent bound to an active customer
grant exchanges a customer subject token directly for one audience-bound `delegated_access` token.
That result is not transitive.

## Token validation contract

Every receiving workload must validate:

- RS256 signature against Axiom JWKS;
- issuer exactly `https://identity.meridian.com:8443`;
- one exact audience and no audience substitution;
- `exp`, `iat`, and a maximum exchange-token lifetime of 300 seconds;
- `tenant_id=meridian`;
- original principal in `sub`;
- current business Agent in structured `act.sub`, `act.client_id`, and `act.workload_id`;
- `client_id` and `azp` as the OAuth client that performed the current exchange;
- required business scope;
- `authority_profile`, `authority_id`, and `token_use` for the expected hop;
- `delegation_id` only for direct customer consent;
- current route, workload, broker, session, and application authority when revocation sensitivity is
  required.

The Gateway is the OAuth caller on Gateway-minted tokens, but it is never the business Agent in
`act`. `sub` remains the original human or originating workload through every hop.

## Functional proof

From the Axiom repository, publish and replay the reviewed package, then run both live harnesses:

```bash
python3 scripts/configure_axiom.py --check
python3 scripts/configure_axiom.py --tenant meridian
python3 scripts/configure_axiom.py --tenant meridian
python3 scripts/verify-argus-agent-exchange.py
python3 scripts/verify-ciam-agent-delegation.py
```

The Argus harness must end with:

```text
RESULT PASS (workforce -> Agent -> Argus Gateway -> Agent -> resource)
```

It proves the full live chain, exact claims, signature validation, wrong-route rejection, sibling
replay rejection, scope-escalation rejection, caller actor-data rejection, audit completeness, and
absence of credentials from audit output.

The Wealth application uses the same issuer and broker with its own scope, workload identities,
audiences, Kubernetes Secrets, and least-authority route graph. See
[Control Plane Wealth to Axiom Integration](control-plane-wealth-axiom-integration.md).
