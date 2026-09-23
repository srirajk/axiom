# Control Plane Wealth to Axiom Integration

This is the exact identity handoff for the Control Plane Quarterly Portfolio Review application.
Axiom authenticates `rm_jane`, establishes application membership, and mints every continuation token.
Argus Gateway brokers only routes that Axiom has persisted. Control Plane must not manufacture identity
claims or sign an on-behalf-of token.

## Connection

| Purpose | Value |
|---|---|
| Cluster token endpoint | `http://axiom.axiom.svc.cluster.local:8084/oauth/token` |
| Cluster discovery | `http://axiom.axiom.svc.cluster.local:8084/.well-known/openid-configuration` |
| Public issuer | `https://identity.meridian.com:8443` |
| Public JWKS | `https://identity.meridian.com:8443/oauth2/jwks` |
| Tenant | `meridian` |
| Business scope | `wealth:review.invoke` |
| Gateway client | `argus-gateway-broker` |
| Gateway audience | `argus-gateway` |

Receivers must validate the public issuer even when they use the cluster Service for transport.

## Workforce entry

`wealth-review-web` is a public S256 PKCE client. It has no secret. `rm_jane` and `rm_marco` hold the
application role `wealth-review-relationship-manager`, whose only business permission is
`wealth:review.invoke`.

The browser token is exchanged by the confidential server-side client `wealth-entry-agent`. The
result keeps the human in `sub=rm_jane` and records the current workload in structured `act`. The Entry
Agent obtains Gateway authority, and the Gateway continues the same human subject to the exact Wealth
Orchestrator audience.

## Workloads, audiences, and Secrets

Every workload has one active confidential identity. Each opaque Secret contains only `client_id` and
`client_secret`.

| Client ID | Workload reference | Audience | Kubernetes Secret |
|---|---|---|---|
| `wealth-entry-agent` | `agent:wealth-entry-agent:development` | `agent:meridian:wealth-entry-agent` | `wealth/wealth-entry-agent-axiom-oauth-client` |
| `wealth-orchestrator` | `agent:wealth-orchestrator:development` | `agent:meridian:wealth-orchestrator` | `wealth/wealth-orchestrator-workload-oauth-client` |
| `wealth-holdings-agent` | `agent:wealth-holdings-agent:development` | `agent:meridian:wealth-holdings-agent` | `wealth/wealth-holdings-agent-workload-oauth-client` |
| `wealth-market-agent` | `agent:wealth-market-agent:development` | `agent:meridian:wealth-market-agent` | `wealth/wealth-market-agent-workload-oauth-client` |
| `wealth-suitability-agent` | `agent:wealth-suitability-agent:development` | `agent:meridian:wealth-suitability-agent` | `wealth/wealth-suitability-agent-workload-oauth-client` |
| `wealth-drafting-agent` | `agent:wealth-drafting-agent:development` | `agent:meridian:wealth-drafting-agent` | `wealth/wealth-drafting-agent-workload-oauth-client` |
| `wealth-decision-agent` | `agent:wealth-decision-agent:development` | `agent:meridian:wealth-decision-agent` | `wealth/wealth-decision-agent-workload-oauth-client` |
| `wealth-reports-agent` | `agent:wealth-reports-agent:development` | `agent:meridian:wealth-reports-agent` | `wealth/wealth-reports-agent-workload-oauth-client` |
| `argus-gateway-broker` | trusted broker, not an Agent | `argus-gateway` | `argus-system/argus-gateway-agent-exchange-oauth-client` |

Do not copy these credentials into ConfigMaps, images, logs, UI state, or a browser client.

## Reviewed route matrix

Every Agent has an Agent-to-Gateway route. Only relationships proven by the Control Plane workload are
present beyond that baseline.

| Source workload | Destination type | Exact audience or workload |
|---|---|---|
| Entry | Gateway | `argus-gateway` |
| Entry | Agent | `agent:wealth-orchestrator:development` |
| Orchestrator | Gateway | `argus-gateway` |
| Orchestrator | Agent | Holdings, Market, Suitability, Drafting |
| Holdings | Gateway | `argus-gateway` |
| Holdings | Resource | `tool:meridian:wealth-holdings-tool`, `model:meridian:wealth-review-model` |
| Market | Gateway | `argus-gateway` |
| Market | Resource | `tool:meridian:wealth-market-tool`, `model:meridian:wealth-review-model` |
| Suitability | Gateway | `argus-gateway` |
| Suitability | Resource | `model:meridian:wealth-review-model` |
| Drafting | Gateway | `argus-gateway` |
| Drafting | Resource | `model:meridian:wealth-review-model` |
| Decision | Gateway | `argus-gateway` |
| Decision | Resource | `model:meridian:wealth-review-model` |
| Reports | Gateway | `argus-gateway` |

There is no Orchestrator self-route. There is no Orchestrator to Decision edge because the current
application invokes the decision operation separately. There is no invented Reports edge.

## Exchange contract

Every hop calls `/oauth/token` with HTTP Basic authentication for the exact current caller:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<current Axiom access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
requested_token_type=urn:ietf:params:oauth:token-type:access_token
audience=<one exact audience>
scope=wealth:review.invoke
```

Do not send `actor_token`, `act`, tenant, purpose, route, workload, or authority-profile fields. Axiom
derives those values from the authenticated client, subject token, application membership, broker,
workload, and active route. A token must retain the original human `sub`, contain one exact audience,
and identify the current business workload in structured `act`.

## Functional handoff

From the Axiom repository:

```bash
python3 scripts/configure_axiom.py --check
python3 scripts/configure_axiom.py --tenant meridian
python3 scripts/configure_axiom.py --tenant meridian
python3 scripts/verify-wealth-agent-exchange.py
```

For the acceptance-only revocation loop:

```bash
AXIOM_WEALTH_VERIFY_REVOCATION=1 python3 scripts/verify-wealth-agent-exchange.py
python3 scripts/configure_axiom.py --tenant meridian
python3 scripts/configure_axiom.py --tenant meridian
```

Restart Axiom and rerun the non-destructive harness. Acceptance requires the same result after restart.
Control Plane wiring is outside this package. It should consume these existing Secret names and exchange
contracts without changing the Axiom authority model.
