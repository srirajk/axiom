# CIAM and Agent Delegation Functional Acceptance

This runbook is the handoff gate for the greenfield Axiom CIAM and RFC 8693 slice. It validates the
running product through public HTTP surfaces. It does not insert directly into PostgreSQL.

## Clean start

The reset is destructive and is run only against the local Axiom Compose project:

```bash
docker compose down -v --remove-orphans
docker compose up -d --build
docker compose ps --all
curl --fail http://localhost:8180/actuator/health
curl --fail http://localhost:8180/.well-known/openid-configuration
```

Do not delete or modify Argus Assured volumes as part of this verification.

## Publish the local demonstration estate

Set `AXIOM_CIAM_DEMO_CUSTOMER_PASSWORD` to a local demonstration password, then publish through the
same HTTP APIs used by the product:

```bash
set -a
source .env
set +a
python3 scripts/publish-ciam-demo.py
```

The publisher creates or reconciles exactly one demonstration application, one public customer
client, one confidential Agent client, one verified customer, one Agent workload, and one active
delegation for `cards:incident.read`. It immediately replays itself and fails if stable identifiers,
inventory counts, audit counts, or lifecycle-event counts change during reconciliation. After the
no-op replay check, it performs one live RFC 8693 exchange to prove the locally held Agent credential
and persisted delegation work together. That proof creates the expected token-exchange audit record.

The generated Agent client secret is written only to
`.local/ciam-demo/agent-client.json` by default. The directory is gitignored and the file is mode
`0600`. Override the location with `AXIOM_CIAM_DEMO_SECRET_FILE`; a location inside the repository is
accepted only when Git confirms it is ignored. The secret is never printed or returned by read APIs.

If the confidential client exists but this local file has been lost, do not create a parallel client
or place a credential in source. On a greenfield local estate, perform the documented clean reset and
publish again.

## Functional harness

After the server implementation exposes the locked contract, run:

```bash
set -a
source .env
set +a
python3 scripts/verify-ciam-agent-delegation.py
```

The harness reads credentials only from environment variables and never prints passwords, client
secrets, verification tokens, recovery tokens, authorization codes or access tokens.

Required environment:

```text
AXIOM_ADMIN_PASSWORD
```

Optional local overrides:

```text
AXIOM_CIAM_ISSUER=http://localhost:8180
AXIOM_CIAM_TENANT_ID=meridian
AXIOM_CIAM_ADMIN_USERNAME=admin
```

## Required proof

The command must print `PASS` for:

- discovery advertises token exchange;
- customer registration and verification;
- customer authentication;
- customer subject token has `identity_kind=customer`, customer UUID `sub`, tenant and session;
- customer subject token has no workforce roles, platform roles, workforce permissions or impersonation authority;
- confidential agent-workload registration;
- customer-owned bounded delegation creation;
- the customer subject token and authenticated confidential-client actor remain distinct;
- exchange succeeds for exact grant, audience and scope;
- delegated JWT has exact `sub`, `act.sub`, audience, scope, tenant, purpose and delegation ID;
- downstream validation accepts the exact request;
- excessive scope fails;
- an unknown or unapproved business scope fails before exchange;
- wrong audience fails;
- wrong actor fails;
- cross-tenant use fails;
- revoked delegation prevents new exchange;
- revoked workload prevents new exchange;
- customer suspension prevents authentication and new exchange;
- credential recovery invalidates the earlier customer session for exchange;
- a new customer session after recovery requires a newly recorded delegation grant;
- audit shows lifecycle, successful exchange and denied exchange events;
- audit contains no credential material.

The command must end with:

```text
RESULT PASS (all CIAM and agent delegation acts)
```

## Argus Gateway continuation harness

After publishing `configuration/tenants/meridian`, run the multi-hop workforce and Agent contract:

```bash
set -a
source .env
set +a
python3 scripts/verify-argus-agent-exchange.py
```

The command must prove workforce S256 PKCE, application-scoped membership, source Agent exchange,
source Agent to Gateway authorization, Gateway to downstream Agent continuation, downstream Agent
to Gateway authorization, and Gateway to first-party resource access. It must also reject a wrong
route, sibling replay, scope escalation, and a caller-supplied actor token. It must end with:

```text
RESULT PASS (workforce -> Agent -> Argus Gateway -> Agent -> resource)
```

See [Control Plane to Axiom Integration](control-plane-axiom-integration.md) for the exact endpoint,
client, route, request, and JWT validation contract.

## Wealth workforce and Agent exchange harness

After publishing `configuration/tenants/meridian`, run the live Wealth chain:

```bash
python3 scripts/verify-wealth-agent-exchange.py
```

The command proves S256 PKCE for `rm_jane`, Workforce to Wealth Entry Agent, Entry Agent to Argus
Gateway, Gateway to Wealth Orchestrator, the four approved specialist delegations, and Holdings Agent
resource access. It also proves that wrong routes, an Orchestrator self-route, a false Decision Agent
edge, sibling replay, scope escalation, and caller-supplied actor authority fail closed.

Run the destructive route mutation only in a disposable acceptance environment:

```bash
AXIOM_WEALTH_VERIFY_REVOCATION=1 python3 scripts/verify-wealth-agent-exchange.py
python3 scripts/configure_axiom.py --tenant meridian
```

The first command revokes the active Holdings Agent to Gateway route and proves a later exchange is
denied. The publisher restores exactly the reviewed route. A second publisher replay must be a full
no-op.

The Wealth command must end with:

```text
RESULT PASS (workforce -> Wealth Entry Agent -> Argus Gateway -> Wealth Orchestrator -> specialist -> resource)
```

## Browser product acceptance

Run the customer and administrator journeys at 1280, 1440 and 1728 pixel widths.

As the customer:

- register and complete local verification;
- sign in;
- review Agent, audience, scopes, purpose and expiry before granting consent;
- review active sessions and delegation grants;
- revoke the grant and confirm its terminal status;
- sign out and confirm the session is no longer usable.

As the administrator at `http://localhost:5182`:

- the customer is verified and active;
- the agent workload is visible and revoked at the end of the harness;
- the delegation grant is visible and revoked at the end of the harness;
- the audit timeline identifies customer and actor separately;
- secret values are never displayed.

At every width confirm:

- all controls are keyboard reachable and have visible focus;
- no information depends on colour alone;
- long purpose, audience and scope values wrap;
- no clipping, overlap, hidden controls or document-level horizontal scrolling;
- loading, empty, validation, denial and revoked states preserve the same frame;
- the browser console has no errors or warnings.

## Non-acceptance conditions

Do not call the slice complete when any of the following remains true:

- `/auth/impersonate` is used as the on-behalf-of mechanism;
- customer ID in a URL is sufficient authorization;
- a workforce, administrator or impersonation token is accepted as the customer subject;
- an exchange is not authenticated by the exact confidential Agent workload client;
- Axiom accepts zero or multiple matching grants instead of requiring one unambiguous active authority;
- audience or scope is widened;
- a revoked grant or workload can obtain a new token;
- a downstream API validates only signature and expiry;
- audit persistence is optional;
- acceptance depends on retained local database state.
