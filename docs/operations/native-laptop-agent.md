# Native laptop clients

A coding tool can sign a workforce person in with authorization code and PKCE through a public client, then send that access token to a trusted Gateway broker. The broker can exchange it for a registered target. Axiom keeps the person as `sub`, names the registered laptop workload in `act`, and pins the issued token to the target audience. The broker still needs its own confidential client and trusted-broker registration.

## Configure one tool for one use case

The Meridian demo in `configuration/tenants/meridian/ciam/` contains a complete `quickstart-laptop-tool` example. It creates a public workforce client on the `argus-gateway` application with PKCE, `offline_access`, refresh-token rotation, and a 600-second access token. It also creates a `NATIVE` workload bound to that client, a GATEWAY route, a RESOURCE route to the quickstart tool, and an application role assigned to the demo person. The redirect URI is a loopback URI; the registered client accepts an ephemeral loopback port.

For a real tool and use case, use distinct client IDs and workload references. Register its public client through `POST /admin/tenants/{tenant}/applications/{applicationId}/clients` with `clientType: PUBLIC_BROWSER`, `population: WORKFORCE`, `refreshTokens: true`, `accessTokenTtlSeconds: 600`, and only the needed scopes. The application audience must equal the trusted broker's gateway audience. Register the workload through `POST /admin/tenants/{tenant}/ciam/agent-workloads` with `kind: NATIVE` and the public `oauthClientId`. Add an active GATEWAY route for that workload and a destination route or broker target. Assign the person application access for the requested scope.

A server workload continues to use `kind: SERVER` (the default) and a confidential client. Native workloads cannot receive CIAM customer delegation or consent. Registration and route creation are tenant-admin operations; the public client alone has no authority to create them.

## Checks and recovery

An original sign-in token is accepted for a Gateway broker exchange only when it is workforce, has exactly the broker gateway audience, comes from an active public workforce client, belongs to a person with current application access, and that client has an active native workload with a GATEWAY route covering the requested scope. Target registration and scope limits still apply. Disabling the client, person access, workload, route, or target stops new exchanges. The gateway route ID is carried into issued target tokens so their live validation can detect route revocation. A target token cannot be used for an unrelated audience.

If setup fails partway through, rerun `python3 scripts/configure_axiom.py --check` and then the reviewed tenant publisher. Existing records are checked for kind, client settings, and route drift. To withdraw the path, revoke the native workload or its GATEWAY route through the admin API. Do not delete or reset the tenant database to recover from a configuration error.

The isolated `EntryAgentGatewayScenarioIT` covers registration, PKCE sign-in, exchange, `sub`/`act`/audience claims, unauthorized broker denial, route revocation, and introspection with PostgreSQL and Redis containers. It does not exercise a live browser, Gateway, or CLI.
