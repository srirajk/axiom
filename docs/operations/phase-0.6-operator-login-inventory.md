# Phase 0.6 — legacy operator-login inventory (Axiom-side)

Status: **inventory complete for the current clone; migration not started or accepted**. No login endpoint, credential, client, or deployed release was changed.

## Direct script callers found

Source search for `/auth/login` in `scripts/*.py` found six direct callers, not the seven reported in the strategy. The seventh must be identified from the earlier inventory or another revision; do not invent or mark it migrated.

| Script | Current use of password-issued admin token | Migration class |
|---|---|---|
| `scripts/configure_axiom.py` | Publishes tenant/application/CIAM/Agent/broker/route configuration via admin APIs | Machine publisher; highest-priority replacement, with explicit tenant and narrowly scoped write authority |
| `scripts/publish-ciam-demo.py` | Reconciles demo application, browser/service clients, customer, workload and grant | Demo publisher; keep outside any external pilot until a dedicated test/operator client is approved |
| `scripts/verify-ciam-agent-delegation.py` | Sets up disposable CIAM Agent test resources | Test fixture administrator, not a human-login test |
| `scripts/verify-quickstart-agent-exchange.py` | Reads broker inventory for verification | Read-only verifier; should not need configuration-write authority |
| `scripts/verify-argus-agent-exchange.py` | Reads broker and route inventory | Read-only verifier; should not need configuration-write authority |
| `scripts/verify-wealth-agent-exchange.py` | Reads broker, workload and route inventory | Read-only verifier; should not need configuration-write authority |

The isolated Phase 0 harness also uses `/auth/login` for test-namespace bootstrap. It is a separate test harness, not a production migration substitute. The admin web UI references login/token paths for human interaction and is not a machine-script migration target. `/auth/token` is a backwards-compatible password endpoint in `AuthController`, so disabling only `/auth/login` would not eliminate the legacy capability.

`configure_axiom.py` also checks Kubernetes Secret get/create/patch permissions in namespaces named by its bundle. It must **not** be run as a 0.6 test against the current environment: its HTTP writes and possible Secret writes exceed the isolated `axiom-phase0-test` surface. Moving HTTP authentication to a client credential does not grant permission for those Kubernetes operations; they need a separate, explicitly reviewed scope and test fixture.

## Current blocker to a safe client-credentials swap

Axiom confidential application clients can obtain client-credentials tokens, but `JwtClaimsCustomizer` gives them workload identity and tenant/client/audience claims, not administrator roles. The `/admin/**` filter requires platform, tenant or domain admin roles; `TenantProvisioningController` additionally requires `platform_admin`. Simply replacing a script's password with an existing service-client secret will fail authorization. Copying `platform_admin` into every service token or treating any `client_credentials` token as admin would widen access and is rejected as a migration approach.

Before implementation, enumerate the exact HTTP methods/routes each script needs and separate read-only verification, tenant configuration writes, and platform-only provisioning. Define a dedicated operator client posture and scopes with explicit tenant binding, endpoint-level method gates, short token lifetime, auditable client identity, secret rotation and revocation. Preserve human login through the supported browser flow. Test that an ordinary confidential workload client, a cross-tenant client, and a read-only operator cannot perform writes; test that the intended publisher can perform only its approved operations. Do not disable either password endpoint until all machine callers and rollback are proven.

Recovery for a future migration is to restore the prior script authentication mode in the isolated test profile while the old endpoint is still available, revoke the test operator client, and re-run read/write denial checks. This document itself requires no runtime rollback.
