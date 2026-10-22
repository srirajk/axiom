# Axiom and Argus identity onboarding implementation plan

Date: October 22, 2026

Status: implementation proposal. This file changes no application code, configuration, database, credentials or running service.

## 1. Outcome and implementation boundary

Yes, this is possible. A customer connects its company identity provider once. Authorized people sign in with company SSO, Axiom creates their identity reference on first login, and registering an agent through Argus provisions its separate workload identity. Argus continues to control approved access to tools, models and other agents.

The recommended first implementation uses the customer IdP for human authentication and Axiom for the tokens consumed by the Argus integration. Agent clients are created in Axiom. This does not require permission to create clients in the customer's Okta, Auth0 or Entra tenant.

Existing customers retain the existing login, manually linked federation, SCIM, client-registration and agent-registration paths. New automation is opt-in. Compatibility is an implementation requirement with explicit acceptance gates, not a promise that unimplemented code has passed regression testing.

This plan covers workforce users, agent workloads and the infrastructure identities needed for the integration. It does not change the separate CIAM customer population. It does not introduce unrestricted exchange of existing external access tokens, universal downstream API access or support for multiple runtime issuers on one gateway.

## 2. What the customer does

### One-time organization setup

1. An authorized operator provisions the Axiom tenant, registers the application/client/audience boundaries, approves the scope vocabulary and client ceilings, and configures the Argus integration. The resource order and scope assignments are specified below; existing administrative provisioning remains the bootstrap mechanism.
2. A customer IdP administrator registers Axiom as a confidential OIDC web application, enables authorization code sign-in and configures the supplied stable callback URL. They assign the people or groups allowed to use this integration.
3. An authorized Argus administrator enters the issuer, client ID and secret through an identity-connection setup flow. The secret goes to Axiom's protected credential storage; Argus stores a reference, not a retrievable copy.
4. The setup flow validates discovery, performs a test login, configures the permitted downstream application clients and enables JIT onboarding for this connection.
5. Axiom remains the issuer configured for the Argus Hub, Control API, CLI and relevant gateway. Their distinct audiences and client registrations remain distinct.

The upstream registration happens per customer connection and environment as required by its isolation policy. Each agent does not need a new upstream IdP application.

### Bootstrap resources and scope registration

Bootstrap establishes the authority to configure the integration. It does not propagate a human administrator's credentials into background services. The operator completes these operations in order:

| Order | Resource and operation | Required result |
| --- | --- | --- |
| 1 | `POST /admin/tenants` with `{tenantId, name, slug}` and an `Idempotency-Key`, using the existing platform-admin bootstrap path | Record the active tenant ID and provisioning outcome; do not configure clients against a half-provisioned tenant |
| 2 | Register the tenant's business-scope names through `POST /admin/tenants/{tenantId}/business-scopes`; deployment-approved names may already exist | Establish the permitted vocabulary, for example `argus:invoke`, `orders.read` and `orders.write`. A scope name in the catalog grants nothing by itself |
| 3 | `POST /admin/tenants/{tenantId}/applications`, then `POST .../applications/{applicationId}/clients` | Create management and business applications with explicit audiences, client types, callback URLs, authentication methods and allowed scopes |
| 4 | `POST .../applications/{applicationId}/access/roles`, then configure the new source/application mapping policy | Establish baseline application permissions and any approved mapping from upstream evidence. Existing operator memberships can use `.../access/memberships` and `.../memberships/{membershipId}/roles`; normal people will use JIT |
| 5 | Create the connection-manager, registrar and authority-publisher clients through the proposed privileged service templates | Assign only the proposed service scopes listed below. Store each private credential in its deployment's approved credential store |
| 6 | Create the gateway broker client and register it using `POST /admin/tenants/{tenantId}/agent-exchange/brokers` | Record the broker ID and gateway audience. A broker identity is not also an agent workload |
| 7 | Create and validate the upstream source through the existing `identity-sources` APIs; configure its new application bindings, admission policy and optional permission mappings | Bind the upstream issuer/client to this tenant and the specific downstream applications. Initial SSO claim scopes are explicitly configured |
| 8 | Configure Argus issuer/JWKS, token endpoint, Control API audience, gateway audience, caller-client claim and broker credential reference | Hub, CLI, Control API and gateway use the intended Axiom issuer with their own audience checks. Argus's operator roles and review assignments are established through its existing authorization model |
| 9 | Configure managed-identity application templates and the authority-publisher's allowed gateway/target ceilings | Establish which existing application a managed workload belongs to and which reviewed routes can later be materialized |
| 10 | Run a first company login and a first governed call before enabling normal onboarding | Verify actual granted scopes, application membership, subject/actor/client identity and the Argus decision record |

Steps 1 to 4 and 6 reuse existing administrative APIs. The service templates, source policy and managed-onboarding operations are additions in this plan. An installer may orchestrate them only under its separately authorized bootstrap identity; the ordinary registrar cannot create tenants or bootstrap its own privileges.

Create these distinct registrations and ceilings. Names and audience examples below are illustrative configuration values, not hardcoded identifiers:

| Registration | Issuer and purpose | Scope ceiling and restrictions |
| --- | --- | --- |
| Axiom's upstream SSO client | Customer IdP; authenticate company users to Axiom | `openid profile email`, plus provider-supported claim/group scopes if an approved mapping needs them. `offline_access` is optional and requires a defined upstream refresh lifecycle |
| Argus Hub and CLI clients | Axiom; authenticate people to Argus management | OIDC scopes supported by their client posture, plus only actual registered Control API scopes if required. A public CLI does not gain confidential-web refresh support simply by asking for `offline_access` |
| Business experience/BFF client | Axiom; authenticate a person to a specific agent experience | Example: `openid profile email argus:invoke orders.read orders.write`; the resulting business scopes are narrowed to that person's effective entitlements |
| Business entry-agent client | Axiom; authenticate the acting workload | Explicit runtime ceiling such as `argus:invoke orders.read orders.write`; no identity-administration scopes. For initial human delegation, place this client in the same Axiom application as its business experience/BFF client |
| Additional agent clients | Axiom; authenticate each distinct workload | Their own approved runtime ceilings and explicit continuation routes. Separate clients remain separate identities |
| Gateway broker client | Axiom; authenticate the trusted exchanging intermediary | Its explicit broker registration, for example `argus:invoke` for its own configured authority. Business scope ceilings on source routes and broker targets are separately configured; do not assume all source business scopes must be copied into the broker's own OAuth scope list |
| Connection-manager client | Axiom; configure the allowed tenant's SSO connection | Proposed `identity-connections.configure`; no workload creation, publication or human administration |
| Identity registrar client | Axiom; provision owned managed workload identities | Proposed `managed-identities.provision` and `managed-identities.read`; add `managed-identities.retire` only to the authorized lifecycle worker |
| Authority-publisher client | Axiom; materialize approved release authority | Proposed `managed-authority.publish`, restricted to the configured tenant, gateway, owned identities and scope ceilings |

The management Hub application is not the source application for every business agent. `AgentExchangeAuthorityService.resolveWorkforce` currently requires the workforce login client and initial acting workload client to share the same Axiom application. Preserve this check. A person launches a separate authorization for the business application, which can reuse their company SSO session, rather than forwarding a Hub/CLI management token into an unrelated agent application.

Managed templates must therefore support an operator-provisioned application containing both the business browser/BFF client and its entry-agent client. A dedicated application can also be created from an approved template for an autonomous agent. Do not unconditionally create an unrelated application for every workload and then weaken the existing delegation check to make human delegation work.

Service administration scopes are explicit grants to selected infrastructure clients. Do not add them to the default `SERVICE_SCOPES` set in `TenantApplicationService`: its current empty-scope registration behavior defaults to that set. Instead add a privileged template/client policy and require it at registration, issuance and the service endpoint. Reserve these administrative names from the tenant's ordinary custom business-scope catalog, so registering an identically spelled business scope cannot obtain provisioning authority.

### A person signs in

1. The Hub or CLI starts its normal Axiom authorization code flow with PKCE.
2. Axiom resolves the downstream client to its tenant, workforce population and allowed identity connection. A single configured connection redirects automatically to the company IdP.
3. The IdP authenticates the person. Axiom processes the callback using the stored authorization request, validates the upstream identity and applies the connection's admission policy.
4. If an active exact external identity link exists, Axiom reuses it. If no link exists and JIT is enabled, Axiom atomically creates a minimal principal, an external-only authentication policy, an external identity link and the explicitly configured baseline application membership.
5. Axiom resumes the original downstream authorization request. The Hub or CLI receives an authorization code and exchanges it for Axiom tokens through the existing token endpoint.
6. Argus resolves the person's separately assigned administrative permissions. A valid company login does not automatically make the person an administrator, owner or reviewer.

The person does not visit Axiom administration, create a local password or wait for a SCIM record.

### An owner registers an agent

1. In Argus, the owner chooses **Create managed identity**. **Use an existing client** remains available.
2. A deployment-side CLI/helper generates a key pair or uses a supported existing key. Only the public JWK is submitted. A private key stays in the deployment's approved key or secret store.
3. Argus starts a durable onboarding job scoped to the tenant, environment, gateway and intended agent. Axiom provisions its client/workload objects inside the approved application template through a narrowly authorized service interface; a new application is created only when the template calls for it.
4. After provisioning succeeds, Argus records the resulting issuer and client ID through the existing agent-registration domain logic and client-assignment ledger. A retry returns the same onboarding result.
5. The owner requests the agent's grants. The existing approval and release process decides when those grants take effect.
6. The deployment authenticates as that agent using its own private key. Axiom issues the appropriate bounded tokens. Argus permits calls only under the live release.

Identity readiness and permission to call a tool are separate states. Neither successful provisioning nor a successful sign-in grants broad access.

## 3. Current implementation and required additions

Repository locations below refer to the inspected checkouts. Axiom paths are relative to this repository; Argus paths are relative to `/Users/srirajkadimisetty/projects/control-plane`.

| Area | Current behavior | Required addition |
| --- | --- | --- |
| Upstream federation | `federation/` already performs source-bound OIDC login and validation | Preserve it; add trusted downstream-client context and opt-in JIT |
| Login entry | `FederatedLoginController` starts an explicitly selected source; `PopulationLoginEntryPoint` chooses workforce or CIAM login | Resolve allowed source from the downstream workforce client and support automatic routing |
| External identity resolution | `FederatedIdentityResolver.resolve` requires an existing active link and principal | Create missing identities only under an enabled admission policy; never recreate disabled links |
| Application access | `ApplicationAccessService.tokenClaims` requires an active application membership | Add explicit baseline membership provisioning for admitted first logins |
| Upstream callback | `IdentitySourceClientRegistrationRepository` uses `{source UUID}.{revision}` in its registration and callback | Offer a stable callback URI while retaining the revisioned internal registration ID |
| User passwords | `Principal.passwordHash` is required; `CustomUserDetailsService` loads active principals for password login | Add an external-only policy and enforce it across credential mutation and password authentication |
| Token issuance | `JwtClaimsCustomizer` already produces application, tenant, audience and delegation claims | Reuse issuance; bind federated sessions and verify caller/actor semantics with Argus |
| Machine administration | Most provisioning controllers require human administrative roles | Add an explicit service-only provisioning surface and scoped ownership checks |
| Agent registration | Argus `FirstPartyAgentController.register` requires a client ID created elsewhere | Add a managed onboarding job that finishes through the existing registration logic |
| Client assignment | Argus `ClientAssignments` reserves issuer/client pairs for a holder | Keep this ledger authoritative for assignments; managed identities use it too |
| Agent credentials | Argus accepts an existing identity; deployment helpers obtain runtime tokens | Add public-key onboarding and deployment-side `private_key_jwt` support where missing |
| Lifecycle | Axiom has source/link status and durable IAM sessions, but no source binding on `IamSession` | Bind new federated authorizations to their source/link and enforce disablement consistently |

## 4. Compatibility rules

The implementation must satisfy all of these rules:

- A missing federation policy means the current link-only behavior. JIT is never enabled by a migration or an omitted request field.
- Existing `CreateIdentitySourceRequest`, existing agent-registration requests and required response fields keep their meaning. New operations use separate resources and DTOs.
- Existing principal IDs, external links, application memberships, clients and workload IDs do not change.
- Keep the internal federation registration ID and its source-revision checks. A stable callback URL does not imply accepting a changed source during an in-flight login.
- Existing local users retain local authentication. Existing SCIM ownership and managed-field behavior remain intact.
- A disabled principal, link or membership remains disabled. JIT cannot reactivate it, create a replacement to bypass it or overwrite SCIM-managed data.
- Existing Axiom administration roles, Argus roles, maker/checker separation and approved identity-control operations retain their current authority.
- No changes to the existing token issuer, claim meanings, audience checks or runtime client lookup are included merely to make onboarding succeed.
- Existing Argus releases and runtime record formats remain valid. Pending onboarding jobs are not published as runtime authority.
- A provisioning outage does not alter existing registrations or releases. New work shows a pending or failed state and resumes safely.
- All database changes are additive. Do not reuse an already allocated migration number or edit an applied migration.

The Argus identity-issuance design currently contains an explicit supersession stating that Argus does not create clients. The new managed mode is a product-contract extension to that rule. Preserve the existing customer-created-client mode and update the product documentation in the implementation change; do not silently reactivate the superseded design.

## 5. Axiom changes for human SSO

### A1. Add federation policy and application bindings

Add `FederationPolicy` and `FederationApplicationBinding` entities, repositories and service logic. Use a separate policy API so existing identity-source creation DTOs and callers remain unchanged.

Proposed additive data:

| Record | Minimum contents |
| --- | --- |
| `federation_policies` | Source ID, tenant ID, admission mode `LINK_ONLY` or `JIT`, status, policy revision, maximum authentication age, stable-callback setting |
| `federation_application_bindings` | Source ID, tenant/application ID, downstream client ID, permitted population, baseline membership policy, status |
| `principal_authentication_policies` | Principal ID, tenant ID, mode `EXTERNAL_ONLY`, owning source, creation origin |
| `federated_login_events` | Opaque event ID, tenant, principal, source, link, source/policy revision, authenticated time and reauthentication deadline |
| `federated_session_bindings` | IAM session ID and federated login event ID, with indexes for source/link/session revocation |

Use foreign keys and tenant-qualified validation. Reuse the existing unique external-link key `(source_id, issuer, subject)` rather than maintaining a second mapping. Policy absence preserves legacy behavior.

Proposed new policy API: `GET/PUT /admin/tenants/{tenantId}/identity-sources/{sourceId}/federation-policy`, plus an explicit application-bindings resource. These names describe new work, not currently available endpoints. Gate policy writes with the existing administrative boundary and a reviewed change for admission widening or privileged mapping.

Do not map arbitrary upstream groups to Axiom tenant-wide administration roles. The first release needs explicit admission and baseline application membership; when upstream business-permission propagation is enabled, also implement the source-bound mapping and ceiling rules in section 8. Privileged Argus assignments remain in Argus's current authorization model.

### A2. Resolve the source from the downstream authorization request

Change these existing files:

- `server/src/main/java/com/openwolf/iam/auth/PopulationLoginEntryPoint.java`
- `server/src/main/java/com/openwolf/iam/controller/LoginController.java`
- `server/src/main/java/com/openwolf/iam/controller/FederatedLoginController.java`
- `server/src/main/java/com/openwolf/iam/config/SecurityConfig.java`
- `server/src/main/resources/templates/login.html`

Add a `FederationLoginContext` and resolver that derive tenant/application/population from a registered downstream client. Bind the selected source and policy revision to the server-side upstream authorization request. Preserve the original downstream request and PKCE challenge.

The direct source-selection endpoint may still identify a source, but it must not select a different tenant or grant application access. Enforce binding at issuance even if somebody starts `/oauth2/authorization/{registrationId}` directly. A source hint is a routing hint; it never establishes trust or permissions.

For a client without a binding, keep the existing login entry behavior. For an enabled binding with one source, redirect directly. Restrict any selection page to that client's permitted sources. Keep CIAM routing separate. Email-domain discovery can be added later; it is unnecessary for the first integration.

### A3. Make the callback stable without removing revision fencing

Change `server/src/main/java/com/openwolf/iam/federation/IdentitySourceClientRegistrationRepository.java` only for policy-enabled sources:

```text
Internal registration ID:  {source UUID}.{source revision}          unchanged
Legacy callback:           /login/oauth2/code/{registrationId}      unchanged
Opt-in stable callback:    /login/oauth2/code/source-{source UUID}  new
```

Set the redirect URI on the new registration mode; do not replace the internal registration ID with a source-only ID. The OAuth callback filter must resolve the original registration from the stored authorization request and `state`, not trust the callback path as identity evidence. The locally cached Spring Security 6.5.11 callback implementation resolves `registration_id` from the saved authorization request; verify this behavior against the dependency actually built and the configured distributed session store in the implementation test.

Retain the existing guards in `FederatedAuthorizationCodeAccessTokenResponseClient`, `FederatedJwtDecoderFactory`, `IdentitySourceRevisionGuard` and `FederatedOidcUserService`. Add policy-revision checks for new login contexts. A changed source or policy during login must fail and restart, even though the external callback address is stable.

Existing sources stay on the old callback until explicitly switched. During an explicit switch, register the new callback upstream first, retain the old callback long enough for in-flight requests to finish, then switch the source. Test URI matching and proxy-derived public URLs.

### A4. Add transactional JIT resolution

Change `server/src/main/java/com/openwolf/iam/federation/FederatedIdentityResolver.java` and `FederatedOidcUserService.java`. Add a dedicated `FederatedIdentityProvisioningService` rather than embedding database writes in token validation.

After upstream validation and downstream binding validation:

1. Recheck source and policy status/revision under the provisioning transaction's concurrency boundary.
2. Look up the exact existing link, including disabled rows. An inactive link or principal denies login.
3. If no link exists and the policy is link-only, retain the current denial.
4. If no link exists and JIT is enabled, allocate an opaque principal ID and a generated globally unique internal username. Display name and email are profile attributes, not identity keys.
5. Create the principal, external-only policy, link, configured baseline application membership and required audit event atomically. Validate the chosen application belongs to the same tenant. For an existing active link signing in to another explicitly bound application, provision only that application's missing baseline membership under the same policy. Never recreate a disabled membership or restore a withdrawn role.
6. Resolve concurrent first logins through database uniqueness and retry in a fresh transaction after a uniqueness conflict. Return the winning identity; leave no orphan principal or duplicate membership. Keep upstream network calls outside this database transaction.

Never merge accounts by email. Never silently relink an upstream subject to another local principal. Never apply upstream `roles`, `permissions`, `tenant_id`, `client_id` or `act` as Axiom authority.

Do not automatically add the person to all tenant applications. Membership is created only for the bound application under its explicit baseline policy. Argus privileged permissions are separately assigned; zero administrative roles is a valid first-login result.

### A5. Enforce external-only authentication

Keep `Principal.password_hash` and its existing constructor compatible. For a new external-only principal, store an unusable randomly generated encoded value to satisfy the current non-null schema, and make the authentication policy the explicit enforcement mechanism.

Change:

- `auth/CustomUserDetailsService.java`: reject password authentication for `EXTERNAL_ONLY` principals. This protects both form login and legacy password login, which share this service.
- `service/UserService.java` and credential mutation paths: reject converting an external-only account into a password account through an ordinary profile or password write.
- `service/RecoveryOperatorService.java`: explicitly decide eligibility for enrolling a new external-only identity as a recovery operator; default to refusing ordinary SSO enrollment into this independent recovery mechanism. Preserve already configured recovery operators and their distinct credentials.
- User/admin projections where needed: expose a safe sign-in-method indicator without exposing the random hash or source credential.

Do not create a new password reset feature for this work. Company-account recovery remains upstream. An explicit future conversion of authentication method requires its own reviewed operation.

### A6. Bind federation to session lifecycle

Change `service/IamSessionService.java`, `auth/JwtClaimsCustomizer.java`, `auth/SessionAwareIntrospectionAuthenticationProvider.java` and the existing subject/session authority checks used by token exchange and refresh.

Persist a login event and bind every new IAM authorization session produced from that login to it. Carry its trusted reference through the server-side authentication/authorization state so refresh cannot lose the source binding. Do not depend only on a thread-local value or a browser session surviving until refresh.

For newly bound federated sessions, check source active, link active, principal active and reauthentication deadline at new issuance, refresh and relevant online authority validation. Follow `subject_sid` to apply the same root-session status to derived tokens. Legacy sessions without this binding keep their existing validation path.

On source or link disable, use the existing approved identity-control apply path to mark affected bound sessions inactive and trigger the existing root-session/continuation cleanup. Extend `IdentityControlApplyService` as needed. A routine credential rotation is not automatically a reason to revoke every established session; source revision pins an in-flight login, while explicit lifecycle status controls established sessions.

Initial operation without SCIM must set a bounded maximum federated authentication age and require a fresh upstream authorization when it expires. Axiom refresh-token activity alone does not prove that the upstream account is still enabled. Provider logout events or lifecycle events can reduce this window in a later increment. Offline JWT recipients retain their bounded expiry window unless they perform online validation.

For MFA claims, preserve trusted upstream authentication evidence separately from password evidence. `JwtClaimsCustomizer.addAssurance` currently emits `amr=["pwd"]` for its recognized local details. Do not feed a federated login through that path and mislabel it as a local password login. Map supported upstream assurance values explicitly; omit unsupported assurance claims and refuse actions whose assurance requirements cannot be satisfied.

### A7. Add identity connection management and admin projections

The Argus setup screen cannot call the existing Axiom admin API with an arbitrary Argus administrator's token. Add an explicit integration boundary:

- Add a proposed Argus `identity_connection.configure` permission, checked by a tenant-scoped connection controller through the existing permission model.
- Add a separate Axiom connection-manager service identity, distinct from the agent registrar and authority publisher. Its proposed `identity-connections.configure` scope permits connection setup only inside the preauthorized tenant and template.
- Expose a narrowly matched service API, proposed as `/provisioning/v1/tenants/{tenantId}/identity-connections`, for create, validate and initial setup operations. Reuse `IdentitySourceService` validation and `SecretProtector`; do not grant this service general human-administration authority.
- Relay the upstream client secret over TLS to Axiom without retaining it in Argus persistence, request logging, tracing or returned metadata. Return a non-secret connection reference and safe test status.
- Keep admission widening, existing-source disablement and credential rotation in the existing reviewed identity-control model. The connection-manager service cannot approve its own request. Initial operator bootstrap establishes the baseline policy and the authorized configuration actors; until a trusted cross-product review contract exists, reviewed source changes remain available through the existing Axiom operator flow.
- Extend `admin/src/pages/IdentitySources.tsx` with an optional federation-policy/application-binding panel and correct its copy that currently says no principal is ever created automatically. Legacy sources must continue to show link-only behavior.
- Extend `admin/src/api/client.ts` with separate policy DTOs/methods. Include the existing backend `VALIDATED` source status in `IdentitySourceStatus`; do not conflate source lifecycle with JIT or connection-test states.

The Hub setup controller calls this service using its dedicated machine credential after checking the human permission. It never forwards a human token as a machine administrator credential. Credential storage for these infrastructure identities remains part of the operator's deployment setup.

## 6. Axiom changes for automated workload provisioning

### A8. Add a service-only composite provisioning API

Existing admin provisioning methods require administrative roles. An ordinary confidential client cannot call them merely because it obtained a token. Do not copy `platform_admin` into an Argus service token or widen the entire `/admin/**` filter.

Add a separate `ManagedIdentityProvisioningController` and domain service with a narrowly matched service security chain. Proposed resource: `/provisioning/v1/tenants/{tenantId}/managed-identities`.

Proposed operations:

| Operation | Authorized behavior |
| --- | --- |
| `POST` collection | Idempotently create the approved managed identity bundle from a public key and a stable external reference |
| `GET` individual operation/result | Read only the owning integration's operation and non-secret identity metadata |
| `POST` retirement operation | Retire only the owned client/workload after checking lifecycle prerequisites |
| `POST` key-change request | File an owned key-replacement request through the existing reviewed identity-control process |

Use proposed service scopes `managed-identities.provision`, `managed-identities.read` and `managed-identities.retire`; register them through a dedicated privileged service policy rather than the ordinary business-scope catalog or default scope set. The request must match token issuer, audience, tenant, authenticated integration client, privileged template and resource ownership. A read scope never authorizes a write.

The operator preauthorizes a template that limits application type or existing application reference, client auth method, scope ceiling, permitted gateway and issuer. For an entry agent acting for a person, select the application containing its business browser/BFF client. The registrar cannot create tenants, browser redirect URIs, trusted brokers, human users, arbitrary application roles or identities owned by another integration.

Reuse the internal domain operations behind `TenantApplicationService` and `CiamDelegationService.registerWorkload` for application/client/workload creation. The workload API has a historical CIAM path, but it provisions the existing workload identity model; this does not turn a workforce principal into a CIAM customer. Factor shared validation into internal methods with an explicit provisioning context where necessary; do not call controllers internally or impersonate a human administrator.

Record ownership and idempotency in durable `managed_identity_operations` and `managed_identity_resources` records. Bind an idempotency key to a canonical request hash and integration/tenant. The same key with a different public key, holder or template must conflict. Recover from a timeout by reading the original operation, not by blindly creating another client. Do not adopt a same-named resource unless its recorded ownership and request match.

Generate a globally unique, environment-specific client ID once per operation, persist it before retryable effects, and retain the mapping after retirement. Display names are not client IDs. Do not recycle a retired client ID or infer identity from a matching agent name.

The first managed client uses existing Axiom `private_key_jwt` support and the submitted public JWKS. Do not create a placeholder secret-authenticated client and later mutate its authentication method. Store no private key or plaintext client secret in Argus.

### A9. Provision runtime authority after approval

Creating an application, OAuth client or workload must not also grant arbitrary routes. Use a separate publisher identity and a separate authority operation for gateway entry routes and any required broker targets. Infrastructure broker registration remains operator-controlled.

The publisher is explicitly trusted to materialize an approved Argus release within an operator-configured tenant/gateway/scope ceiling. Authenticate that publisher, record the release revision and digest, reject stale revisions and apply the requested subset idempotently. A caller-supplied release ID alone is not proof of approval.

Use `AgentExchangeAuthorityService` and `TrustedBrokerTargetService` for existing route/target checks. The publisher's proposed `managed-authority.publish` service scope is separate from an agent's business scopes. The integration job must establish required Axiom authority and verify its status before Argus declares the new managed call path ready. Argus's approved release remains a required runtime gate even when Axiom authority has already been materialized.

Do not claim cross-product activation is atomically committed. Model partial delivery explicitly and fail closed. Reusing a gateway target must not let one agent inherit another agent's route or revive an old identity after retirement.

## 7. Argus changes

### G1. Add managed onboarding without changing existing registration requests

Keep `POST /v1/configure/agents` and its required `identity_mode=OWN`, issuer and client ID behavior unchanged for existing callers.

Add a separate managed-onboarding resource, proposed as `POST /v1/configure/agent-onboarding`, with a corresponding status read and public-key submission. These are proposed new endpoints. Require the same permission to edit the target draft as existing registration, plus permission to use its configured managed identity template.

Store a durable `identity_onboarding_jobs` record containing tenant, draft/holder reference, environment/gateway, requested template, public key thumbprint, request hash, Axiom operation reference, result IDs, state and safe failure reason. Bind references to the authenticated tenant; client-supplied tenant names cannot establish ownership.

Suggested states:

```text
AWAITING_KEY -> PROVISIONING -> IDENTITY_READY -> REGISTERING -> READY
                    |                              |
                  FAILED                         FAILED
```

Retries resume from the persisted step. Use a database lease/claim for worker ownership, bounded calls and backoff so multiple Control API replicas cannot run the same provisioning step concurrently. Polling exposes no tokens or private material. Cancelled jobs clean up only their own unreferenced resources. A deleted draft or conflicting identity assignment stops finalization and schedules safe compensation.

Once Axiom returns a ready identity, invoke the same transactional domain operation used by `FirstPartyAgentController.register`. Persist the agent, assign its issuer/client pair through `ClientAssignments`, add the draft boundary and complete the job exactly once. Extract a shared `AgentRegistrationService` if necessary; do not duplicate the registration algorithm or make self-HTTP calls.

An unfinished job appears as onboarding progress, not as an agent with an empty client ID in a live release. This avoids relaxing existing validators, null assumptions and runtime identity contracts.

Relevant existing Argus files:

- `components/control-plane/argus-control/image/src/main/java/ai/conduit/authoring/FirstPartyAgentController.java`
- `components/control-plane/argus-control/image/src/main/java/ai/conduit/authoring/FirstPartyAgentRepository.java`
- `components/control-plane/argus-control/image/src/main/java/ai/conduit/authoring/ClientAssignments.java`
- `components/control-plane/argus-control/image/src/main/java/ai/conduit/authoring/IssuerTrust.java`

### G2. Keep issuer and assignment constraints

Managed mode is available only when the selected gateway already trusts the intended Axiom issuer and has the required integration template. Reject an unsupported gateway before provisioning. Do not silently add another trusted issuer, alter existing gateway trust or use the non-production testing issuer in production.

Keep `identity_mode=OWN`. Store managed versus customer-supplied origin as separate metadata; do not bring back a shared Use Case identity. Allocate a separate runtime client for each caller/agent and environment under the configured template. Existing registrations are not automatically reassigned or cloned.

Use the existing client-assignment ledger as the authoritative assignment constraint. The onboarding job owns workflow progress; it is not a second assignment ledger. Reserve stable references before external effects, and enforce the final ledger claim transactionally.

### G3. Deliver the workflow in Hub and CLI

Hub changes:

- Add the company identity-connection setup surface. Only authorized administrators can configure it; first-user bootstrap still uses the established operator path.
- Extend `components/control-plane/hub/image/src/hub/components/agents/AddAgent.tsx` with **Create managed identity** and **Use an existing client** choices. Do not change the existing choice's request shape.
- Extend `AgentIdentityDrawer.tsx` and safe identity reads to show issuer, client ID, origin, provisioning status and credential-rotation status.
- Extend `src/api/authoring.ts` with typed methods for new onboarding resources. Do not place keys or tokens in status messages or error payloads.
- Keep normal Hub sign-in through `src/auth/oidc.ts`; Axiom handles the upstream redirect. Carry tenant/application selection through registered-client context, not an arbitrary issuer URL entered at login.

CLI/deployment changes:

- Extend `components/cli/internal/cmd/agents.go` and add managed-onboarding/key-helper commands backed by the same public API.
- Keep `components/cli/internal/cmd/identity.go` and the existing browser PKCE login behavior. CLI user sign-in is not an agent runtime credential.
- Generate private keys locally or use an approved existing key store; submit only the public JWK. A local helper may write a key only to the explicitly selected deployment destination with restrictive permissions. The Control API does not gain broad Kubernetes Secret-write permission.
- Extend `samples/agents/common/argus_workload_identity.py` with a `private_key_jwt` mode. Its inspected modes are `kubernetes` and `mounted-client`; preserve both paths and their current defaults. Add issuer-configured assertion audience, short expiry and a fresh assertion ID; do not substitute a Kubernetes assertion profile for registered-key authentication.
- Return discovery/issuer, client ID, audience and route configuration as non-secret deployment metadata. The helper obtains tokens at runtime and never logs them.

Public API additions must ship with the exported OpenAPI document, generated CLI bindings, Hub types and the Argus skill/help text in the same implementation change.

Advertise managed onboarding through the existing Argus capability mechanism. A disabled or unsupported stack must hide the new UI option and refuse the new API operation consistently, while the existing client-registration option remains available.

### G4. Bootstrap infrastructure and application callers

The installer/operator creates the registrar, publisher, gateway broker, Hub and CLI registrations with their distinct permissions and audiences. Ordinary agent owners cannot create or change these infrastructure identities.

The same managed provisioning domain can later onboard BFF/service callers through a dedicated caller-onboarding API. Do not treat a BFF as an agent or reuse one agent's client ID for all callers. For the first complete walkthrough, provision its BFF through the supported setup adapter so the owner is not asked to visit Axiom manually.

Upstream human admission, Axiom application membership, Argus administrative membership and agent runtime grants remain separate concepts. Argus does not need a per-Use-Case directory of end users.

## 8. Token and runtime contract

Reuse the current issuance and exchange paths. Explicitly test this contract before enabling the integration:

| Fact | Required behavior |
| --- | --- |
| Human subject | Axiom's stable local `sub`, mapped to the exact upstream identity; email is not the subject key |
| Autonomous agent | Its own registered workload/client, not the person who created it |
| Delegated work | Human `sub` remains the subject; the acting workload appears in `act` under the existing exchange rules |
| Redeeming client | Top-level `client_id` retains its existing meaning, including the broker client on broker redemption |
| Argus caller | The client selected for the current boundary must match the caller authorized by Argus; never assume upstream SSO client, broker and logical agent IDs are interchangeable |
| Audience and scope | Use registered audience and current authority ceilings; provisioning cannot widen requested scope |
| Argus context | Use Case, release and grants come from Argus's trusted state; arbitrary headers or token attributes cannot invent them |
| Downstream access | Destination must trust the issued credential and apply its business authorization |

The existing Axiom issuer remains unchanged. Do not add a new authority-bearing claim solely to bypass a mismatch between Argus caller lookup and Axiom broker exchange. Resolve any mismatch as an explicit joint contract change with its own compatibility tests.

Axiom tokens do not automatically authorize Microsoft Graph, Salesforce or every API protected by the upstream IdP. The first walkthrough should use a configured tool/API that trusts the established credential path. Provider-specific downstream credential integrations are separate work.

An existing application that already holds external IdP tokens must either start the relevant login through Axiom or use a separately implemented external-token trust/exchange profile. JIT browser sign-in does not add that profile.

### Scope types and ownership

Treat these as separate namespaces even when their string values happen to match:

| Type | Owner | Example | Meaning |
| --- | --- | --- | --- |
| Upstream OIDC claim scopes | Customer IdP | `openid profile email` | Allow Axiom to authenticate the person and obtain identity claims; they do not grant Orders API access. See [OIDC scope claims](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) |
| Upstream business permission evidence | Customer IdP and its configured application policy | A signed application-specific entitlement such as `orders:view` | An input to the explicitly trusted Axiom mapping policy; the string alone is not an Axiom permission |
| Axiom application permissions and scopes | Axiom tenant/application policy | `orders.read`, `orders.write`, `argus:invoke` | Bound what a registered client and authenticated subject can request and receive |
| Argus administrative permissions | Argus authorization model | `release.submit`, `release.approve` | Authorize management operations at the appropriate organization, Domain or Use Case scope; never infer them from a runtime scope |
| Argus runtime grants and conditions | Approved Argus release | Entry agent may call Orders API `getOrder` | Authorize a caller's operation; a token containing `orders.read` does not create this grant |
| Target scopes | Target's configured authorization contract | `orders.read` | Bound the credential issued for that target; the target still enforces resource access |
| Infrastructure service scopes | Axiom's privileged service policy | `managed-identities.provision` | Authorize integration machinery; they are never inherited from a human or runtime token |

Registering a scope, granting it to a client, requesting it and issuing it are four distinct operations. Use exact, case-sensitive matching; do not automatically lowercase, prefix-match or expand wildcard values. OAuth scope values are defined by the authorization server; a matching name from another issuer does not by itself establish equivalent authority. See [OAuth scope semantics](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3).

### Propagate authority through an explicit source mapping

Add an optional `scope_propagation_mode` to each new federation/application binding:

- `LOCAL_AUTHORITY`: the upstream connection supplies identity only. Axiom's existing local application entitlements determine business scopes. This preserves existing behavior when a mapping policy is absent.
- `UPSTREAM_CEILING`: validated upstream business permissions cap an explicit list of business scopes for this application. Missing, malformed, expired or unmapped evidence supplies no authority for that list; it never falls back to local authority.

In `UPSTREAM_CEILING` mode, configure the source issuer, upstream client/audience, exact claim name, claim shape, accepted values, target Axiom application, affected business-scope vocabulary and the approved mapping revision. For the initial implementation, use a signed application-specific claim in the validated upstream ID token whose audience includes Axiom's registered upstream client. The administrator must intentionally configure that claim as permission evidence for this integration; ID-token signature validation alone does not make every claim an authorization statement.

An example policy could accept a signed `https://identity.example.com/entitlements` array. This is an illustrative customer-defined claim name, not an OpenID standard or an existing built-in Axiom claim.

| Validated upstream evidence | Approved Axiom application role | Scope output permitted by this mapping |
| --- | --- | --- |
| `orders:view` | `orders_reader` | `orders.read` |
| `orders:refund` | `orders_refunder` | The separately approved refund scope, if that role and scope exist |
| An explicitly configured company group `orders-readers` | `orders_reader` | `orders.read`, only when this exact group claim is trusted by the binding |
| Unknown value or a value from another source | None | None |

The role must already exist in the target application, and all business permissions granted through the mapping must fit its approved output ceiling. Reject a mapping that connects `orders:view` to a role that also grants `orders.write`. An identity mapping such as upstream `orders.read` to Axiom `orders.read` is allowed only as an explicit exact-match mapping with the same source, audience and application checks.

Never copy the upstream token response's `scope` field wholesale. That access token may authorize Axiom's access to UserInfo or another resource, not the person's access to the business application. Do not decode an opaque access token, accept requested-but-ungranted scopes, forward the upstream access token to Argus, or treat an ID token as an API access token. Importing an already-issued external API token requires the separate issuer/resource validation and exchange profile described above.

### Calculate the Axiom-issued scope set

For the business scopes on an opt-in binding, define:

```text
R = business scopes requested by the downstream application
C = business scopes allowed on that registered Axiom client
V = the tenant's approved business-scope vocabulary
L = current application permissions, including approved source-managed role assignments
M = business scopes this binding declares to be capped by upstream evidence
U = current validated upstream permissions after the exact mapping into Axiom scope names

LOCAL_AUTHORITY:
    E = L

UPSTREAM_CEILING:
    E = (L minus M) union (L intersection M intersection U)

Issued business scopes = R intersection C intersection V intersection E
```

`M` is an explicit list, such as `orders.read` and `orders.write`. A baseline `argus:invoke` permission can remain a locally granted integration-entry permission outside `M`; it does not authorize reading or modifying an order. If the customer wants the upstream provider to cap entry as well, include `argus:invoke` in `M` and configure the corresponding upstream assertion/mapping.

OIDC claim scopes such as `openid`, `profile` and `email` follow their existing protocol and registered-client rules, separately from this business-permission formula. `offline_access` remains subject to the existing client-posture and session-lifecycle restrictions.

Provision only the approved source-managed role assignments supported by the current assertion. Record their ownership so a later mapping reconciliation removes only those assignments, not manually approved grants. The upstream ceiling still constrains any remaining manual grant for scopes in `M`. A valid company login with no matching business permission may complete identity-only sign-in if the application permits it; it cannot acquire the missing business scope.

Return the actual issued scopes in the OAuth response and token, using the existing scope-response handling. A request for `orders.write` does not force it into the token. Existing clients retain their existing issuance behavior; the new upstream cap applies only to explicitly enabled bindings.

### Carry scopes through agents and Argus

After Axiom issues a token, each delegated hop keeps a subset of that token's business authority:

| Hop | Scope checks |
| --- | --- |
| Business browser/BFF to entry agent | Requested scopes must fit the human token, current workforce application permissions and acting agent's registered client ceiling. Preserve the existing same-application check |
| Agent to gateway | Requested scopes must fit the agent's current subject token and active workload-to-gateway route; existing workforce/subject authority checks continue to apply |
| Gateway to target through an Axiom exchange | Requested scopes must fit the inbound token and either the applicable broker-owned target or the source's onward route, plus destination-workload ceilings where applicable |
| Argus operation decision | The authenticated caller must hold the named grant and satisfy its conditions in the live release, independently of whether its token contains the target scope |
| Target API | Validate the credential's issuer/audience/expiry, required scope and the subject's access to the specific resource |

This subset behavior is Axiom's chosen exchange profile; token exchange does not mean scope strings from arbitrary issuers become trusted automatically. [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1) defines how the requester specifies a target and scopes and the authorization server decides the issued credential.

Argus already contains `credential/DelegatedScopes.java`. For an exchange-enabled destination with its delegated-scope option enabled, it calculates:

```text
requested target scopes = release invocation scopes
                          union (verified bearer scopes intersection released accepted scopes)
```

Reuse that implementation and the existing `ConnectionRecord` delegated/accepted-scope fields. Configure exact accepted scopes per destination in the approved release. An empty accepted list propagates no optional caller scopes. Preserve the existing disabled behavior for existing connections.

For the Axiom path, the release's required invocation scopes must also be present in the inbound authority and allowed by the route/target ceiling. Their appearance in Argus's exchange request does not grant them. Reject a missing required scope before dispatch where possible, and preserve Axiom's denial of an exchange requesting scopes outside the subject token. Do not replace denied user authority with a more privileged autonomous service credential to make the call succeed.

Do not rename business scopes during an Axiom continuation: a requested new name would violate the existing subset checks. Translate trusted external names once at the ingress mapping. A target needing an external provider's different scope namespace requires an explicit separate outbound credential profile, not an implicit alias during this exchange chain.

### Worked scope example

Assume the company assertion grants `orders:view`, its approved mapping supplies `orders.read`, and the person's configured local application roles permit integration entry and order reading. The browser requests both read and write, but the upstream ceiling includes no write permission.

| Stage | Issuer and audience | Business authority |
| --- | --- | --- |
| Original company sign-in evidence | Company IdP; upstream client registered for Axiom | Signed application entitlement `orders:view`; upstream `openid profile email` scopes remain identity scopes |
| Axiom human access token | Axiom; business application's audience | `argus:invoke orders.read`; `orders.write` is omitted |
| Entry agent obtains delegated token | Axiom; the entry agent's registered audience in that application | Same human `sub`, acting workload in `act`; at most `argus:invoke orders.read` |
| Agent obtains gateway token | Axiom; configured Argus gateway audience | At most `argus:invoke orders.read`, constrained by the gateway route |
| Argus evaluates `getOrder` | Live release and caller identity | Allow only if that caller has the operation grant and its conditions pass |
| Gateway exchanges for Orders API | Axiom; Orders API audience | `orders.read` only, assuming the destination invocation/accepted scopes and Axiom target permit it |
| Agent attempts `updateOrder` | Same chain | Deny if the release lacks the operation grant; an attempted exchange for `orders.write` also fails the scope ceiling |

The gateway-entry permission is not automatically forwarded to the Orders API. The Orders API still decides which order the human subject may read. Registering `orders.write` in the catalog or on the agent client does not manufacture that permission for this human.

For an autonomous scheduled agent there is no original human permission set to propagate. Its source authority comes from its own registered client, approved standing authority where relevant, Axiom routes and Argus release. Keep that execution mode explicit; do not represent it as user-delegated access.

### Exact additions for scope propagation and freshness

The mapping path is new work. Implement these changes together:

| File or record | Required change |
| --- | --- |
| New `FederationScopeMapping` entity/service/API | Persist source/application-specific exact mappings, trusted claim shape, upstream-ceiling scope list, mode and reviewed revision |
| New `federation_scope_mappings` and `federated_entitlement_evidence` tables | Store mapping revisions and normalized effective scope sets, evidence validity, login-event linkage and owned role-assignment references; do not store bearer tokens |
| `FederatedOidcUserService` and new `FederatedEntitlementMapper` | Read only the configured validated assertion claim, normalize its typed values and apply the source/application mapping after identity validation |
| `FederatedIdentityProvisioningService` and `ApplicationAccessService` | Apply source-owned role assignments atomically, reconcile removed mappings, increment the relevant entitlement revision and make the effective ceiling available to both token claims and `decisionAuthority` |
| `JwtClaimsCustomizer.narrowToEntitlement` | Retain existing local narrowing and additionally intersect the current source ceiling for new `UPSTREAM_CEILING` sessions. Do not alter protocol scopes or unrelated clients |
| Refresh, exchange and online validation | Require non-expired evidence and the current mapping/entitlement revision. Scope removal must constrain refreshed and newly exchanged tokens; it must not be restored from an older authorization's saved claims |
| `BusinessScopeRegistry` and privileged service policy | Keep scope vocabulary separate from authority, reserve privileged service names and require explicit registration/issuance authorization for infrastructure scopes |
| Argus `ConnectionRecord`, `DelegatedScopes`, `ExtProcGrpcService` and release compilation | Reuse the existing optional propagation fields; verify release-pinned accepted scopes, required invocation scopes and the exchange request/issued-scope record. Add validation only for the newly enabled profile |
| Bootstrap/setup adapter | Register the catalog, explicit client ceilings, application-role mappings, permitted gateway routes and target ceilings in dependency order; return a non-secret manifest of the resulting IDs and scope lists |

When a new assertion or policy revision removes a source-managed entitlement, reconcile its owned assignments and update the ceiling before allowing subsequent issuance under that new state. Older evidence must not restore a revoked local/mapping generation. On refresh, re-evaluate current local authority and mapping status, but do not claim that a local refresh has rechecked the upstream account. Once upstream evidence reaches its reauthentication deadline, require fresh upstream authorization.

Source/group changes that Axiom has not received cannot be enforced immediately. The configured evidence lifetime, upstream event/synchronization path and target's online-validation behavior define the residual window. Scope propagation does not remove that lifecycle requirement.

## 9. Capability switches and schema rollout

Proposed settings, all disabled by default:

| Setting | Effect |
| --- | --- |
| `iam.federation.jit.enabled` | Permits explicitly enabled source policies to create new principals |
| `iam.federation.auto-routing.enabled` | Enables registered-client-based source routing |
| `iam.federation.scope-mapping.enabled` | Permits explicitly configured source/application mappings and upstream ceilings; absent policy preserves local authority |
| `iam.managed-identities.enabled` | Enables the new service provisioning interface |
| `authoring.managed-identities.enabled` | Exposes Argus managed onboarding on eligible gateways |

These are proposed configuration names. Add explicit validation and defaults to configuration binding; they do not currently exist.

Roll out schema expansion and compatible readers before enabling writes. New readers understand absent policy and absent session bindings as legacy behavior. New external-only principals and managed jobs must not be enabled while older serving instances can bypass their authentication policy or lifecycle checks.

Keep existing DTO constructors and strict request allowlists intact. New response metadata should use a versioned onboarding read or a dedicated detail resource where an old generated consumer cannot tolerate additions. Regenerate each supported client and test both old registration calls and new onboarding calls.

## 10. Delivery sequence and definition of done

| Increment | Changes | Acceptance gate |
| --- | --- | --- |
| 1. Compatibility foundation | Additive schema, default-off switches, admission policy model, external-only enforcement and callback mode | Existing local/federated/SCIM/CIAM flows pass unchanged with switches off |
| 2. Human SSO | Trusted client routing, JIT transaction, baseline application membership, opt-in scope mapping, Hub/CLI resume | First authorized user signs in without a pre-created principal/link; repeated login returns the same identity; mapped business scopes fit original authority |
| 3. Federation lifecycle | Durable login/session binding, refresh/exchange/introspection checks, disable and reauthentication behavior | Source/link disable and maximum authentication age behave as specified; unrelated sessions continue |
| 4. Axiom machine provisioning | Scoped registrar, template/ownership/idempotency records, public-key clients, operation reads | Registrar can provision only allowed owned resources; ordinary workloads and cross-tenant callers are denied |
| 5. Argus managed onboarding | Durable jobs, shared registration service, ledger integration, Hub/CLI/key helper | One owner action yields one distinct registered agent identity after retries and restarts |
| 6. Release and runtime integration | Reviewed authority publisher, route/target readiness, existing release delivery, delegated-scope configuration and token contract | Unreleased agent cannot call; approved call succeeds with target-specific scopes; denied call identifies the applicable decision |
| 7. Packaging and lifecycle | Setup adapters, rotation/retirement, docs and pilot walkthrough | Customer follows the documented setup with no per-user or per-agent Axiom console work |

Increments 2 and 5 are distinct demonstrations: easy human sign-in and easy agent identity creation. The full product promise requires both plus the runtime gate in increment 6.

Do not assign a delivery-date estimate before the machine provisioning authorization and joint token contract are agreed and implemented in a thin vertical slice.

## 11. Required functional and regression checks

### Existing behavior

- Existing local form login, configured legacy password endpoints and recovery operators retain their behavior.
- Existing explicit federated links work with JIT disabled. Unlinked identities still fail in link-only mode.
- Existing versioned callbacks, source-revision checks, application memberships, SCIM ownership, CIAM sign-in and existing agent registration still work.
- Existing client-credentials, code/PKCE, refresh, token exchange, introspection and logout flows retain their contract.
- An existing Argus client-ID registration produces the same composition and runtime authorization as before.

### Human onboarding

- Complete Hub and CLI browser flows against one real configured OIDC provider, not only a synthetic token fixture.
- First login creates exactly one principal/link/membership; concurrent logins, callback replay and retries leave no duplicates or partial identities.
- Disabled links, principals and memberships are not recreated or reactivated. A matching email never joins another account.
- Wrong tenant/client/source, altered state/nonce, wrong audience, wrong issuer and an unbound source all deny.
- Stable callbacks survive source credential rotation for subsequent logins; source/policy changes invalidate an already-started login.
- External-only users cannot use form login, legacy password login or ordinary credential enrollment to obtain a local password path.
- JIT users receive only configured baseline application access. Administrative and reviewer roles are not inferred from email or an arbitrary upstream claim.
- Fresh login, reused SSO session, refresh, source disable and link disable exercise the persisted federation session binding.
- In mapping mode, test an exact upstream-to-Axiom permission mapping and an explicitly approved same-name mapping. A same-named value from another issuer, audience, application or untrusted claim must not match.
- `openid profile email`, requested-but-ungranted upstream scopes and UserInfo access-token scope values cannot manufacture business permissions.
- Missing, malformed, unknown, expired or oversized permission evidence supplies no mapped authority; an enabled upstream-ceiling binding cannot fall back to broader local grants.
- A mapping to a role containing permissions beyond the approved scope output fails configuration validation. Reconciliation removes only source-owned assignments, and the ceiling still constrains manually assigned scopes in its configured list.
- Removing an upstream mapping or local entitlement narrows new issuance, refresh and exchange; an old evidence generation cannot regrant it. Unreceived upstream changes retain only the documented bounded freshness window.

### Agent onboarding

- The existing manual client path remains supported. Managed mode rejects a gateway with incompatible issuer trust before creating external resources.
- The owner registers an agent with a public key; no private key or token appears in API responses, database records, logs or UI status.
- Duplicate requests, Axiom timeouts, worker restart, cancellation and final ledger conflicts result in one owned identity or explicit compensation.
- A normal workload client, read-only registrar, another tenant and another integration cannot provision or retire these resources.
- Provisioning alone enables no tool/model access. Stale release publication and unsigned release labels do not establish authority.
- Autonomous and delegated calls preserve the expected subject, actor, redeeming client, audience and scope at each boundary. Include a gateway-broker redemption in this check.
- A human business token can delegate to its entry workload in the same Axiom application. An Argus management token from a different application is refused; the integration must not weaken that existing check.
- Registering a privileged service scope in an ordinary business catalog, omitting the client scope list, or asking for a service scope from a runtime client never grants provisioning authority.
- A destination receives only its invocation/accepted scopes that Axiom allows. Missing required invocation scope, an unapproved extra scope or an absent Argus operation grant prevents dispatch. No service-credential fallback bypasses the user's scope ceiling.
- Key rotation retains the approved overlap behavior; old keys cease working at the defined boundary. Retirement prevents new issuance and follows the existing revocation model.

### Completion evidence

Run the Axiom build and relevant security/integration suites, Argus Control API functional validation, API contract gates, CLI tests and Hub build. Then run the complete customer walkthrough on an isolated installation with one real upstream connection. Record the build revisions, configuration switches, case results and remaining expiry windows without retaining bearer tokens or private credentials.

The implementation is complete only when the old paths and the new walkthrough pass together. Unit tests alone do not establish a working customer integration.

## 12. Rollback and failure behavior

| Situation | Required response |
| --- | --- |
| JIT provisioning fails | Fail the login without committing a partial identity; retry safely |
| Upstream IdP unavailable | Report sign-in unavailable for that connection; do not silently offer a password bypass for external-only accounts |
| Axiom unavailable during managed provisioning | Keep the job pending/failed with a safe retry; existing agents retain their current identity and release |
| Argus finalization fails after Axiom provisioning | Retain the owned operation reference; resume or retire only that job's unused resources |
| Authority publication incomplete | Keep the new path not ready; do not advertise a successful first call |
| Wrong configuration enabled | Disable new onboarding writes for the affected connection/template; preserve records and correct configuration |

For a rollout rollback, disable new JIT and managed-onboarding creation first. Existing external-only users still need the federation reader, authentication-policy enforcement and lifecycle validators. Existing managed agents still need their published authority until deliberately withdrawn. Therefore switching a creation flag off must not silently disable their read/runtime validation path.

Retain additive tables and identifiers. Do not delete principals, drop schema or turn an external-only principal into a local-password principal to roll back. Do not downgrade serving instances to a binary that ignores external-only or source lifecycle rules. If such a downgrade is unavoidable, first fence affected logins/issuance, revoke their sessions through supported lifecycle operations and establish a supported recovery path.

Withdraw affected runtime authority through the existing approved release/lifecycle process before retiring managed identities that are in use. Publish and verify readiness checks for restored configuration before reopening onboarding.

## 13. Customer promise and remaining setup

The customer-facing promise after the acceptance gates pass is:

> Connect your company identity provider once. People sign in with their existing accounts, and agents receive their own identities during Argus onboarding. Approve the access they need and see the resulting governed calls.

The customer still authorizes the company SSO connection, assigns who may use it, supplies a deployment credential destination and approves agent access. SCIM is optional for initial sign-in. Immediate upstream offboarding requires a supported event/synchronization mechanism; otherwise the configured reauthentication and token-expiry windows apply.

Measure time to first successful company login, time to first registered agent identity, time to first approved governed call and the number of manual identity-administration steps. Do not promise a particular integration time before measuring the packaged walkthrough.

## 14. Source references

### Axiom

- [Federated identity resolver](../../server/src/main/java/com/openwolf/iam/federation/FederatedIdentityResolver.java)
- [Federated user service](../../server/src/main/java/com/openwolf/iam/federation/FederatedOidcUserService.java)
- [Dynamic source registrations](../../server/src/main/java/com/openwolf/iam/federation/IdentitySourceClientRegistrationRepository.java)
- [Source management service](../../server/src/main/java/com/openwolf/iam/service/IdentitySourceService.java)
- [Application access service](../../server/src/main/java/com/openwolf/iam/service/ApplicationAccessService.java)
- [Tenant business scope registration](../../server/src/main/java/com/openwolf/iam/controller/TenantBusinessScopeController.java)
- [Business scope vocabulary](../../server/src/main/java/com/openwolf/iam/auth/BusinessScopeRegistry.java)
- [Password authentication loader](../../server/src/main/java/com/openwolf/iam/auth/CustomUserDetailsService.java)
- [Token customizer](../../server/src/main/java/com/openwolf/iam/auth/JwtClaimsCustomizer.java)
- [IAM sessions](../../server/src/main/java/com/openwolf/iam/service/IamSessionService.java)
- [Security configuration](../../server/src/main/java/com/openwolf/iam/config/SecurityConfig.java)
- [Application and client provisioning](../../server/src/main/java/com/openwolf/iam/service/TenantApplicationService.java)
- [Workload registration](../../server/src/main/java/com/openwolf/iam/service/CiamDelegationService.java)
- [Exchange authority](../../server/src/main/java/com/openwolf/iam/service/AgentExchangeAuthorityService.java)
- [Broker targets](../../server/src/main/java/com/openwolf/iam/service/TrustedBrokerTargetService.java)
- [Delegation semantics](axiom-token-delegation-chain.md)
- [Consumer identity contract](axiom-consumer-identity-contract.md)
- [Operator authentication inventory](../operations/phase-0.6-operator-login-inventory.md)

### Argus

- [Current agent-registration controller](/Users/srirajkadimisetty/projects/control-plane/components/control-plane/argus-control/image/src/main/java/ai/conduit/authoring/FirstPartyAgentController.java)
- [Client assignment ledger](/Users/srirajkadimisetty/projects/control-plane/components/control-plane/argus-control/image/src/main/java/ai/conduit/authoring/ClientAssignments.java)
- [Issuer trust](/Users/srirajkadimisetty/projects/control-plane/components/control-plane/argus-control/image/src/main/java/ai/conduit/authoring/IssuerTrust.java)
- [Agent creation UI](/Users/srirajkadimisetty/projects/control-plane/components/control-plane/hub/image/src/hub/components/agents/AddAgent.tsx)
- [Identity change UI](/Users/srirajkadimisetty/projects/control-plane/components/control-plane/hub/image/src/hub/components/agents/AgentIdentityDrawer.tsx)
- [CLI browser login](/Users/srirajkadimisetty/projects/control-plane/components/cli/internal/cmd/identity.go)
- [Superseded identity-issuance design](/Users/srirajkadimisetty/projects/control-plane/architecture/build/AGENT-IDENTITY-ISSUANCE.md)
- [Caller identity decision](/Users/srirajkadimisetty/projects/control-plane/architecture/decisions/D20-caller-identity-client-only.md)
- [Delegated scope selection](/Users/srirajkadimisetty/projects/control-plane/components/data-plane/argus-ext-decision/image/src/main/java/ai/conduit/argus/decision/credential/DelegatedScopes.java)
- [Destination scope settings](/Users/srirajkadimisetty/projects/control-plane/components/data-plane/argus-ext-decision/image/src/main/java/ai/conduit/argus/decision/records/ConnectionRecord.java)
- [Runtime exchange integration](/Users/srirajkadimisetty/projects/control-plane/components/data-plane/argus-ext-decision/image/src/main/java/ai/conduit/argus/decision/api/ExtProcGrpcService.java)

The working trees contain existing local changes. Implement against the reviewed working-tree state and do not overwrite unrelated edits. The proposed additions above are not evidence that the features are deployed.
