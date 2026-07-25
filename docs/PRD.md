# Axiom Identity Platform — Product Requirements Document

**Status:** Approved product direction; incremental delivery  
**Version:** 1.0  
**Date:** 2026-07-24  
**Product:** Axiom  
**Reference customer profile:** Meridian

## 1. Product statement

Axiom is a customer-deployed identity and platform-authorization control plane that gives many
applications one stable identity contract. It federates a customer's existing OIDC identity provider,
maintains application access, issues application-bound tokens, synchronizes workforce identities and
Groups through SCIM, and evaluates platform authorization without forcing every application to build
its own identity system.

Axiom does not replace the customer's workforce identity provider. It is the stable identity and
authorization layer between that provider and the customer's applications.

## 2. Customer problem

Enterprises operate many applications across business lines. Each application commonly reimplements:

- enterprise SSO integration;
- user, Group and role synchronization;
- OAuth client and service-principal management;
- token validation and signing-key rollover;
- application access and attribute propagation;
- authorization policy lifecycle;
- session, secret and access revocation; and
- identity audit.

These implementations drift, create inconsistent security boundaries and make application onboarding
slow. Axiom centralizes the common identity capabilities while keeping each application's domain
authorization model separate.

## 3. Product boundary

### Axiom owns

- one customer organization per deployment;
- workforce and service identities;
- upstream customer OIDC federation;
- OIDC issuer, discovery, authorization, token and JWKS endpoints;
- applications, browser/service clients and resource audiences;
- application memberships, roles and typed authorization attributes;
- SCIM Users, Groups and direct memberships;
- signing keys, client/SCIM secrets, sessions and revocation;
- platform-authorization policy lifecycle and Cerbos evaluation;
- immutable entitlement/configuration revisions and audit; and
- Axiom Admin.

### Applications own

- their business objects, workflows and decisions;
- their application-specific roles/attributes and assignment intent;
- their own idempotent Axiom provisioning adapters; and
- their own domain reference/demo data.

Probata is the first consumer. Probata continues to own Agent governance, evidence, assurance and
contextual clearance.

## 4. Deployment model

- One customer organization is served by one Axiom deployment and database.
- Many applications and business lines may share that customer deployment.
- The reference deployment represents the customer **Meridian**.
- Probata, orchestration, control-plane and future Wealth applications register as independent
  applications within Meridian.
- Additional example customers are separate selectable seed profiles and separate deployments; they
  are never co-loaded as unrelated tenants in one production identity database.
- Local development uses standalone Docker Compose with explicit configurable host ports.
- Helm charts and Kubernetes operating profiles follow after the Compose contract is proven.

## 5. Personas

- **Platform administrator** — owns tenant bootstrap, applications, clients, keys and recovery.
- **Identity administrator** — manages users, Groups, memberships and directory synchronization.
- **Application administrator** — manages access only for assigned applications.
- **Security approver** — independently approves high-risk identity/policy changes.
- **Auditor** — reads identity, access, session, key and policy history without mutation rights.
- **Application developer/operator** — registers approved clients and integrates through OIDC.
- **Workforce user** — signs in through the customer's IdP and accesses assigned applications.

## 6. Core journeys

### 6.1 Bring a customer deployment online

1. Start the standalone Axiom Compose.
2. Run schema-only Flyway migrations.
3. Execute the first-tenant bootstrap for Meridian.
4. Run the idempotent Meridian directory seed.
5. Configure Meridian's upstream OIDC provider.
6. Confirm issuer discovery, JWKS, Admin UI, health and audit.

### 6.2 Add an application

1. The application provisioner registers its application.
2. It creates approved browser and/or service clients.
3. It declares its resource audience, scopes, roles and typed attributes.
4. It assigns selected Meridian identities or Groups.
5. The user signs in once through Meridian's customer IdP.
6. Axiom issues a token containing only that application's access.

### 6.3 Synchronize the directory

1. Meridian's directory calls Axiom's tenant-bound SCIM endpoint.
2. Axiom creates/updates/deactivates Users and Groups idempotently.
3. Direct Group membership changes are reconciled.
4. Application access changes only where an approved mapping exists.
5. Ambiguous or rejected records appear in an actionable reconciliation report.

### 6.4 Revoke access

1. An administrator, SCIM source or approved application removes access.
2. Axiom increments the exact entitlement revision.
3. Refresh/session/live-context boundaries deny the removed access.
4. Audit identifies source, actor, subject, application and revision.

## 7. Functional requirements

### Identity and directory

- Durable tenant-scoped users, service principals, Groups and direct memberships.
- Immutable external identity links keyed by provider, issuer and subject.
- Inbound SCIM 2.0 Users and Groups with discovery, filtering, pagination, PUT/PATCH and deactivate.
- Explicit source-of-record and conflict behavior for SCIM-managed fields.

### Applications and access

- Durable Tenant → Application → Client hierarchy.
- Public browser clients: Authorization Code with mandatory S256 PKCE and exact redirects.
- Confidential service clients: approved scopes and one persisted resource audience.
- Application-scoped memberships, roles and typed attributes.
- No cross-application or cross-tenant entitlement leakage.

### Enterprise SSO

- Operator-managed upstream OIDC providers.
- Exact issuer/discovery/JWKS validation.
- Exact `(issuer, subject)` linking; email is never an authorization identity.
- Axiom remains the stable issuer trusted by applications.
- SAML is not supported.

### Application access authorization

- Versioned application-owned resource/action/attribute vocabulary.
- PostgreSQL-backed draft, review, approval and activation lifecycle.
- Cerbos PostgreSQL runtime store and bounded publication/reload.
- Default-deny generic batch decisions with exact tenant/application/revision binding.

#### Application-access decision v1

`POST /api/v1/platform-authz/decisions` is a service-only, versioned (`1.0`) bounded batch contract.
The authenticated confidential client's persisted tenant and application binding is authoritative; a
caller cannot select another application. v1 evaluates only active application membership, assigned
application-role permissions and the neutral membership `scopes` map. Each permission persists one
closed effect: `allow`, `read`, `scoped`, or `cosign`; absent permission denies. `scoped` requires an
applicable matching neutral scope for every configured scope key. The response uses the frozen
decision tuple (`permit`/`deny`/`require_cosign`) with deterministic entitlement and
application-access-policy revisions. This is not Axiom-admin Cerbos Policy Studio evaluation and
does not accept consuming-product governance concepts.

## 7.1 Policy-plane boundary

Axiom and its consuming applications have two different policy responsibilities. They do not share a
policy bundle or a Cerbos store.

### Axiom application access policy

This policy answers:

> May this identity perform this application action on this application resource?

For Probata, examples include:

- may Daniel approve an access request in the Banking domain;
- may Riya view this governed Agent;
- may Lena administer Probata application assignments; and
- may this Probata service client call the subject-context API.

The consuming application registers a versioned access vocabulary with Axiom:

- application identifier;
- resource kinds;
- actions;
- typed resource and principal attributes;
- application roles and assignment mappings; and
- the audience/scopes needed by its clients.

Axiom owns the access-policy draft, review, approval, activation, evaluation and audit lifecycle.
Every access decision is bound to the customer organization, application, principal, resource,
action, entitlement revision and access-policy revision.

### Consuming-application domain policy

The consuming application owns every policy that decides its business or product outcome. For
Probata, this is the governance control pack that answers:

> Is this Agent cleared for this exact use case, deployment and environment, based on the required
> evidence and controls?

Probata owns those governance control packs, evidence requirements, thresholds, contextual-clearance
logic, policy lifecycle, governance Cerbos runtime and audit evidence. Axiom must not store, publish,
evaluate or interpret them.

### Cross-boundary contract

The only runtime link is trusted identity and access authorization:

1. Axiom authenticates or federates the user and establishes the stable principal.
2. Probata asks Axiom whether that principal may perform an exact Probata action on an exact resource.
3. Axiom returns an allow/deny decision with decision, entitlement and access-policy revisions.
4. If allowed, Probata performs the action and independently applies its own governance policies.
5. Both products retain the shared correlation/decision identifier in their separate audit records.

No policy YAML, policy pack, governance verdict or evidence threshold crosses this boundary.

### Application resource ownership and scoped roles

The consuming application remains the source of truth for its business resources. Axiom stores only
the identity/access relationships required to authorize operations on those resources.

For Probata:

- Probata owns Domain, Use Case, Agent and workflow records.
- Probata registers application roles such as `domain_steward` and actions such as
  `manage_domain` with Axiom.
- Axiom owns the assignment that connects a principal or identity Group to that application role and
  resource scope, for example `Daniel → domain_steward → domain:banking`.
- Axiom's generic access policy compares the requested resource's stable `domain_id` with the
  principal's active scoped grants. Customer/domain names are never hardcoded in policy.
- Creating a new Probata Domain does not generate a new policy. It creates a Domain in Probata and,
  when an owner is designated, an idempotent scoped assignment in Axiom.
- Probata treats authorization setup as pending and fails closed until Axiom confirms the assignment.
- Axiom emits an entitlement-revision event when an assignment changes; Probata invalidates any
  authorization cache for the affected principal/resource.

The two products retain correlated audit evidence:

- Probata records the business mutation and requested owner.
- Axiom records the assignment mutation, actor, source application and entitlement revision.
- Both records carry the same idempotency/correlation identifier.

### Operations

- Restart-safe signing identity and governed key rollover.
- One-time, hashed client and SCIM secrets with rotation/revocation.
- Session inventory and revocation.
- Strongly authenticated, audited break-glass operation for upstream IdP outage.
- Health/readiness for database, issuer, keys, OAuth state, SCIM, federation, policy and audit.
- Backup/restore proof.

## 8. Meridian reference profile

The Axiom-owned `meridian` seed demonstrates the identity product without embedding any application:

- 1 organization: Meridian;
- 1 bootstrap platform administrator;
- 48 realistic workforce identities;
- 10 typed identity Groups spanning platform operations, identity operations, Banking, Wealth,
  Financial Crime, Risk, Audit and executive oversight;
- direct Group memberships, including a few multi-Group users;
- active, invited and deactivated lifecycle examples;
- stable external IDs suitable for later SCIM replay; and
- no Probata, orchestration, Agent, use-case or application-role data.

The same logical fixture has two adapters:

1. supported Axiom service/API seed for the first release; and
2. inbound SCIM replay after AXP-4.

Both adapters must converge to the same identity and Group state.

## 9. Seed and migration rules

- Flyway contains schema, constraints and indexes only.
- No user, Group, tenant, application, role, policy or demo row is inserted by Flyway.
- Seeds never use direct SQL.
- Seed profiles are explicit, idempotent and safe to replay.
- Secrets and signing keys are supplied/generated at runtime and never stored in seed manifests.
- A seed reports created, updated, unchanged, rejected and deactivated counts.
- Production startup never runs a reference seed implicitly.

## 10. First release acceptance

The first release is accepted when:

1. Axiom builds and starts from its standalone repository and Compose.
2. Meridian can be bootstrapped and seeded twice without duplicates.
3. OIDC discovery and JWKS expose the configured immutable issuer.
4. Probata registers itself as the first ordinary application.
5. a Meridian user signs into Probata through Axiom.
6. a Probata service client receives only its registered tenant/audience/scopes.
7. the same identity can receive different access in a second sample application.
8. user/membership disablement fails closed at the live boundary.
9. restart preserves identities, clients, signing identity, sessions, policy revision and audit.
10. the Axiom image builds without UAC in its build context.
11. Axiom contains no Probata governance policy, evidence threshold, clearance rule or Probata-named
    grounding adapter.
12. Probata access authorization and Probata Agent-governance evaluation use different policy stores,
    Cerbos runtimes, revisions and audit records.

## 11. Deferred requirements

- token exchange/on-behalf-of;
- Device Authorization Grant;
- SDKs, CLI and Terraform provider;
- advanced access-request approval, expiry and recurring review;
- outbound SCIM;
- Helm and Kubernetes deployment profiles; and
- SAML permanently unless the product direction is explicitly reopened.

## 12. Success measures

- a new application integrates without Axiom source-code changes;
- one customer IdP change does not require changes in connected applications;
- directory disablement becomes effective and auditable within the agreed live-context window;
- every token and authorization decision is attributable to exact application and entitlement
  revision; and
- clean startup, seed, restart and restore are repeatable operator procedures.
