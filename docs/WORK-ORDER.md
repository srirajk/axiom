# Axiom Multi-Application Identity — Product Capability Work Order

**Status:** Accepted north star; incremental implementation  
**Last updated:** 2026-07-24  
**Product boundary:** Axiom identity and platform authorization  
**First consumer:** Probata  
**Primary outcome:** one Axiom deployment can securely serve multiple applications without adding
application-specific Java code.

**Normative companion:** [OIDC-CONTRACT.md](OIDC-CONTRACT.md). The companion is part of this work
order, not optional guidance.

## 0. Delivery boundary

### Build now — first reusable Axiom release

- AXP-0 standalone repository extraction without breaking Probata compatibility.
- A standalone Docker Compose that exposes explicit host endpoints for local integration and owns its
  Java build toolchain. Helm/Kubernetes packaging follows after the Compose contract is stable.
- Close and runtime-prove AXP-1 application/client registration.
- AXP-2 safe core: application membership, application-scoped roles/attributes, assignment source,
  assigning actor and audit timestamp.
- AXP-3 customer OIDC federation with exact `(issuer, subject)` identity linking.
- AXP-4 inbound SCIM Users, Groups and direct memberships.
- Essential AXP-5 controls: restart-safe keys, secret/session revocation, health and recovery.
- AXP-7 PostgreSQL policy source and Cerbos PostgreSQL runtime.

### Explicitly deferred — next production-hardening increment

- Advanced access-governance workflow: business reason, independent approval, start/end time,
  recurring access review and recertification.
- Outbound SCIM connectors and advanced directory reconciliation.
- AXP-8 token exchange/on-behalf-of, Device Authorization Grant, SDKs, example integrations, CLI and
  Terraform automation.

Deferral does not permit insecure placeholders. The first release must still fail closed, keep
application access isolated, record assignment provenance, and produce complete audit evidence.

## 1. Product decision

Axiom is a reusable identity and platform-authorization product. Probata is one application registered
with Axiom; it is not a special identity mode.

Two policy planes are intentionally separate:

| Plane | Question answered | Owner | Runtime |
|---|---|---|---|
| **Application access authorization** | May this identity perform this action on this application resource? | Axiom, from a vocabulary registered by the consuming application | Axiom access-policy store and Axiom Cerbos |
| **Product/domain governance** | Does this business object meet the consuming product's rules? | The consuming application | The application's own policy store and decision runtime |

For Probata, the second plane is Agent governance: evidence requirements, control packs, thresholds and
the exact Agent × use case × deployment clearance verdict. Those records and policies remain entirely
inside Probata. Axiom receives neither the governance bundle nor its evidence.

The cross-boundary contract is limited to:

1. Axiom stable principal identity and application membership;
2. a Probata-registered access vocabulary (resource kinds, actions and typed authorization attributes);
3. a bounded access decision request from Probata to Axiom;
4. an allow/deny response carrying exact entitlement and access-policy revisions; and
5. a shared correlation/decision identifier recorded in both products' separate audit trails.

The unqualified term `policy bundle` is prohibited in product contracts. Use **Axiom application
access policy set** or **Probata governance control pack**.

### Resource ownership synchronization

Consuming applications own their business-resource records; Axiom owns the access assignments that
authorize identities to operate those records.

For a Probata Domain:

1. Probata creates the Domain in its own system of record.
2. Probata registers or reuses its versioned Axiom access vocabulary:
   `resource=domain`, `role=domain_steward`, `action=manage_domain`, typed attribute `domain_id`.
3. Designating an owner sends an idempotent scoped-assignment command to Axiom:
   `(application=probata, principal/group, role=domain_steward, resource_scope=domain:<stable-id>)`.
4. Axiom persists and audits the assignment, increments the application entitlement revision and
   returns an immutable receipt.
5. Probata stores only the external assignment reference/receipt and remains fail-closed until the
   assignment is confirmed.
6. Axiom emits revocation/change events so Probata invalidates authorization caches.

The generic access-policy expression compares typed attributes. It never contains customer-specific
domain names, use-case names, Agent identifiers or seed values.

The production isolation model is **one customer organization per Axiom deployment, with many
applications inside that deployment**. A deployment retains one immutable organization/tenant
identifier in records, tokens and audit evidence, but it does not serve unrelated customers from one
shared database. A future management plane may provision separate Axiom deployments; it does not turn
the identity data plane into a shared multi-tenant runtime.

The stable hierarchy is:

```text
Tenant
├── Workforce identities
├── External identity providers
├── Applications
│   ├── Browser clients
│   ├── Service clients
│   ├── Memberships
│   ├── Role assignments
│   └── Attribute grants
└── Audit and entitlement revisions
```

- A **Tenant** is the customer isolation boundary.
- In production, the deployment contains exactly one active Tenant/Organization. Development fixtures
  may exercise multiple identifiers, but multi-customer serving is not a product mode.
- An **Application** is the authorization and token boundary for one product.
- A **Client** is one OAuth/OIDC entry point for an application.
- A **Principal** is a reusable tenant identity.
- A **Membership** connects a principal to an application.
- A **Role assignment** and **attribute grant** are application-scoped unless explicitly declared
  tenant-wide.

Probata terms such as `Steward`, `Banking`, and `loanmemo` are application data. Axiom may validate,
store, version, and evaluate them, but must not compile them into its product code.

### Seed ownership

- Axiom owns organization bootstrap and directory-reference data: tenant, platform administrator,
  workforce users, identity Groups and direct group memberships.
- Each consuming application owns its registration and application-specific roles, attributes,
  memberships and reference personas. Probata therefore provisions Probata into Axiom through the
  supported Axiom API; Axiom's own seed contains no Probata application data.
- Reference customer profiles are mutually exclusive. `meridian` is the default profile. Additional
  example customers may be offered as alternative profiles, but one clean Axiom deployment loads
  exactly one customer organization.
- The directory fixture is shaped like SCIM data and will use inbound SCIM once AXP-4 is available.
  Until then it must enter through the same Axiom services/APIs, never direct SQL.

## 2. Current product truth

### Already real

- tenant-scoped principals, roles, groups and audit;
- Authorization Code with S256 PKCE for public browser clients;
- client credentials for confidential service clients;
- persistent OAuth authorization/session state;
- persistent RS256 signing identity and JWKS;
- tenant provisioning and fail-closed tenant resolution;
- live subject context for Probata;
- Axiom Admin surfaces for users, teams, roles, platform policy and audit; and
- isolated platform-policy lifecycle and Cerbos runtime.

### Product gaps

1. OAuth clients are durable, but required clients and their security posture are created in
   `SecurityConfig` using the names `axiom-admin`, `probata-spa`, and `probata-api`.
2. There is no first-class persisted Tenant → Application → Client relationship.
3. Client audience, service tenant, permitted scopes and public/confidential posture are partly
   expressed in code and deployment properties rather than one authoritative record.
4. PKCE enforcement contains a compiled set of browser client identifiers.
5. token audience and machine-caller validation contain Probata-specific branches.
6. tenant roles and attributes are not yet cleanly scoped to an application membership.
7. Axiom Admin cannot register or disable an application, manage its clients, rotate a service secret,
   or inspect which identities have access to it.
8. customer OIDC federation and immutable `(issuer, subject)` identity links are specified but not yet
   a complete operator-managed product capability.
9. SCIM user/group provisioning is not yet a product capability.
10. signing identity is restart-safe, but a governed signing-key rotation lifecycle and overlap window
    remain to be productized.
11. the current Teams/Groups/Domains projection is ambiguous: identity group membership, business-domain
    assignment and a free-form user `team` attribute are not yet one typed model.
12. role presentation does not clearly separate Axiom platform roles, application roles and attributes;
    identity administration must not present a generic `clearance_required` field as application access.
13. identity mutation authorization is partly expressed in the global security chain. New application,
    client, federation and assignment controllers require explicit method-level authorization and tests.
14. inbound directory synchronization and downstream application provisioning are not yet separate,
    first-class capabilities.
15. the platform-policy authoring lifecycle is durable, but the Cerbos runtime must no longer depend on
    a filesystem policy repository.

## 3. Non-negotiable security invariants

1. No open dynamic client registration endpoint.
2. Client creation and updates require an authorized tenant administrator and are audited.
3. Public clients have no secret and require Authorization Code + S256 PKCE.
4. Confidential clients use client credentials only when explicitly enabled.
5. Redirect and post-logout URIs are exact allowlisted HTTPS URIs in production.
6. A client belongs to exactly one application and tenant.
7. A token audience is derived from the registered client/application, never caller input.
8. A service client is tenant-bound in persisted authority, never by a request parameter or fallback.
9. Service secrets are shown once, stored only as strong hashes, rotatable, and never returned again.
10. A principal receives only the roles and attributes authorized for the requesting application.
11. Disabled tenant/application/client/principal states fail closed immediately.
12. Cross-tenant application, client, membership, secret and audit reads are non-disclosing.
13. Unknown scope, audience, redirect URI, client posture or application membership denies.
14. Every material change increments an entitlement/configuration revision and creates an audit record.
15. Probata governance policies, evidence requirements, thresholds and contextual-clearance semantics
    never move into Axiom. Axiom access-policy records never move into Probata.
16. Identity **Groups** and application assignments are first-class relationships. Business **Domains**
    are typed authorization attributes, not aliases for a group row or free-form `team` text.
17. Flyway owns database structure only. Baseline identities, roles, applications and policies are
    created idempotently through supported Axiom service/API seed paths, never data-bearing Flyway
    migrations or direct SQL inserts.
18. PostgreSQL is the durable source for policy authoring and the Cerbos runtime store. Filesystem policy
    directories are development/import artifacts only, never production truth.

## 4. Dependency-safe delivery

### AXP-0 — Standalone product extraction

**Outcome:** Axiom has one independent source repository and UAC consumes it as a versioned product.

- Create `/Users/srirajkadimisetty/projects/axiom` as Axiom's source of truth.
- Bring the Spring service, Axiom Admin, generic platform-policy package, migrations, deployment
  templates and generic tests.
- Keep UAC/Probata seed runners, demo fixtures and consumer-specific compose wiring with UAC.
- Replace `probata-spa`, `probata-api`, Probata audience fallbacks and Probata-only subject-context
  branches with ordinary application/client records and versioned generic contracts.
- Remove `ProbataPlatformGroundingProvider`, every `probata-platform-contract` schema identity and
  every Probata-named policy fixture from the standalone product. Replace them with an
  application-registered access vocabulary.
- Preserve issuer, discovery, JWKS and existing Probata compatibility until the external image passes
  parity.
- Add an Axiom-owned Compose with explicit, configurable host ports for the issuer/API, Admin UI,
  PostgreSQL, Redis and platform Cerbos endpoints. Published infrastructure ports are local-integration
  conveniences, not the future Kubernetes exposure model.
- Add an idempotent Axiom seed command with a Meridian reference profile containing realistic
  workforce identities, Groups and memberships, with no application-specific Probata records.
- Publish immutable image versions and pin consumers by version/digest.
- Do not delete the embedded copy until Probata and a second application pass against the standalone
  image.

**Acceptance**

- Standalone Axiom builds and starts without the UAC repository in its build context.
- `docker compose up` from the standalone repository builds with the pinned container toolchain and
  exposes every documented local endpoint on its configured host port.
- a clean Flyway migration has no reference data; the Meridian seed can be applied twice without
  duplicates and reports exact created/unchanged counts.
- No runtime class or configuration contains a required Probata-specific client, tenant, audience or
  claim branch.
- No Axiom artifact contains a Probata governance control pack, evidence threshold, clearance rule or
  governance-Cerbos dependency.
- UAC consumes the standalone image and passes OIDC login plus machine-token/live-context journeys.
- A second generic sample application completes browser PKCE and service-client flows.
- Extraction provenance and the replacement image/SBOM pin are auditable.

### AXP-1 — Application and client registry

**Outcome:** an administrator can register a second application without changing Java code.

- Add a tenant-scoped `Application` aggregate with key, display name, description, state and revision.
- Add application-owned client metadata that references Spring Authorization Server's durable
  registered-client record.
- Support:
  - public browser client;
  - confidential service client; and
  - explicit resource/audience identity.
- Replace tenant-application entries in the compiled client list with a bootstrap/provisioning path
  that uses the same application service as normal administration.
- Derive PKCE posture, audience, permitted grant types, scopes and tenant binding from persisted
  authority.
- Provision `Probata` as an ordinary application record in the reference environment.
- Retain `Axiom Admin` as a deployment-owned system client. It manages Axiom itself and must not be
  assignable, disableable, or re-owned through a tenant application API.
- Require explicit method-level authorization for every application/client lifecycle mutation.

**Acceptance**

- Register `sample-portal` with a browser and service client through the service/API.
- Complete S256 login for the browser client.
- Mint a tenant-bound service token for the service client.
- Reject wrong redirect, missing/plain PKCE, wrong secret, unapproved scope, wrong audience,
  cross-tenant access and disabled application/client.
- Restart Axiom and prove both clients and active sessions remain valid.
- Show the application, clients, state and last change in Axiom Admin.
- Show every create/update/disable/secret-rotation event in tenant audit.

### AXP-2 — Application access model

**Outcome:** the same person can have different access in different applications.

- Add application memberships.
- Add application-scoped role definitions and assignments.
- Add application-owned attribute schema and grants.
- Add application-resource scoped assignments with stable opaque resource identifiers and typed
  scope attributes.
- In the first release, record assignment source, assigning actor and audit timestamp.
- In the production-hardening increment, add business owner/reason, independent approver, effective
  time, expiry and recurring review state.
- Support direct and group-derived access without losing provenance; removal of either source is
  deterministic and auditable.
- Defer time-bound access and access-review/recertification to the production-hardening increment;
  these remain identity-access controls and must not move product-governance decisions into Axiom.
- Reconcile identity Groups, group membership and business-domain attributes into distinct typed
  relationships; do not preserve `team` as an authorization source.
- Resolve user and service subject context using `(tenant, application, principal)`.
- Provide idempotent assignment commands and immutable receipts suitable for a consuming
  application's transactional-outbox relay.
- Keep explicitly declared tenant-wide administrative roles separate from application roles.
- Emit an application-specific entitlement revision.

**Acceptance**

- The same principal is an administrator in one application and a viewer in another.
- A role or attribute from application A never appears in application B's token or live context.
- Disable membership and demonstrate revocation without waiting for the original access token to expire.
- Expire or revoke a time-bound/group-derived assignment and prove its exact downstream entitlement
  revision changes.
- Create a new application resource in a consumer, assign an owner, and prove it remains inaccessible
  until Axiom confirms the scoped assignment.

### AXP-3 — Enterprise OIDC federation

**Outcome:** each tenant can connect its customer workforce identity provider without changing Axiom.

- Operator-managed OIDC federation only.
- Exact external identity links by `(issuer, subject)`, never email.
- Explicit account-link approval; no default JIT grant.
- Provider discovery/JWKS validation, issuer pinning, allowed claims and authentication-policy state.
- Axiom remains the stable issuer seen by applications.
- SAML is explicitly outside the product scope. Unsupported federation protocols fail closed rather
  than appearing as partially configured providers.
- Make source-of-record mode explicit per organization: externally managed identities cannot be
  silently edited locally.
- Support optional, explicitly approved JIT identity linking without granting application access.

**Acceptance**

- Link one external user, sign in through the customer IdP, and receive the same Axiom principal.
- Unknown, duplicate, inactive, email-only, wrong-issuer and cross-tenant links deny without disclosure.
- Validate discovery metadata, exact issuer, JWKS key identity, signature algorithm, token audience,
  nonce, timestamps and authentication context before linking the upstream session.
- Treat the upstream provider as deployment-owned customer configuration: a Meridian deployment may
  federate to Meridian's Entra/Okta-compatible OIDC issuer while a different customer deployment uses
  its own issuer, without changing application integrations.

### AXP-4 — Lifecycle provisioning

**Outcome:** enterprise directories can provision identities and groups consistently.

- Standards-conformant inbound SCIM 2.0 Users and Groups endpoints, including discovery resources,
  filtering, pagination, create, replace, PATCH, deactivate and direct group membership.
- tenant-bound bearer credentials with rotation and audit;
- idempotent create/update/disable and group membership;
- immutable external identity correlation through `externalId` plus the configured identity source;
- no automatic application grant unless an approved mapping exists; and
- reconciliation report for rejected or ambiguous records.
- optional downstream SCIM connectors for applications that cannot consume Axiom OIDC and live
  entitlement APIs. Inbound and outbound SCIM credentials, ownership and reconciliation are separate.

The customer directory is authoritative for SCIM-managed attributes. Axiom stores origin, last-sync
revision and reconciliation state, and prevents local edits from being silently overwritten.

### AXP-5 — Operational identity controls

**Outcome:** Axiom is operable as a shared enterprise identity service.

- governed signing-key rotation with overlap and retirement;
- service-secret rotation and emergency revocation;
- session inventory and administrator/user session revocation;
- a recovery-tested, strongly authenticated break-glass operator path for an upstream IdP outage;
  it is time-bounded, audited and never becomes normal workforce authentication;
- explicit method-level authorization and separation of duties for identity, client, federation,
  policy and key mutations;
- federation and entitlement change events/webhooks;
- rate limits, lockout and suspicious authentication telemetry;
- backup/restore proof for database, OAuth state, signing keys and policy bundles; and
- product-level health/readiness for issuer, client registry, federation, policy and audit.

### AXP-6 — Generic application access authorization

**Outcome:** applications can ask Axiom for bounded, audited authorization decisions.

- versioned resource/action schema per application;
- versioned typed authorization-attribute schema per application;
- generic batch-decision API;
- exact application, tenant, subject, resource and entitlement-revision binding;
- default deny for unknown or malformed input;
- policy lifecycle, independent approval and atomic activation; and
- invalidation/replay for entitlement and policy changes.

**v1 decision authority:** until a separately versioned application policy-PDP lifecycle is delivered,
the authoritative application-access policy is the durable active membership + assigned application
role definitions. Role permission effects are persisted (`allow`, `read`, `scoped`, `cosign`), and
neutral membership `scopes` supplies bounded ABAC. This must never be routed through the Axiom-admin
Cerbos Policy Studio bundle or represented as consuming-product governance policy.

This reuses the existing AXM-3 through AXM-5 contracts. It must remain separate from Probata's
governance decision that answers whether an Agent is cleared for a business use.

**Boundary acceptance**

- Probata registers its access vocabulary without an Axiom source-code change.
- An Axiom decision can authorize `approve_access_request` for a Banking-scoped resource, but cannot
  determine whether an Agent is cleared.
- Probata's governance control pack can determine clearance, but cannot grant the caller permission
  to operate Probata.
- The two decisions have different policy revision identifiers and separate audit records joined only
  by the request correlation identifier.

### AXP-7 — PostgreSQL policy runtime

**Outcome:** platform authorization is restart-safe and dynamically managed without filesystem policy
truth.

- Keep draft, review, approval, test evidence and immutable activation records in Axiom-owned
  PostgreSQL tables.
- Configure Cerbos with its PostgreSQL storage driver in a dedicated database schema.
- Publish only independently approved active bundles to Cerbos through its authenticated Admin API.
- Use a transactional outbox and idempotent publisher; reload every Cerbos replica after activation.
- Record the exact active policy revision in authorization decisions and audit.
- Seed baseline policies through the same Axiom policy service/CLI used by administration.
- Keep Flyway migrations schema-only; no baseline or demo policy rows in migration files.

**Acceptance**

- A clean database migration creates structure but no demo identities or policy content.
- The seed runner creates the baseline policy lifecycle through supported services and can be replayed.
- Restart Axiom and Cerbos and prove the same active policy revision remains effective.
- Activate a new approved revision, reload every PDP replica, and prove atomic version convergence.
- A failed publish leaves the prior active policy effective and produces actionable audit evidence.

### AXP-8 — Trusted identity propagation and developer integration

**Delivery status:** deferred to the next production-hardening increment.

**Outcome:** browser applications, APIs, background services and developer tools integrate with Axiom
through stable standards-based contracts rather than product-specific authentication code.

- Add an application/resource registry that binds scopes and audiences to resource servers.
- Add a bounded OAuth token-exchange/on-behalf-of profile for propagating a user's identity between
  approved services without forwarding the original browser token everywhere.
- Add Device Authorization Grant only for explicitly registered CLI/headless clients; it is not a
  fallback for browser applications.
- Publish a versioned integration profile containing discovery, claims, validation, logout, error and
  live-entitlement-context contracts.
- Provide reference integrations for a browser SPA/BFF, resource API, service client and CLI.
- Provide idempotent Admin API/CLI automation suitable for deployment pipelines; a Terraform provider
  may wrap this stable API later.
- Version claims and APIs compatibly and publish deprecation windows.

**Acceptance**

- A user signs in once and an approved service exchanges the user token for a narrower audience-bound
  downstream token; unapproved audience, scope, client or subject combinations deny.
- A CLI completes device authorization without collecting the user's password.
- Probata and a second application validate tokens through the same reference integration contract.
- SDK/example validation rejects wrong issuer, audience, algorithm, key, token type and entitlement
  revision.

## 5. Axiom Admin information architecture

```text
Overview
Directory
  Users
  Groups
Applications
  Application details
  Browser & service clients
  Access assignments
OIDC federation
Access model
  Platform roles
  Application roles
  Attributes
Platform policy
Audit
Settings
  Signing keys
  Sessions
  Provisioning
```

The default Applications list shows:

- application name and key;
- active/disabled state;
- browser/service client counts;
- assigned identities;
- federation mode;
- last configuration change; and
- attention state.

Application details use four task-oriented tabs:

1. **Overview** — identity posture and warnings.
2. **Clients** — redirect URIs, grant type, scopes, audience, secret/rotation status.
3. **Access** — memberships, roles and attributes.
4. **Audit** — only changes for this application.

Infrastructure identifiers remain available in an expandable technical-details section; they are not
the primary labels.

## 6. First implementation boundary

Implement AXP-1 before AXP-2. Do not present Axiom as fully multi-application-authorized until
application-scoped memberships and grants in AXP-2 are complete.

The first code change must not:

- rename Probata-specific constants and claim the architecture is generic;
- expose Spring's registered-client table directly;
- accept arbitrary grant types or scopes from the browser;
- return a stored service secret;
- migrate tenant roles into application roles implicitly; or
- weaken the live Probata subject-context security proof.

The Axiom issuer, signing-key location, Redis namespace, Admin origin, Axiom Admin system-client
registration, and bootstrap operator controls remain deployment configuration. Tenant applications,
their clients, audiences, scopes, states, memberships and grants are persisted product data.

Before exposing write actions in Axiom Admin, the corresponding controller must have explicit
administrator authorization, tenant non-disclosure tests and auditable idempotent lifecycle behavior.

## 7. Verification cadence

For each bounded AXP story:

1. compile and run focused Java tests;
2. prove one public-client and one confidential-client journey through the real service;
3. prove the critical negative cases and tenant non-disclosure;
4. build Axiom Admin;
5. inspect the running localhost UX in the in-app Browser; and
6. run only the dependency-selected regression for the changed identity boundary.

Run the larger restart/from-zero/reset proof once at the AXP checkpoint boundary, not after every small
story.
