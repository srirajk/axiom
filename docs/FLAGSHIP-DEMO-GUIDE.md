# Axiom Flagship Demo Guide

This guide lets another presenter demonstrate the standalone Axiom Identity
Platform without knowing its implementation.

## The story in one sentence

**Axiom gives one customer a secure identity and application-access control
plane that many products can share: workforce identities enter through OIDC
and SCIM, applications receive standards-based tokens, sensitive changes pass
through governed controls, and every action leaves an audit trail.**

## What Axiom is—and is not

Axiom owns:

- workforce identities, Teams and identity lifecycle;
- customer OIDC federation and inbound SCIM 2.0;
- application and OAuth client registration;
- application-scoped access, roles and typed attributes;
- signing keys, sessions, credential rotation and revocation;
- identity-control approvals, recovery operators and audit;
- Axiom's own platform-authorization policy lifecycle.

A consuming product still owns its business policy. For example, a product may
decide whether an AI agent is eligible for a business use. That rule does not
belong in Axiom.

The hard policy boundary is simple:

> Axiom policy may reference identity nouns such as tenant, user, group,
> application, client, role, attribute and session. It must not become a
> consuming application's domain-policy engine.

## Before the meeting

### 1. Start the standalone product

From the Axiom repository:

```bash
cd /Users/srirajkadimisetty/projects/axiom
docker compose up -d --build
docker compose ps
```

All long-running services should be healthy. The one-shot `bootstrap` service
should have completed successfully.

Default local endpoints:

| Surface | URL |
|---|---|
| Axiom Admin | `http://localhost:5182` |
| OIDC issuer and API | `http://localhost:8180` |
| Health | `http://localhost:8180/actuator/health` |

If ports were changed, use `AXIOM_ADMIN_HOST_PORT` and
`AXIOM_HTTP_HOST_PORT` from the local `.env`.

### 2. Apply the Meridian reference directory

Only run this if the reference users and Teams are not already visible:

```bash
set -a
source .env
set +a
uv run --project seed python seed/seed_meridian.py
```

The seed uses Axiom's supported OIDC and HTTP paths. It does not insert rows
directly into PostgreSQL and is safe to rerun.

Expected reference story:

- one Meridian customer deployment;
- 48 realistic workforce identities;
- 10 Teams across identity operations, banking, wealth, financial crime, risk,
  audit and executive oversight;
- active, invited and deactivated lifecycle examples.

### 3. Decide whether to enable AI-assisted policy drafting

An LLM key is **optional**. Axiom runs without one and uses a deterministic
proposal fallback.

To demonstrate natural-language policy drafting, set this locally in `.env`:

```dotenv
ZAI_API_KEY=<local-secret>
IAM_POLICY_STUDIO_MODEL=glm-4.6
IAM_POLICY_STUDIO_BASE_URL=https://api.z.ai/api/paas/v4
```

Then rebuild the Axiom server:

```bash
docker compose up -d --build axiom admin
```

Never commit the real key, display `.env`, or paste the key into the browser.

The model is not a decision-maker:

1. the model may propose a policy;
2. Axiom parses it into a closed typed representation;
3. deterministic validation rejects unknown nouns, actions or unsafe scope;
4. pinned Cerbos evaluates the before/after consequences;
5. a different authorized human approves the exact reviewed artifact;
6. Axiom promotes the canonical policy and records the receipt.

The runtime authorization result never comes from an LLM.

## Sign in

1. Open `http://localhost:5182`.
2. Select **Continue securely**.
3. Sign in with username `admin`.
4. Use the local value of `AXIOM_ADMIN_PASSWORD` from `.env`.

Do not place the password in this guide or show `.env` while screen sharing.

The browser uses Authorization Code with S256 PKCE. It does not store a client
secret or the administrator's password.

## Recommended 12-minute flagship journey

This journey is mostly read-only, so it is repeatable and safe for a shared
environment.

### 1. Dashboard — “one place to understand identity”

Open **Dashboard**.

Say:

> This is Meridian's identity control plane. These are real persisted counts,
> not mock cards. The activity stream shows who changed what and when.

Show:

- workforce identity, Team and role counts;
- recent audited activity;
- the signed-in administrator identity.

What it proves: the UI is backed by the running Axiom API and PostgreSQL state.

### 2. Users and Teams — “the reusable workforce directory”

Open **Users**, search for `riya.patel`, and then open **Teams**.

Say:

> Axiom holds stable workforce identities and lifecycle state. Teams represent
> enterprise identity groupings such as Banking Builders or Enterprise Risk;
> they are not application-specific business policy.

Show:

- Riya Patel as a workforce identity;
- active, invited and deactivated states;
- Banking, Wealth, Financial Crime, Risk and Audit Teams;
- direct membership provenance.

What it proves: one application-neutral identity layer can serve many products.

### 3. Applications — “identity becomes usable by products”

Open **Applications** and select an active application.

Say:

> An identity does not automatically receive access everywhere. Each product is
> a registered application with its own clients, members, roles and attributes.

Show the three levels:

1. **Application** — the product boundary and audience.
2. **Client** — browser or service integration, redirect URIs, scopes and PKCE.
3. **Access** — application members, application-local roles and typed
   attributes.

Call out:

- browser clients use Authorization Code + S256 PKCE and have no secret;
- confidential service clients receive a secret only at creation or rotation;
- stored secrets are never displayed later;
- application roles do not silently become tenant-wide roles.

What it proves: Axiom is an identity platform for multiple applications, not
just a shared user table.

### 4. Customer IdP and SCIM Sources — “connect the customer's ecosystem”

Open **Customer IdP**.

Say:

> In production, Meridian keeps its existing identity provider. Axiom
> federates it through OIDC and validates issuer metadata, keys and audience
> before activation.

Then open **SCIM Sources**.

Say:

> OIDC authenticates people. SCIM synchronizes their directory lifecycle:
> Users, Groups, memberships and deactivation.

Show:

- source health and lifecycle state;
- that sensitive activation or credential changes route through
  **Identity Controls**;
- SCIM token material is shown once and stored hashed;
- reconciliation and source traceability.

What it proves: a customer can connect its existing IdP and directory rather
than migrating identities manually.

### 5. Signing Keys and Sessions — “trust is operable”

Open **Signing Keys**.

Say:

> Axiom signs tokens with durable managed keys and publishes verifiable OIDC
> metadata. Rotation is a controlled lifecycle, not a file replacement.

Open **Sessions**.

Say:

> Administrators can see and revoke durable sessions. Revocation survives a
> service restart.

Show lifecycle and status only. Do not rotate a signing key or revoke the
presenter's session during the standard demo.

What it proves: issuance, verification and revocation are operational product
capabilities.

### 6. Identity Controls — “sensitive change requires proof and separation”

Open **Identity Controls**.

Say:

> High-impact identity operations are not direct buttons. A request records the
> action and target, a different authorized person reviews it, and only an
> approved request can be applied.

Show:

- pending and terminal request tabs;
- the safe request reference, action and target;
- proposal → independent approval → apply lifecycle;
- rejected, cancelled and expired terminal states;
- no secret or payload hash disclosed in the UI.

What it proves: rotation, activation and recovery changes are governed,
traceable and fail closed.

For a live mutation demo, prepare two authorized operators in advance. The
requester must not approve their own request.

### 7. Recovery Operators — “recovery does not become a back door”

Open **Recovery Operators**, then **My recovery access**.

Say:

> Recovery access is explicit, time-bound and independently activated. An
> operator cannot enroll or activate themselves, and disabling recovery
> invalidates its bearer session.

Show:

- enrolled versus active recovery authority;
- separation of requester and activator;
- expiry and disabled states;
- the self-service view disclosing only the signed-in operator's access.

What it proves: Axiom can recover identity operations without bypassing the
same control principles.

### 8. Policy Studio — “AI may propose; controls decide”

Open **Policy Studio**.

Say:

> This studio governs access to Axiom and its registered applications. It does
> not author a consuming product's business policy.

Walk through the visible sequence:

1. **Describe the access change**.
2. **Generate and validate draft**.
3. **Review consequences** from pinned Cerbos.
4. **Approve and promote** with a different human.

If an LLM key is configured, say:

> The model translates intent into a proposal. Unknown vocabulary, a wider
> tenant scope or an unsafe grant is rejected by deterministic controls.

If no LLM key is configured, say:

> The same safety pipeline is demonstrable through Axiom's deterministic
> fallback; no runtime authorization depends on a model.

Show:

- the closed identity vocabulary;
- canonical policy rather than raw model output;
- access-widening warning and concrete decision deltas;
- lifecycle evidence and examiner chain;
- break-glass as an audited, bounded workflow.

Do not promote a new policy during an ordinary read-only demo.

What it proves: policy authoring is assistive, but enforcement truth remains
Cerbos plus deterministic validation and human accountability.

### 9. Audit Log — “finish with proof”

Open **Audit Log**.

Say:

> Every important identity and policy action ends here with actor, action,
> target and time. Secrets are excluded, but accountability is retained.

Show:

- recent identity, application or control-request events;
- the request reference that links a controlled change to its audit history;
- retained terminal events rather than deleted history.

What it proves: the product is explainable after the fact, not only secure
during the action.

## Optional 3-minute executive version

When time is short, show only:

1. **Dashboard** — one customer identity estate.
2. **Applications** — shared identity, application-specific access.
3. **Customer IdP + SCIM Sources** — connects to the customer's ecosystem.
4. **Identity Controls** — sensitive changes require independent approval.
5. **Audit Log** — every action is attributable.

Close with:

> Axiom lets every Meridian application consume the same trustworthy identity
> foundation without rebuilding OIDC, SCIM, credential lifecycle, separation
> of duties and audit independently.

## Questions a reviewer may ask

### “Is Axiom multi-tenant?”

One deployment serves one customer organization. That deployment can serve
many applications. This keeps the customer boundary explicit and makes
operational isolation easier to reason about.

### “Does Axiom replace the customer's IdP?”

No. It can provide local bootstrap access, but the enterprise design federates
the customer's OIDC provider and accepts directory lifecycle through SCIM.

### “Does Cerbos store identities?”

No. PostgreSQL is the durable identity and lifecycle system of record. Cerbos
evaluates authorization policy.

### “Does the LLM decide access?”

No. It may propose authoring text and optionally phrase an already-computed
consequence. Deterministic validation, pinned Cerbos evaluation, separation of
duties and explicit promotion decide what becomes active.

### “Where do application business policies live?”

Inside the consuming application or its governance product. Axiom owns only
identity and application-access policy.

### “Can we use SAML?”

SAML is not part of the current product scope. The supported federation
direction is OIDC/JWKS, with inbound SCIM 2.0 for directory synchronization.

### “Are credentials visible in the Admin UI?”

No stored secret is displayed. New client or SCIM secrets are revealed only
once at creation or rotation and are then stored using protected forms.

## Demo safety rules

- Never display `.env`, API keys, client secrets, SCIM tokens or recovery
  bearers.
- Do not rotate a key, revoke the current session or promote a policy unless
  the meeting specifically requires a mutation demo.
- Never approve your own identity-control or policy request.
- Do not use raw SQL to prepare or repair demo data.
- Do not describe Axiom as the owner of application-domain governance.
- Prefer terminal, already-audited examples for repeatable demonstrations.

## Troubleshooting

### Admin page does not load

```bash
docker compose ps
curl -fsS http://localhost:8180/actuator/health
```

If the configured ports differ, use the local `.env` values.

### Login redirects incorrectly

Confirm that these values match the URL being opened:

```dotenv
AXIOM_ISSUER_URL=http://localhost:8180
AXIOM_ADMIN_REDIRECT_URI=http://localhost:5182/callback
AXIOM_ADMIN_POST_LOGOUT_REDIRECT_URI=http://localhost:5182/login
```

Then rebuild `axiom` and `admin`.

### Reference users are missing

Rerun the idempotent Meridian seed through its supported API path:

```bash
set -a
source .env
set +a
uv run --project seed python seed/seed_meridian.py
```

### Policy drafting reports that the model is unavailable

The product remains safe and usable: the deterministic fallback should still
produce a bounded proposal. For the model-assisted version, verify
`ZAI_API_KEY`, model and base URL locally, then rebuild the Axiom server.

### A controlled operation cannot be approved

Check whether the requester and approver are the same identity. Axiom blocks
self-approval by design.

## Presenter close

> Axiom is the identity foundation beneath the control plane: one customer,
> many applications, standards-based federation and provisioning, governed
> access changes, durable revocation and proof for every important action.
