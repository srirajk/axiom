# Axiom

Axiom is a reusable, single-customer identity and platform-authorization control plane for many
applications. It federates a customer's OIDC identity provider, issues stable OIDC tokens to
registered applications, manages application-scoped access, supports SCIM provisioning, and provides
a PostgreSQL-backed platform-policy lifecycle.

## Repository layout

- `server/` — Spring Authorization Server, identity APIs and policy lifecycle.
- `admin/` — Axiom administrative web application.
- `platform-policy/` — isolated Cerbos policy package used for Axiom platform authorization.
- `docs/` — accepted product work order, OIDC contract and independent critic review.

Start with:

- `docs/PRD.md` — product purpose, personas, journeys and release acceptance.
- `docs/WORK-ORDER.md` — dependency-safe implementation plan.
- `docs/LOCAL-COMPOSE.md` — explicit local endpoints and startup contract.
- `docs/FLAGSHIP-DEMO-GUIDE.md` — presenter-ready 3-minute and 12-minute product journeys.

## Current extraction status

This repository begins as a non-destructive snapshot of the implementation proven inside UAC. It is
not yet the authoritative consumer cutover.

The current server still contains explicitly tracked Probata compatibility seams. Follow AXP-0 in
`docs/WORK-ORDER.md` to replace those seams with persisted application/client records and generic
contracts. Do not delete the embedded UAC copy until Probata and a second application pass against an
immutable standalone Axiom image.

## Product boundary

- Axiom owns identity, OIDC, SCIM, application access and platform authorization.
- Applications own their domain concepts.
- Probata governance policy and contextual Agent clearance remain in Probata.
- One customer organization is served by one Axiom deployment; many applications may share it.
- SAML is not in scope.

## Data discipline

Flyway migrations create schema, constraints and indexes only. Baseline identities, applications,
roles and policies are created idempotently through supported Axiom service/API/CLI paths. Production
policy truth is PostgreSQL-backed; filesystem policy files are import or development artifacts.
