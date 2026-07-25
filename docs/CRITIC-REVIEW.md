# Axiom Identity Work Order — Independent Critic Review

**Review date:** 2026-07-24  
**Verdict:** approved for implementation with the delivery boundary in `WORK-ORDER.md`  
**Review posture:** architecture, product boundary, security, operability and delivery focus

## Executive verdict

The work order is directionally right and is now bounded well enough to execute. It preserves the most
important product decision: Axiom is a reusable identity and platform-authorization product, while
Probata remains the governance control plane. One customer organization per deployment with many
applications is the correct near-term isolation model.

The first release should not wait for token exchange, device login, SDKs, CLI or Terraform. Those
capabilities improve developer experience and cross-application propagation, but they are not required
to prove that Probata and a second application can trust one Axiom issuer.

## What must be true in the first release

1. Axiom builds and runs from its own repository.
2. Probata is registered as an ordinary application; no required Probata client or audience remains
   compiled into Axiom.
3. Public browser clients use Authorization Code with S256 PKCE and exact redirect URIs.
4. Service clients receive only their persisted tenant, application, audience and scopes.
5. Application memberships, roles and attributes cannot leak between applications.
6. Customer identities link by exact upstream `(issuer, subject)`, never email.
7. Inbound SCIM can provision/deactivate Users, Groups and direct memberships idempotently.
8. Flyway creates schema only; service/API seed paths create baseline data.
9. PostgreSQL is authoritative for policy lifecycle and Cerbos runtime policy storage.
10. Keys, secrets, sessions, disabled principals and upstream-IdP outages fail closed and are
    recoverable through an audited operator path.
11. Probata login, machine token and live subject-context journeys continue to work.
12. A second sample application proves Axiom is genuinely reusable.

## Important meaning of “governed assignment”

An ordinary membership table only says:

> Riya has the `viewer` role in Probata.

A governed assignment can also answer:

> The Banking directory assigned Riya; Lena approved it for the loan-memo programme; it expires on
> 30 September; the next review is due in 60 days.

For the first release, Axiom needs the assignment source, assigning actor and timestamp so access is
traceable. Business justification, approval workflow, expiry and recurring review are valuable
production controls but are explicitly deferred.

## Missing items found by the critic and disposition

| Finding | Disposition |
|---|---|
| Trusted identity propagation between applications | Deferred to AXP-8 |
| Device/CLI authentication | Deferred to AXP-8 |
| SDK, examples, CLI and Terraform | Deferred to AXP-8 |
| Advanced assignment approval, expiry and access review | Deferred; safe provenance remains now |
| Break-glass operation during upstream IdP outage | Added to AXP-5 first-release scope |
| Separation of duties for identity, key and policy mutations | Added to AXP-5 first-release scope |
| Outbound SCIM | Deferred; inbound SCIM remains first-release scope |

## Deliberate non-goals

- SAML.
- Shared multi-customer identity data plane.
- Customer governance-policy authoring inside Axiom.
- Email-based identity linking.
- Open dynamic OAuth client registration.
- Password collection by CLI tools.
- Replacing the customer IdP or duplicating its workforce MFA policy.

## Release gate

The work order is accepted when one bounded scenario proves:

1. customer OIDC user signs into Axiom;
2. Axiom issues a correctly scoped token to Probata;
3. the same identity has different access in a second application;
4. SCIM deactivation or membership removal takes effect at the live authorization boundary;
5. restart preserves issuer, clients, identities, policy revision and audit;
6. no UAC repository files are needed to build the standalone Axiom image.

This is a focused production-credible first release, not a claim that every production-hardening item
is already complete.
