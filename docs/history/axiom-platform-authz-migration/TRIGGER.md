# AXM Trigger Prompts

## 1. Root AXM-0 prompt

```text
Execute AXM-0 only from:

docs/spec/axiom-platform-authz-migration/CODEX-START.md

Current approved scope is AXM-001 through AXM-007. Build the source manifest, compatibility/disposition
report, typed cross-language contracts, complete route/resource inventory, deterministic CodeMatrix
golden corpus and baseline evidence. Do not upgrade the runtime Axiom, change authentication behavior,
enable Axiom authorization, or begin AXM-1.

Use GPT-5.6 Luna medium for bounded manifest/fixture/report work and GPT-5.6 Terra high for contract and
authorization-resource review. Keep file ownership disjoint. Use a fresh read-only critic for the
complete AXM-0 diff. Commit only reviewed AXM-owned changes with UAC commit conventions, update the AXM
evidence record, and stop for user acceptance.
```

The execution entry point includes `06-policy-realization.md`. AXM-1 workers must preserve that policy
boundary and must not begin GOVPOL runtime stories.

## 2. Axiom upstream contract worker

```text
Work in an isolated worktree of /Users/srirajkadimisetty/projects/orchestrator-demo from
conduit-platform-next. Read that repository's AGENTS/CLAUDE/OpenWolf rules and:

/Users/srirajkadimisetty/projects/uac/docs/spec/axiom-platform-authz-migration/02-target-architecture-and-contracts.md
/Users/srirajkadimisetty/projects/uac/docs/spec/axiom-platform-authz-migration/03-work-orders-and-dependency-dag.md
/Users/srirajkadimisetty/projects/uac/docs/spec/axiom-platform-authz-migration/04-acceptance-matrix.md

Implement only the specifically assigned AXM-3 stories. The API must be generic Axiom platform authz:
no import or compile dependency on Probata, no governance/clearance/evidence semantics, no caller-supplied
role authority, no Conduit gateway dependency. Resolve subjects live, bind tenant exactly, authenticate
the Probata service client narrowly, return complete typed batch decisions with entitlement/policy
revision and call IDs, audit safely, and fail closed. Follow the upstream repository's commit convention.
Do not edit UAC.
```

## 3. Probata Axiom product import worker

```text
Continue in the existing Probata integration session at /Users/srirajkadimisetty/projects/uac. Read
docs/spec/axiom-platform-authz-migration/CODEX-START.md completely.

Implement AXM-1 only. Import the pinned Axiom product slice:

- `orchestrator-demo/iam-service` -> `uac/axiom`;
- `orchestrator-demo/admin-ui` -> `uac/axiom-admin`; and
- the reviewed IAM/domain/Policy Studio/templates/invariants subset of
  `orchestrator-demo/infra/cerbos` -> `uac/axiom-platform-policy`.

Do not import Conduit gateway, registry, agents, apps, demo identities, generated output or Conduit
agent/relationship/insights policies. Preserve `axiom/provision_uac.py` as a Probata-owned overlay.
Do not edit the Axiom upstream repository, Probata governance Cerbos, clearance/evidence semantics,
user-owned untracked artifacts or an unassigned migration. Keep CodeMatrix authoritative. Build all
three components from source, use isolated Postgres/Redis/signing/policy storage, prove restart/login/
Policy Studio/audit/Cerbos invariants, and return exact evidence. Do not self-certify or begin AXM-2.
```

## 4. Frontend OIDC worker

```text
Work only after AXM-2 is explicitly opened and /api/auth/config + callback/session contracts are frozen.
Implement the assigned Probata frontend OIDC Authorization Code + PKCE stories in an isolated worktree.
Do not change backend contracts, platform policy, navigation permission semantics or product governance.
No production password form, no localStorage token authority, no client-side JWT entitlement gating.
Use the Browser and Playwright/axe for login/callback/deep-link/expiry/logout/outage states. Stop at the
assigned story boundary.
```

## 5. Independent critic

```text
READ ONLY. Review the frozen AXM specification, full assigned-checkpoint diff, harness output and evidence.
Do not edit, commit, fix or approve your own work. Look specifically for:

- JWT entitlement trust;
- cross-tenant or subject-confusion paths;
- service-client overprivilege;
- fail-open/mirror grant fallback;
- missing/duplicate/malformed batch-result handling;
- untyped resource attributes or hidden-object leakage;
- cache keys missing entitlement/policy/resource revisions;
- bypasses around PlatformAuthorizationPort;
- SoD/RLS/no-disclosure regression;
- platform-policy/governance-policy plane mixing;
- unsafe database/key/client migration;
- generated/demo/secret files entering source; and
- unverifiable parity, outage, rollback or user claims.

Return P0/P1/P2 findings with exact file/line evidence and a lock verdict. Do not mark findings resolved.
```
