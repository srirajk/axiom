# AXM-0 Baseline Evidence

This record freezes the current Probata authorization baseline. It does not claim a live Axiom
platform-decision integration.

## Authority at capture

- Probata commit: `b9a0712439c9a1b6aed1c7f6c77ac2a91f7e2a66` on `feat/grg`.
- `CodeMatrixAdapter` remains the only configured `AuthzPort` implementation.
- Axiom remains limited to the existing password-proxy/JWKS identity path when
  `UAC_IDENTITY_PROVIDER=axiom`; no Axiom decision/subject-context client exists.
- M2M continues to use scoped `X-API-Key` credentials before bearer identity resolution.
- Probata governance Cerbos is outside AXM-0 and untouched.

## Frozen baseline artifacts

- Source pin: `axiom/UPSTREAM-SOURCE.json`.
- Version pairing: `AXM-0-VERSION-PAIR-LEDGER.json`.
- Contract lock: `backend/contracts/platform-authz/v1/contract-lock.json`.
- CodeMatrix corpus: 1,655 evaluated records across 7 roles × 59 permissions × 4 resource
  cases, plus explicit unrepresentable-current-engine negatives; SHA-256
  `0cc05811da5cf3fdf3b7d9138ef10e95e205b1a43d9b51bdeed7ac9be8431e03`.
- Gate inventory: 59 source files and 175 current authorization/SoD helper calls; SHA-256
  `fc85c737ea4dcc6036e000e14bcf6353df331430334a531f634c6469ba93ffed`.

## Focused proof scope

The AXM-0 focused contract test proves deterministic corpus generation, frozen-hash comparison,
all five current effects, explicit gap disposition, complete AST-derived gate classification, and
typed contract rejection of malformed tenant/result/effect combinations.

Observed on 2026-07-23, without starting or changing services:

- Ruff and strict mypy passed for the four AXM Python source/test files.
- 60 focused contract/unit tests passed: the AXM-0 lock, Axiom role parity, CodeMatrix, M2M,
  local identity, and Axiom claim-mapping suites.
- 39 focused API unit tests passed: access/no-disclosure, fork visibility, and API-key endpoint
  behavior. Test-process OTLP export attempted `localhost:4327` and was unavailable in the managed
  sandbox; it did not affect the passing in-process authorization assertions.

Existing focused suites remain the behavioral baseline for local identity, Axiom JWT/JWKS mapping,
CodeMatrix authorization, M2M separation, and Axiom provisioner role parity. A live Axiom identity
test may skip when the service is unavailable; it is not evidence that Axiom platform decisions are
live.

## Known, intentional AXM-0 gaps

The current pure CodeMatrix cannot express inactive Axiom subjects or resource tenancy, and it does
not produce a no-disclosure HTTP response. Those are respectively AXM-2 live subject context and
existing Probata RLS/resource-access concerns. They are recorded in the corpus rather than fabricated
as matrix outcomes.

AXM-1 is safe to open only after this diff and its focused baseline evidence receive the requested
independent review. AXM-0 does not authorize an Axiom refresh, OIDC/PKCE change, runtime decision
adapter, shadow mode, or route cutover.
