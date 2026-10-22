# Delegation chain evidence (2026-10-05)

## Initial nested-chain run

Source fingerprint (scratchpad fp.py over examples/identity_scenarios, server/src/main, server/pom.xml, platform-*):
`e4c0b2691455e4a43179dc22ebe9bd261d3668a745653682ca5ba49ebc508e54` (606 files), unchanged before and after the full run.
Jar: `server/target/iam-service-1.0.0.jar` sha256 `1b2694a41e61fbcf86c70683c31a6e88fe240c375dbb8ba0e8df340faa46f813`.

- `java-summary.json`: counts only (no messages or stack traces).
- `mutation-results.txt`: DelegationChainIT under three mutations.
- `python-summary.txt`: full cookbook suite on a disposable estate.

Corrected contract: `docs/architecture/axiom-token-delegation-chain.md`.

## Standards-first R2 follow-up (current source)

`r2-standards-first.txt` records the later owner-approved self-acting-token change: source fingerprint
`f0077b01e600b422578b96715db86ce3f419ea57779970fbb5cad6c462e3c151` (606 files, unchanged across its
run) and jar sha256 `6a8eccd6d95464343ad9c3342f95feb1fc6136647f2332f4e3145dcc23954ae0`.
`java-summary-r2-standards-first.json` records 424/424 Java unit tests passing and 193/206 integration tests
passing, with 1 failure, 9 errors and 3 skips. The four JDBC-connection errors in `ActionApprovalIT` and
`IdpBaselineIT` passed isolated reruns (5/5 and 12/12); six failures/errors in three environment-dependent classes
remain. The follow-up also records focused tests and mutations. Its disposable-estate Python suite passed 76/76.
These results are not a clean full integration-suite pass or a Kubernetes release result.
