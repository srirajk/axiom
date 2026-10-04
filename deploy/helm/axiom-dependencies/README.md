# Axiom dependencies Helm chart

This chart packages PostgreSQL 16, Redis 7, Cerbos 0.53, curated base policies, local policy-runtime/audit PVCs,
namespace NetworkPolicies and resource guardrails. It creates no Namespace, Secret or cluster-scoped resource. It
is designed for the disposable [`axiom-test` Docker Desktop profile](../../axiom-test/README.md), not production.

Install it **before** the Axiom app chart. The app chart's pre-install bootstrap hook needs these services ready.
The operator creates `axiom-runtime` and `axiom-signing-key` Secrets separately; Helm never receives their values.
The `axiom-runtime` Secret must include `spring.datasource.password` before PostgreSQL starts.

All Services are ClusterIP. The chart creates a default-deny policy and explicit DNS, dependency and Axiom HTTP
rules. The Axiom Admin UI has no egress to PostgreSQL, Redis or Cerbos. These policies only protect the namespace
when the cluster CNI actually enforces NetworkPolicy; the profile includes an empirical negative canary.

The two explicit PVCs carry `helm.sh/resource-policy: keep`, and the PostgreSQL/Redis StatefulSets retain their
volume claims on removal. A namespace deletion overrides that retention and can destroy all four claims and their
locally provisioned volumes. Do not uninstall/recreate for routine debugging.

`policyRuntime.accessModes: [ReadWriteOnce]` plus one-node pinning is a Docker Desktop exception: Axiom and Cerbos
share that volume on the same node. Production must use a reviewed RWX store or the app chart's S3 backend.

Run `helm lint`, a server-side dry run, `helm test axiom-dependencies`, and the `axiom-test` network canary before
calling a fresh install ready. `helm test` verifies connectivity, not a full OAuth or identity contract.
