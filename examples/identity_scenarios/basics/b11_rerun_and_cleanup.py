"""B11 — Safe re-runs and cleanup of only this run's records.

1. Teaches: how to provision idempotently and clean up without touching anyone else's data. Population: n/a.
2. Setup: provisioning operator; a fixture namespace ``ckbk-<hex>`` unique to the run.
3. Records: an application, a client, a workforce user and a workload, all named in the namespace.
4. Calls: creation calls twice (the second is a 409 conflict, which a re-run treats as "already provisioned");
   cleanup via the registry: ``DELETE`` (disable) for users, clients and applications, ``retire`` for workloads.
5. Tokens: n/a.
6. Positive: cleanup disables or revokes every owned record; a second cleanup is a no-op. Denials: duplicate
   creation; the cleaned-up client can no longer authenticate.
7. Interrupted runs: ``python -m axiom_cookbook.estate reap`` removes leftover containers/run directories carrying
   the cookbook label; against a non-disposable target the registry report lists residual (disabled) records.
8. Cleanup: this example *is* the cleanup demonstration. Axiom keeps disabled records for audit; the cookbook never
   deletes rows with SQL.
9. Consumer must: namespace its fixtures, record what it created, and treat 409 on re-run as success only after
   checking the existing record is the one it intended.
"""
from __future__ import annotations

from axiom_cookbook import oauth
from axiom_cookbook.context import Context, Registry
from axiom_cookbook.example import Outcome, standalone


def run(ctx: Context) -> Outcome:
    out = Outcome("B11 re-run and cleanup")
    op = ctx.operator()
    local = Registry(ctx.target.namespace + "-b11")
    outer, ctx.registry = ctx.registry, local
    try:
        app = ctx.application(op, "rerun")
        svc, _ = ctx.service_client(op, app, "rerun-svc", ["reports.read"])
        ctx.workload(op, svc, "rerun-svc")
        ctx.workforce_user(op, "rerun-user")
        again = ctx.http.post(ctx.admin_base() + "/applications", bearer=op, json_body={
            "applicationKey": app["applicationKey"], "displayName": "again", "audience": app["audience"] + "-2"})
        out.refused(again.status == 409, "re-running a creation reports a conflict instead of duplicating")
        existing = ctx.http.get(f"{ctx.admin_base()}/applications/{app['id']}", bearer=op).expect(200).json()
        out.ok(existing["applicationKey"] == app["applicationKey"], "the existing record is the intended one")
        owned = len(local.owned)
        report = local.cleanup()
        out.ok(not report["failed"] and len(report["disabled_or_revoked"]) == owned == 4,
               "cleanup disabled/retired exactly this run's four records (application, client, workload, user)")
        out.facts["cleanup_report"] = report
        out.refused(oauth.client_credentials(ctx.http, svc, ["reports.read"]).status in (400, 401),
                    "a cleaned-up client can no longer authenticate")
        out.ok(local.cleanup() == {"disabled_or_revoked": [], "residual": [], "failed": []},
               "a second cleanup is a no-op")
    finally:
        ctx.registry = outer
    out.consumer_must.append("namespace fixtures and record what you created; never clean up by pattern alone")
    return out


if __name__ == "__main__":
    standalone(run)
