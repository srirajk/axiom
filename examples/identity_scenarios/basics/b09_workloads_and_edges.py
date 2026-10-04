"""B09 — Workload clients, an exchange intermediary and exact exchange edges; registration is not authority.

1. Teaches: the records behind every exchange, and the role separation Axiom enforces. Population: workloads.
2. Setup: provisioning operator.
3. Records: two confidential clients registered as workload identities (``POST /admin/tenants/{t}/ciam/agent-workloads``
   — the path name is historical; Axiom stores a generic workload), one client registered as an exchange
   intermediary (``POST …/agent-exchange/brokers``), and exact edges (``POST …/agent-exchange/routes``) with a
   destination type (``GATEWAY`` = to the intermediary, ``RESOURCE``, ``AGENT`` = to another workload), audience,
   scopes and expiry.
4. Calls: as above, plus a token exchange to show an edge is required.
5. Tokens: a workload's own client-credentials token is its identity, not permission to reach anything.
6. Positive: registrations and edges created. Denials: the intermediary's client cannot also be a workload, a
   workload's client cannot become the intermediary (role confusion); an edge to a workload destination needs that
   workload; a registered workload without an edge to an audience cannot exchange to it.
7. Expiry: edges carry ``expiresAt`` (max 90 days) and can be revoked.
8. Cleanup: edges and intermediary revoked, workloads retired, clients disabled.
9. Consumer must: model its own business relationships elsewhere; Axiom edges only say which hop may be minted.
"""
from __future__ import annotations

from axiom_cookbook import oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone

READ = "orders.read"


def run(ctx: Context) -> Outcome:
    out = Outcome("B09 workloads and exchange edges")
    op = ctx.operator()
    a_app, b_app, edge_app = ctx.application(op, "svc-a"), ctx.application(op, "svc-b"), ctx.application(op, "edge")
    a, _ = ctx.service_client(op, a_app, "svc-a", [READ])
    b, _ = ctx.service_client(op, b_app, "svc-b", [READ])
    edge, _ = ctx.service_client(op, edge_app, "edge", [READ])
    wa, wb = ctx.workload(op, a, "svc-a"), ctx.workload(op, b, "svc-b")
    ctx.broker(op, edge, edge_app["audience"], [READ])
    out.ok(wa["status"] == "ACTIVE" and wa["oauthClientId"] == a.client_id, "workload identities registered")

    as_workload = ctx.http.post(f"{ctx.admin_base()}/ciam/agent-workloads", bearer=op, json_body={
        "workloadRef": "workload:" + ctx.name("edge-as-workload"), "name": "x", "oauthClientId": edge.client_id})
    out.refused(as_workload.status == 409, "the intermediary's client cannot also be registered as a workload")
    as_broker = ctx.http.post(f"{ctx.admin_base()}/agent-exchange/brokers", bearer=op, json_body={
        "oauthClientId": a.client_id, "gatewayAudience": a_app["audience"], "scopes": [READ]})
    out.refused(as_broker.status == 409, "a workload's client cannot become an exchange intermediary")
    missing_destination = ctx.http.post(f"{ctx.admin_base()}/agent-exchange/routes", bearer=op, json_body={
        "sourceWorkloadId": wa["id"], "destinationType": "AGENT", "audience": b_app["audience"], "scopes": [READ],
        "purpose": "x", "expiresAt": "2099-01-01T00:00:00Z"})
    out.refused(missing_destination.status in (400, 404), "an edge to a workload must name that workload")

    token = oauth.tokens(oauth.client_credentials(ctx.http, a, [READ]).expect(200)).access_token
    out.refused(oauth.exchange(ctx.http, a, token, edge_app["audience"], [READ]).status in (400, 401),
                "registration alone grants nothing: without an edge the workload cannot exchange")
    ctx.route(op, wa["id"], "GATEWAY", edge_app["audience"], [READ])
    ctx.route(op, wa["id"], "AGENT", b_app["audience"], [READ], destination_workload=wb["id"])
    out.ok(oauth.exchange(ctx.http, a, token, edge_app["audience"], [READ]).status == 200,
           "with an explicit edge the same exchange succeeds")
    out.consumer_must.append("keep business relationships (assignments, ownership of data) in the consumer")
    return out


if __name__ == "__main__":
    standalone(run)
