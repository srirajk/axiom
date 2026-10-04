"""C03 — Workload-to-workload chains: explicit edges bound the depth; wrong recipients and substituted actors fail.

Capability: IDP-05 (authorized continuation). Software only: workload A → intermediary → workload B → intermediary →
resource, each hop an RFC 8693 exchange under an explicitly registered edge.

1. Teaches: how far authority can travel and why it cannot go further. Population: workforce person via workloads.
2. Setup: the generic topology: edges portal-svc→edge (GATEWAY), portal-svc→orders-api (RESOURCE),
   portal-svc→reports-svc (AGENT), reports-svc→edge (GATEWAY). Deliberately *no* reports-svc→orders-api,
   reports-svc→portal or reports-svc→reports edge.
3. Records: topology only.
4. Calls: ``POST /oauth/token`` token exchange per hop.
5. Tokens: P3 (person, act=portal-svc, aud=edge) → R1 (aud=reports, act=portal-svc) → R2 (aud=edge, act=reports-svc).
6. Positive: the registered chain completes to reports-svc and back to the intermediary. Denials: R2 onward to a
   resource, back to portal or around to reports again (no edge = no hop, which bounds depth); portal-svc redeeming
   R1 (wrong recipient / actor substitution); the intermediary redeeming R1 directly (not addressed to it);
   ``actor_token`` naming another actor.
7. Status: every hop is re-checked against current edges and workload state (B09 shows revocation of an edge).
8. Cleanup: topology.
9. Consumer must: register only the edges a deployment needs; treat ``act`` as the immediate actor and decide whether
   nested delegation is acceptable for the action; never forward a token to the next hop.
"""
from __future__ import annotations

from axiom_cookbook import oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone

READ = topology.READ


def run(ctx: Context) -> Outcome:
    out = Outcome("C03 workload chains")
    op = ctx.operator()
    top = topology.build(ctx, op)
    http, v = ctx.http, ctx.validator
    p1 = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    p2 = oauth.tokens(oauth.exchange(http, top.portal_svc, p1, top.portal_app["audience"], [READ]).expect(200)).access_token
    p3 = oauth.tokens(oauth.exchange(http, top.portal_svc, p2, top.edge_audience, [READ]).expect(200)).access_token
    r1 = oauth.tokens(oauth.exchange(http, top.edge, p3, top.reports_app["audience"], [READ]).expect(200)).access_token
    r2 = oauth.tokens(oauth.exchange(http, top.reports_svc, r1, top.edge_audience, [READ]).expect(200)).access_token
    c2 = v.access_token(r2, top.edge_audience)
    out.ok(c2["sub"] == top.member and c2["act"]["client_id"] == top.reports_svc.client_id,
           "the registered chain reaches reports-svc and its intermediary authorization, person unchanged")

    for audience, label in ((top.orders_app["audience"], "to a resource reports-svc has no edge to"),
                            (top.portal_app["audience"], "back to the first workload"),
                            (top.reports_app["audience"], "around to reports-svc again")):
        out.refused(oauth.exchange(http, top.edge, r2, audience, [READ]).status in (400, 401),
                    f"no further hop {label}: depth is bounded by registered edges")
    out.refused(oauth.exchange(http, top.portal_svc, r1, top.edge_audience, [READ]).status in (400, 401),
                "the first workload cannot redeem a token addressed to the second (actor substitution)")
    out.refused(oauth.exchange(http, top.edge, r1, top.orders_app["audience"], [READ]).status in (400, 401),
                "the intermediary cannot redeem a token addressed to a workload")
    out.refused(oauth.exchange(http, top.reports_svc, r1, top.edge_audience, [READ],
                               extra={"actor_token": p2.reveal(),
                                      "actor_token_type": oauth.ACCESS_TOKEN_TYPE}).oauth_error() == "invalid_request",
                "a caller cannot name a different actor")
    out.facts["chain"] = ["person", "portal-svc", "edge", "reports-svc", "edge", "(stop: no further edges)"]
    out.consumer_must += ["register only needed edges; review them like firewall rules",
                          "decide per action whether a nested actor chain is acceptable"]
    return out


if __name__ == "__main__":
    standalone(run)
