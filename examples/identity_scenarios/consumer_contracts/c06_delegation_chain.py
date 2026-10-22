"""C06 — Delegation chain: the ``act`` claim names the current actor and nests prior actors (RFC 8693 section 4.1).

Capability: IDP-05 (authorized continuation). Same generic topology as C03: person → portal-svc → edge (broker) →
reports-svc → edge, each hop an RFC 8693 exchange under an explicitly registered edge.

1. Teaches: what ``act`` says at each hop and what a receiver may rely on. Population: workforce person via workloads.
2. Setup: the generic topology (C03).
3. Records: topology only.
4. Calls: ``POST /oauth/token`` (authorization code, client credentials, token exchange), ``POST /oauth/introspect``.
5. Tokens: P1 (person, no act) → P2/P3 (act = portal-svc) → R1 (broker-issued: client_id = edge, act = portal-svc)
   → R2 (act = reports-svc, act.act = portal-svc exactly as in R1). A client-credentials token has no act; a service
   acting only for itself has none after a self-exchange (S1) or a broker hop (S2) either; when reports-svc takes
   over (S3) it is the only actor and the service stays ``sub``.
6. Positive: the person stays ``sub``; an actor change nests the prior actor verbatim; a broker hop and a
   same-workload continuation add no level; the broker is identified only by ``client_id`` and is never an actor;
   introspection reports the same chain. Denials: the C03 refusals still hold (actor substitution, a token not
   addressed to the caller, no further edge). Malformed and over-deep chains (more than 5 levels) are refused with
   ``invalid_grant`` and never truncated; they cannot be produced by a client and are proven by the Java
   ``DelegationChainIT`` with re-signed tokens.
7. Status: every hop is re-checked against current edges and workload state; nested actors are informational only.
8. Cleanup: topology.
9. Consumer must: authorize on top-level claims and the outermost ``act`` (the current actor) only; treat nested
   actors as audit information; identify a presenting broker by ``client_id``, never by ``act``.
"""
from __future__ import annotations

from axiom_cookbook import oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone

READ = topology.READ


def _depth(act) -> int:
    levels = 0
    while isinstance(act, dict):
        levels += 1
        act = act.get("act")
    return levels


def _actors(act) -> list[str]:
    seen = []
    while isinstance(act, dict):
        seen.append(act.get("client_id"))
        act = act.get("act")
    return seen


def run(ctx: Context) -> Outcome:
    out = Outcome("C06 delegation chain")
    op = ctx.operator()
    top = topology.build(ctx, op)
    http, v = ctx.http, ctx.validator
    portal, reports, edge = top.portal_svc.client_id, top.reports_svc.client_id, top.edge.client_id

    p1 = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    c1 = v.access_token(p1, top.portal_app["audience"])
    out.ok("act" not in c1, "a person's login carries no actor")

    p2 = oauth.tokens(oauth.exchange(http, top.portal_svc, p1, top.portal_app["audience"], [READ]).expect(200)).access_token
    c2 = v.access_token(p2, top.portal_app["audience"])
    out.ok(c2["sub"] == c1["sub"] and c2["act"]["client_id"] == portal and _depth(c2["act"]) == 1,
           "the first exchange names portal-svc as the only actor")
    p3 = oauth.tokens(oauth.exchange(http, top.portal_svc, p2, top.edge_audience, [READ]).expect(200)).access_token
    c3 = v.access_token(p3, top.edge_audience)
    out.ok(c3["act"] == c2["act"], "a same-workload continuation adds no level")

    r1 = oauth.tokens(oauth.exchange(http, top.edge, p3, top.reports_app["audience"], [READ]).expect(200)).access_token
    cr1 = v.access_token(r1, top.reports_app["audience"])
    out.ok(cr1["client_id"] == edge and cr1["act"] == c3["act"],
           "a broker hop: the broker presents (client_id) and the chain is unchanged")

    r2 = oauth.tokens(oauth.exchange(http, top.reports_svc, r1, top.edge_audience, [READ]).expect(200)).access_token
    cr2 = v.access_token(r2, top.edge_audience)
    out.ok(cr2["sub"] == c1["sub"], "the person stays the subject across the chain")
    out.ok(cr2["act"]["client_id"] == reports and cr2["act"]["workload_id"] == top.reports_workload["id"]
           and cr2["act"].get("act") == cr1["act"] and _depth(cr2["act"]) == 2,
           "an actor change: reports-svc outermost, portal-svc nested exactly as it was")
    out.ok(all(edge not in _actors(c["act"]) for c in (c2, c3, cr1, cr2)), "the broker is never an actor")

    introspected = oauth.introspect(http, top.orders_receiver, r2)
    out.ok(introspected.get("active") is True and introspected.get("act") == cr2["act"],
           "introspection reports the same nested chain")

    cc = oauth.tokens(oauth.client_credentials(http, top.portal_svc, [READ]).expect(200)).access_token
    out.ok("act" not in v.access_token(cc, top.portal_app["audience"]), "a client-credentials token carries no actor")

    # A service acting only for itself: no act, even after exchanging its own token and across a broker hop.
    s1 = oauth.tokens(oauth.exchange(http, top.portal_svc, cc, top.edge_audience, [READ]).expect(200)).access_token
    cs1 = v.access_token(s1, top.edge_audience)
    out.ok(cs1["sub"] == portal and "act" not in cs1, "a self-exchange by a service names no actor")
    s2 = oauth.tokens(oauth.exchange(http, top.edge, s1, top.reports_app["audience"], [READ]).expect(200)).access_token
    cs2 = v.access_token(s2, top.reports_app["audience"])
    out.ok(cs2["sub"] == portal and cs2["client_id"] == edge and "act" not in cs2,
           "a broker hop of a self-acting service adds no actor")
    # Takeover: reports-svc continues the service's work; it is the only actor and the service stays sub.
    s3 = oauth.tokens(oauth.exchange(http, top.reports_svc, s2, top.edge_audience, [READ]).expect(200)).access_token
    cs3 = v.access_token(s3, top.edge_audience)
    out.ok(cs3["sub"] == portal and cs3["act"]["client_id"] == reports and _depth(cs3["act"]) == 1,
           "another workload taking over a service's work is the only actor")
    out.refused(oauth.exchange(http, top.portal_svc, s2, top.edge_audience, [READ]).status in (400, 401),
                "the service cannot redeem a self-acting token addressed to another workload")

    # The C03 refusals still hold with nested chains.
    out.refused(oauth.exchange(http, top.portal_svc, r1, top.edge_audience, [READ]).status in (400, 401),
                "the first workload cannot redeem a token addressed to the second (actor substitution)")
    out.refused(oauth.exchange(http, top.edge, r1, top.orders_app["audience"], [READ]).status in (400, 401),
                "the intermediary cannot redeem a token addressed to a workload")
    out.refused(oauth.exchange(http, top.edge, r2, top.orders_app["audience"], [READ]).status in (400, 401),
                "no further hop where no edge is registered")
    out.facts["chain"] = {"P1": [], "P2": [portal], "P3": [portal], "R1": [portal], "R2": [reports, portal],
                          "S1 (service for itself)": [], "S2 (broker hop)": [], "S3 (takeover)": [reports]}
    out.consumer_must += ["authorize on top-level claims and the outermost act only; nested actors are audit data",
                          "identify a presenting broker by client_id, never by act"]
    return out


if __name__ == "__main__":
    standalone(run)
