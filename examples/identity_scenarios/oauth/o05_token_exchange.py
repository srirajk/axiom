"""O05 — RFC 8693 token exchange under Axiom's on-behalf-of profile: person-on-behalf-of, workload-only and an
authorized continuation through an exchange intermediary.

1. Teaches: how authority moves between services without forwarding a person's token. Population: workforce person
   and workloads.
2. Setup: the generic topology (``axiom_cookbook/topology.py``): browser client + workload in the ``portal``
   application, a second workload ``reports-svc``, an intermediary ``edge`` and a resource ``orders-api``, with exact
   edges. Profile: RFC 8693 with ``subject_token`` only — Axiom refuses ``actor_token``; the *authenticated client*
   is the exchanging party and Axiom itself records the acting workload in ``act`` (Axiom-specific profile).
3. Records: see the topology; nothing else.
4. Calls: ``POST /oauth/token`` ``grant_type=urn:ietf:params:oauth:grant-type:token-exchange`` with
   ``subject_token``, ``subject_token_type=…:access_token``, ``audience``, ``scope``; HTTP Basic client auth.
5. Tokens per hop (person flow):
   P1 browser login → ``sub``=person, ``aud``=portal;
   P2 portal-svc exchanges P1 → ``sub``=person, ``act``=portal-svc, ``aud``=portal (the workload's own audience);
   P3 portal-svc exchanges P2 → ``aud``=edge (an authorization for the intermediary);
   P4 edge exchanges P3 → ``aud``=orders-api, ``client_id``=edge, ``act`` still portal-svc, ``sub`` still the person.
   The person never changes, the actor is the workload, the client is whoever authenticated. Lifetimes only shrink.
6. Positive: all three flows. Denials: another workload redeeming the person's token; scope widening; an audience
   without an edge; ``actor_token``; a resource token used onward; a person outside the application; the edge using
   a token that was not addressed to it.
7. Expiry: each exchanged token lives at most 5 minutes and never beyond its subject token.
8. Cleanup: topology records disabled/revoked/retired.
9. Consumer must: exchange per hop (never forward), send the exact audience, request minimal scope, and have every
   receiver validate ``aud``, ``scope`` and ``exp`` (plus status, see O06).
"""
from __future__ import annotations

from axiom_cookbook import oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.oauth import Tokens
from axiom_cookbook.tokens import unverified_claims

READ, WRITE = topology.READ, topology.WRITE


def _scopes(claims: dict) -> list[str]:
    scope = claims.get("scope", [])
    return scope.split() if isinstance(scope, str) else list(scope)


def run(ctx: Context) -> Outcome:
    out = Outcome("O05 token exchange")
    op = ctx.operator()
    top = topology.build(ctx, op)
    http, v = ctx.http, ctx.validator

    # ------------------------------------------------------------------ person on behalf of, with continuation
    p1 = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    p2 = oauth.tokens(oauth.exchange(http, top.portal_svc, p1, top.portal_app["audience"], [READ]).expect(200)).access_token
    p3 = oauth.tokens(oauth.exchange(http, top.portal_svc, p2, top.edge_audience, [READ]).expect(200)).access_token
    p4 = oauth.tokens(oauth.exchange(http, top.edge, p3, top.orders_app["audience"], [READ]).expect(200)).access_token
    c1, c2 = v.access_token(p1, top.portal_app["audience"]), v.access_token(p2, top.portal_app["audience"])
    c3, c4 = v.access_token(p3, top.edge_audience), v.access_token(p4, top.orders_app["audience"])
    out.ok(c1["sub"] == c2["sub"] == c3["sub"] == c4["sub"] == top.member,
           "the represented person stays the subject at every hop")
    out.ok(c2["act"]["client_id"] == c3["act"]["client_id"] == c4["act"]["client_id"] == top.portal_svc.client_id,
           "the acting workload is recorded in act and the intermediary never becomes the actor")
    out.ok(c4["client_id"] == top.edge.client_id and c2["client_id"] == top.portal_svc.client_id,
           "client_id is the authenticated client of each exchange, distinct from subject and actor")
    out.ok(_scopes(c4) == [READ] and c4["exp"] <= c3["exp"] <= c2["exp"] <= c1["exp"]
           and c4["exp"] - c4["iat"] <= 300, "scope stays within the edge; lifetimes only shrink and are <= 5 minutes")
    out.facts["person_hops"] = [{"aud": c["aud"], "client_id": c.get("client_id"), "act": (c.get("act") or {}).get("client_id"),
                                 "token_use": c.get("token_use"), "lifetime_s": c["exp"] - c["iat"]} for c in (c1, c2, c3, c4)]

    # ------------------------------------------------------------------ workload only (no person)
    w1 = oauth.tokens(oauth.client_credentials(http, top.portal_svc, [READ]).expect(200)).access_token
    w2 = oauth.tokens(oauth.exchange(http, top.portal_svc, w1, top.edge_audience, [READ]).expect(200)).access_token
    w3 = oauth.tokens(oauth.exchange(http, top.edge, w2, top.orders_app["audience"], [READ]).expect(200)).access_token
    cw = v.access_token(w3, top.orders_app["audience"])
    out.ok(cw["sub"] == top.portal_svc.client_id and cw.get("identity_kind") == "workload",
           "a workload-only flow carries the workload as subject and no person")

    # ------------------------------------------------------------------ authorized workload-to-workload continuation
    to_reports = oauth.exchange(http, top.edge, p3, top.reports_app["audience"], [READ]).expect(200)
    r1 = oauth.tokens(to_reports).access_token
    r2 = oauth.tokens(oauth.exchange(http, top.reports_svc, r1, top.edge_audience, [READ]).expect(200)).access_token
    cr = v.access_token(r2, top.edge_audience)
    out.ok(cr["sub"] == top.member and cr["act"]["client_id"] == top.reports_svc.client_id,
           "continuation through an explicit workload edge keeps the person and names the new actor")

    # ------------------------------------------------------------------ denials
    out.refused(oauth.exchange(http, top.reports_svc, p1, top.reports_app["audience"], [READ]).status in (400, 401),
                "another workload cannot redeem a person's token from an application it does not belong to")
    out.refused(oauth.exchange(http, top.portal_svc, p2, top.edge_audience, [READ, WRITE]).oauth_error()
                in ("invalid_scope", "invalid_grant"), "the person's entitlement and the edge cap scope (no widening)")
    out.refused(oauth.exchange(http, top.portal_svc, p2, "https://unknown.cookbook.invalid", [READ]).oauth_error()
                in ("invalid_target", "invalid_grant"), "an audience without an explicit edge is refused")
    out.refused(oauth.exchange(http, top.portal_svc, p1, top.portal_app["audience"], [READ],
                               extra={"actor_token": p1.reveal(),
                                      "actor_token_type": oauth.ACCESS_TOKEN_TYPE}).oauth_error() == "invalid_request",
                "a caller cannot choose the actor (actor_token is refused)")
    out.refused(oauth.exchange(http, top.edge, p4, top.orders_app["audience"], [READ]).status in (400, 401),
                "a resource token is terminal: it cannot be exchanged onward")
    out.refused(oauth.exchange(http, top.edge, p2, top.orders_app["audience"], [READ]).status in (400, 401),
                "the intermediary cannot redeem a token that was not addressed to it")
    try:
        oauth.browser_login(http, top.web, top.outsider, top.outsider_password, ("openid", READ))
        outsider = True
    except oauth.LoginFailed:
        outsider = False
    out.refused(not outsider, "a person without access to the application gets no subject token to delegate")
    out.facts["receiver_view_of_p4"] = {k: unverified_claims(p4).get(k) for k in ("token_use", "authority_profile")}
    out.consumer_must += ["exchange per hop; never forward a token to another audience",
                          "receivers must check aud, scope and exp and decide how fresh status must be (O06)"]
    return out


if __name__ == "__main__":
    standalone(run)
