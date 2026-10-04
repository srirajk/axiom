"""IDP-05 — token exchange for permitted downstream tokens, for workforce, CIAM and software-only callers
(RFC 8693; Axiom's delegation profile).

1. Teaches: how a service turns the token it received into a narrower token for the next hop, keeping three things
   apart: the represented subject (``sub``), the current actor (``act``) and the authenticated client (``client_id``).
   Populations: workforce person, customer, software only.
2. Setup (setup adapter): an application ``portal`` with a workforce client, a customer-facing client and a service
   client registered as a workload; an intermediary (``edge``) with its audience; a resource (``orders-api``); explicit
   exchange edges portal-svc → edge and portal-svc → orders-api (via edge). Registration alone grants nothing.
3. Records: applications, clients, workloads, intermediary, edges, a member, a customer.
4. Calls: ``POST /oauth/token`` with ``grant_type=urn:ietf:params:oauth:grant-type:token-exchange``,
   ``subject_token``, ``subject_token_type=urn:ietf:params:oauth:token-type:access_token``, ``audience`` (or
   ``resource``) and ``scope``, authenticated as the exchanging client. ``actor_token`` is not accepted: the actor is
   the authenticated workload, never a caller-chosen value.
5. Tokens per hop: subject token (aud=portal, sub=person|customer) → hop 1 (client=portal-svc, aud=portal,
   act=portal-svc) → hop 2 (client=portal-svc, aud=edge) → hop 3 (client=edge, aud=orders-api, act still portal-svc).
   ``sub`` never changes; lifetimes only shrink; scope only narrows.
6. Positive: workforce and customer chains reach the resource with the subject preserved and the intermediary never
   becoming the actor; a software-only token follows its own edge. Denials: a workload of another application
   (cross-subject borrowing), widening scope, a destination without an edge, a caller-chosen actor (``actor_token``),
   onward exchange of a resource token, an intermediary redeeming a token not addressed to it, and a customer token
   presented on the workforce path of another application.
7. Status: every hop is re-checked against current state (session, membership/customer status, client, edges).
8. Cleanup: edges/intermediary revoked, workloads retired, clients/applications disabled, user disabled, customer suspended.
9. Consumer must: exchange per hop, never forward a token to another audience, validate ``aud``/``scope``/``exp`` at
   each receiver, and log ``sub``/``act``/``client_id`` separately.
"""
from __future__ import annotations

from axiom_cookbook import ciam, oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.topology import READ, WRITE


def _aud(claims):
    aud = claims["aud"]
    return aud if isinstance(aud, str) else aud[0]


def _scopes(claims) -> set[str]:
    raw = claims.get("scope", "")
    return set(raw.split()) if isinstance(raw, str) else set(raw)


def chain(ctx, top, subject_token, out, label):
    http, v = ctx.http, ctx.validator
    subject = v.access_token(subject_token, top.portal_app["audience"])
    h1 = oauth.tokens(oauth.exchange(http, top.portal_svc, subject_token, top.portal_app["audience"], [READ]).expect(200))
    c1 = v.access_token(h1.access_token, top.portal_app["audience"])
    h2 = oauth.tokens(oauth.exchange(http, top.portal_svc, h1.access_token, top.edge_audience, [READ]).expect(200))
    c2 = v.access_token(h2.access_token, top.edge_audience)
    h3 = oauth.tokens(oauth.exchange(http, top.edge, h2.access_token, top.orders_app["audience"], [READ]).expect(200))
    c3 = v.access_token(h3.access_token, top.orders_app["audience"])
    out.ok(subject["sub"] == c1["sub"] == c2["sub"] == c3["sub"], f"{label}: the represented subject is preserved at every hop")
    out.ok(c1["act"]["client_id"] == c2["act"]["client_id"] == c3["act"]["client_id"] == top.portal_svc.client_id,
           f"{label}: the acting workload is recorded in act; the intermediary never becomes the actor")
    out.ok(c1["client_id"] == top.portal_svc.client_id and c3["client_id"] == top.edge.client_id,
           f"{label}: client_id is the authenticated exchanging client, distinct from sub and act")
    out.ok(_scopes(c3) == {READ} and c3["exp"] <= c2["exp"] <= c1["exp"] <= subject["exp"],
           f"{label}: scope narrows to the edge; lifetimes only shrink")
    out.refused(oauth.exchange(http, top.edge, h3.access_token, top.orders_app["audience"], [READ]).status in (400, 401),
                f"{label}: a resource token is terminal")
    return h1, h3


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-05 token exchange (workforce, CIAM, software)")
    http, v = ctx.http, ctx.validator
    op = ctx.operator()
    top = topology.build(ctx, op)
    shop_web, _ = ctx.interactive_client(op, top.portal_app, "portal-shop", [READ], population="CUSTOMER")
    customer = ciam.verified(ctx, op, "cleo")

    person_token = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    p1, _ = chain(ctx, top, person_token, out, "workforce")
    customer_token = oauth.browser_login(http, shop_web, customer.email, customer.password, ("openid", READ)).access_token
    chain(ctx, top, customer_token, out, "customer")
    out.facts["hops"] = ["subject (aud=portal)", "portal-svc (aud=portal)", "portal-svc (aud=edge)", "edge (aud=orders-api)"]

    # Software only: the workload's own token follows its own edge to the intermediary; no person appears.
    own = oauth.tokens(oauth.client_credentials(http, top.portal_svc, [READ]).expect(200)).access_token
    sw = oauth.tokens(oauth.exchange(http, top.portal_svc, own, top.edge_audience, [READ]).expect(200))
    sc = v.access_token(sw.access_token, top.edge_audience)
    out.ok(sc["sub"] == top.portal_svc.client_id and sc["act"]["client_id"] == top.portal_svc.client_id,
           "software only: the workload is both subject and actor; no person is invented")

    # Denials.
    out.refused(oauth.exchange(http, top.reports_svc, person_token, top.reports_app["audience"], [READ]).status == 400,
                "a workload of another application cannot redeem the person's token")
    out.refused(oauth.exchange(http, top.reports_svc, customer_token, top.reports_app["audience"], [READ]).status == 400,
                "a workload of another application cannot redeem the customer's token")
    out.refused(oauth.exchange(http, top.portal_svc, person_token, top.portal_app["audience"], [READ, WRITE]).status == 400,
                "scope cannot widen beyond the subject's entitlement")
    out.refused(oauth.exchange(http, top.portal_svc, p1.access_token, "https://unregistered.cookbook.invalid", [READ]).status == 400,
                "a destination without an edge is refused")
    out.refused(oauth.exchange(http, top.portal_svc, person_token, top.portal_app["audience"], [READ],
                               {"actor_token": own.reveal(), "actor_token_type": oauth.ACCESS_TOKEN_TYPE}).status == 400,
                "a caller cannot choose the actor (actor_token is refused)")
    out.refused(oauth.exchange(http, top.edge, p1.access_token, top.orders_app["audience"], [READ]).status == 400,
                "the intermediary cannot redeem a token that was not addressed to it")
    out.consumer_must += ["exchange per hop; never forward a token to another audience",
                          "record sub, act and client_id separately; act is history, not extra authority"]
    return out


if __name__ == "__main__":
    standalone(run)
