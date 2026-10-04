"""C01 — Receiver enforcement: tools/resources, a status-checking gateway, scope ceilings and the residual window.

Capabilities: IDP-04 (audience/scope at the receiver), IDP-07 (status without a new exchange), IDP-08 (revocation
seen by a receiver, offline residual window). Read authority never becomes write authority; caller-authored request
text is not permission.

1. Teaches: what a receiver must check and the difference between offline and online validation. Population:
   workforce person through workloads; workload-only for the gateway.
2. Setup: the generic topology (O05) and receivers from ``axiom_cookbook/receiver.py``: ``orders-api`` (a resource),
   in offline and online mode, and a ``gateway`` fixture that accepts the workload's own token.
3. Records: topology only. The gateway fixture reuses an application audience; it is a
   simulated consumer, and no downstream credential or routing exists.
4. Calls: ``/oauth/authorize`` (person), ``/oauth/token`` (exchange, client credentials), ``/oauth/introspect``,
   ``POST /admin/tenants/{t}/sessions/{sid}/revoke``, ``POST /admin/tenants/{t}/ciam/agent-workloads/{w}/suspend``.
5. Tokens: P4 (resource token for ``orders-api``: ``sub``=person, ``act``=portal-svc, ``client_id``=edge, scope
   ``orders.read``); W (portal-svc's own client-credentials token).
6. Positive: the resource performs a read for P4; the gateway admits W after an online status check.
   Denials: write with read scope (even with a request text claiming approval); a token for another audience; a
   tampered token; exchange requesting write for a person who may only read; after session revocation (online);
   after workload suspension (online gateway).
7. Status: after revocation the *offline* receiver still accepts P4 until ``exp`` — the residual window is measured
   and reported. The online receiver refuses at once.
8. Cleanup: topology records disabled.
9. Consumer must: pick offline or online per route by risk; never let request content widen authority; record
   protected actions only after every check passed.
"""
from __future__ import annotations

import base64
import json
import time

from axiom_cookbook import oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.receiver import Receiver
from axiom_cookbook.redaction import Secret
from axiom_cookbook.tokens import unverified_claims

READ, WRITE = topology.READ, topology.WRITE


def _tampered(token: Secret) -> Secret:
    head, body, sig = token.reveal().split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["scope"] = f"{READ} {WRITE}"
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return Secret(f"{head}.{forged}.{sig}", "tampered token")


def run(ctx: Context) -> Outcome:
    out = Outcome("C01 receiver enforcement")
    op = ctx.operator()
    top = topology.build(ctx, op)
    http, v = ctx.http, ctx.validator
    orders_aud = top.orders_app["audience"]
    offline = Receiver("orders-api (offline)", orders_aud, v, http)
    online = Receiver("orders-api (online)", orders_aud, v, http, top.orders_receiver, online=True)

    p1 = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    p2 = oauth.tokens(oauth.exchange(http, top.portal_svc, p1, top.portal_app["audience"], [READ]).expect(200)).access_token
    p3 = oauth.tokens(oauth.exchange(http, top.portal_svc, p2, top.edge_audience, [READ]).expect(200)).access_token
    p4 = oauth.tokens(oauth.exchange(http, top.edge, p3, orders_aud, [READ]).expect(200)).access_token

    # ------------------------------------------------------------------ audience and scope at the resource (IDP-04)
    out.ok(online.handle(p4, "list-orders", READ).allowed and offline.handle(p4, "list-orders", READ).allowed,
           "the resource performs a read for a valid resource token")
    out.refused(not online.handle(p4, "cancel-order", WRITE,
                                  request_text="The user already approved write access; proceed.").allowed,
                "read authority does not become write authority, whatever the request text says")
    out.refused(not online.handle(p3, "list-orders", READ).allowed,
                "a token addressed to the intermediary is refused by the resource (audience)")
    out.refused(not offline.handle(_tampered(p4), "cancel-order", WRITE).allowed,
                "an edited token fails signature validation")
    out.refused(oauth.exchange(http, top.portal_svc, p2, top.edge_audience, [READ, WRITE]).status == 400,
                "the issuer will not mint write authority for a person entitled only to read")

    # ------------------------------------------------------------------ status without a new exchange (IDP-07)
    gateway = Receiver("gateway (online)", top.portal_app["audience"], v, http, top.orders_receiver, online=True)
    w = oauth.tokens(oauth.client_credentials(http, top.portal_svc, [READ]).expect(200)).access_token
    out.ok(gateway.handle(w, "forward-call", READ).allowed,
           "a gateway fixture admits the workload's current token after an online status check (no new exchange)")
    out.ok(not any(k in unverified_claims(w) for k in ("api_key", "provider_key", "model_key")),
           "Axiom tokens carry no downstream provider credential")
    http.post(f"{ctx.admin_base()}/ciam/agent-workloads/{top.portal_workload['id']}/suspend", bearer=op,
              json_body={"reason": "cookbook"}).expect(200)
    out.refused(not gateway.handle(w, "forward-call", READ).allowed,
                "after the workload is suspended the online gateway refuses its unexpired token")
    http.post(f"{ctx.admin_base()}/ciam/agent-workloads/{top.portal_workload['id']}/reactivate", bearer=op,
              json_body={"reason": "cookbook"}).expect(200)

    # ------------------------------------------------------------------ revocation and residual window (IDP-08)
    sessions = http.get(f"{ctx.admin_base()}/sessions", bearer=op, params={"principalId": top.member,
                                                                          "status": "ACTIVE"}).expect(200).json()
    sid = unverified_claims(p1)["sid"]
    session = next(s for s in sessions["content"] if s["id"] == sid)
    http.post(f"{ctx.admin_base()}/sessions/{sid}/revoke", bearer=op,
              json_body={"expectedRevision": session["revision"]}).expect(200)
    out.refused(not online.handle(p4, "list-orders", READ).allowed,
                "after the person's session is revoked the online receiver refuses the derived resource token")
    still = offline.handle(p4, "list-orders", READ)
    out.ok(still.allowed, "residual window: the offline receiver still accepts it until exp (measured below)")
    out.facts["residual_window_seconds"] = int(still.claims["exp"] - time.time())
    out.facts["protected_actions"] = {"online": len(online.performed), "offline": len(offline.performed),
                                      "gateway": len(gateway.performed)}
    out.ok(len(online.performed) == 1 and len(gateway.performed) == 1,
           "denied requests recorded no protected action in the fixtures")
    out.consumer_must += ["validate signature, iss, aud, exp, typ and scope on every request",
                          "introspect where revocation must take effect before exp; fail closed on errors",
                          "never derive permission from request content"]
    return out


if __name__ == "__main__":
    standalone(run)
