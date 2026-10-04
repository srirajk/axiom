"""IDP-07 — current token status for an authorized consumer (RFC 7662 token introspection).

1. Teaches: asking Axiom whether a token is active now, as an authenticated resource server, and what each answer
   means. Populations: workforce, customer and software tokens.
2. Setup (setup adapter): an application with sign-in clients for both populations and a confidential service client
   that the resource server uses to authenticate to the introspection endpoint.
3. Records: application, clients, member, customer.
4. Calls: ``POST /oauth/introspect`` (form ``token``, optional ``token_type_hint``) with HTTP Basic or
   ``private_key_jwt``; the answer is ``{"active": true, ...claims}`` or exactly ``{"active": false}``.
5. Tokens: none issued by introspection. Software tokens have no person and no session: their status is the client's
   (and its workload's) live status — no session is fabricated.
6. Positive: active workforce, customer and software tokens report active with their claims. Denials: expired, revoked,
   unknown/garbage and logged-out tokens report ``active: false``; an unauthenticated or wrongly authenticated caller is
   refused (401) — a different outcome from "inactive". (Another tenant's client learns only ``active: false``: IDP-10.)
7. Status: answers reflect the current session, client, customer/person and edge state at the moment of the call (no
   cache in Axiom). Dependency outage: when Redis or PostgreSQL is unavailable introspection never answers active (the
   opt-in disruptive suite pauses each and checks recovery).
8. Cleanup: clients/application disabled, user disabled, customer suspended.
9. Consumer must: authenticate its introspection client, treat errors/timeouts as inactive (fail closed), decide its own
   cache interval (the residual window is that interval), and still check aud/scope itself.
"""
from __future__ import annotations

import time

from axiom_cookbook import ciam, oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret
from axiom_cookbook.topology import READ


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-07 introspection")
    http = ctx.http
    op = ctx.operator()
    app = ctx.application(op, "status")
    staff, _ = ctx.interactive_client(op, app, "status-staff", [READ])
    shop, _ = ctx.interactive_client(op, app, "status-shop", [READ], population="CUSTOMER")
    svc, _ = ctx.service_client(op, app, "status-svc", [READ])
    rs, _ = ctx.service_client(op, app, "status-rs", [READ])
    role = ctx.app_role(op, app, "reader", {READ: "allow"})
    person, pw = ctx.workforce_user(op, "ivy")
    ctx.membership(op, app, person, role["id"])
    customer = ciam.verified(ctx, op, "ina")

    wf = oauth.browser_login(http, staff, person, pw, ("openid", READ))
    cu = oauth.browser_login(http, shop, customer.email, customer.password, ("openid", READ))
    sw = oauth.tokens(oauth.client_credentials(http, svc, [READ]).expect(200))
    for label, tok, sub in (("workforce", wf.access_token, person), ("customer", cu.access_token, customer.id),
                            ("software", sw.access_token, svc.client_id)):
        view = oauth.introspect(http, rs, tok)
        out.ok(view["active"] is True and view["sub"] == sub and view.get("client_id") and view.get("exp"),
               f"{label} token: active with sub, client_id and exp")
    out.ok("sid" not in oauth.introspect(http, rs, sw.access_token), "software tokens have no session; none is fabricated")

    out.refused(oauth.introspect(http, rs, Secret("not-a-token", "garbage"))["active"] is False, "an unknown token is inactive")
    out.refused(http.post("/oauth/introspect", form={"token": wf.access_token}).status == 401,
                "an unauthenticated introspection call is refused (401, not 'inactive')")
    out.refused(http.post("/oauth/introspect", basic=(rs.client_id, Secret("wrong-secret-123456", "x")),
                          form={"token": wf.access_token}).status == 401, "a wrongly authenticated caller is refused")
    oauth.revoke(http, svc, sw.access_token).expect(200)
    out.refused(oauth.introspect(http, rs, sw.access_token)["active"] is False, "a revoked token is inactive")
    oauth.logout(http, wf.id_token)
    out.refused(oauth.introspect(http, rs, wf.access_token) == {"active": False}, "a logged-out session's token is exactly {active: false}")

    # Disclosure boundary across tenants (another tenant's client learns only {"active": false}) is exercised in IDP-10.

    # Expiry: a 30-second software token.
    short = oauth.tokens(oauth.client_credentials(http, svc, [READ]).expect(200))
    if 0 < short.expires_in <= 60:
        time.sleep(short.expires_in + 2)
        out.refused(oauth.introspect(http, rs, short.access_token)["active"] is False, "an expired token is inactive")
    out.facts["software_token_expires_in"] = short.expires_in
    out.consumer_must += ["authenticate introspection; treat any error or timeout as inactive",
                          "your cache interval is your residual window after revocation"]
    return out


if __name__ == "__main__":
    standalone(run)
