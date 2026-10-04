"""C05 — Authentication assurance: what Axiom asserts, what it refuses to let callers assert, and what is deferred.

Capability: IDP-15 (conditional; profile not selected). Native MFA/passkeys are deferred; Axiom's only first-party
authenticator is a password, so the only assurance it asserts is ``acr=urn:openwolf:axiom:acr:pwd`` with
``amr=["pwd"]`` and ``auth_time``. A stronger requirement fails closed until an authenticator and an assurance
vocabulary are selected (open decision: IDP-15 assurance profile).

1. Teaches: reading ``acr``/``amr``/``auth_time`` honestly. Population: workforce person, workload, customer.
2. Setup: the generic topology and one verified customer.
3. Records: topology, customer fixtures.
4. Calls: browser login, token exchange (with caller-supplied ``acr``/``acr_values``/``amr`` parameters),
   client credentials, customer sign-in.
5. Tokens: P1 (interactive login) carries assurance; exchanged P2 is observed and reported; workload and customer
   tokens carry none.
6. Positive: P1's assurance is the password level with a fresh ``auth_time``. Denials: caller-supplied assurance
   parameters never raise the issued ``acr``; tokens without an interactive login carry no ``auth_time``.
7. Status: ``auth_time`` ages; a receiver needing freshness compares it to its own bound.
8. Cleanup: fixtures.
9. Consumer must: require the acr/auth_time it needs per action and refuse when absent; never accept assurance
   written by a caller; treat stronger assurance as unavailable today.
"""
from __future__ import annotations

import time

from axiom_cookbook import ciam, oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone

READ = topology.READ
PASSWORD_ACR = "urn:openwolf:axiom:acr:pwd"


def run(ctx: Context) -> Outcome:
    out = Outcome("C05 authentication assurance")
    op = ctx.operator()
    top = topology.build(ctx, op)
    http, v = ctx.http, ctx.validator
    p1 = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    c1 = v.access_token(p1, top.portal_app["audience"])
    out.ok(c1.get("acr") == PASSWORD_ACR and c1.get("amr") == ["pwd"] and abs(time.time() - c1["auth_time"]) < 300,
           "an interactive login asserts the password level with a fresh auth_time")

    p2 = oauth.tokens(oauth.exchange(http, top.portal_svc, p1, top.portal_app["audience"], [READ]).expect(200)).access_token
    c2 = v.access_token(p2, top.portal_app["audience"])
    out.facts["exchange_preserves"] = {k: (k in c2 and c2[k] == c1[k]) for k in ("acr", "amr", "auth_time")}
    out.ok(c2.get("acr") in (None, PASSWORD_ACR), "an exchanged token never carries a higher acr than its subject")

    raised = oauth.exchange(http, top.portal_svc, p1, top.portal_app["audience"], [READ],
                            extra={"acr": "urn:example:mfa", "acr_values": "urn:example:mfa", "amr": "hwk"})
    if raised.status == 200:
        c3 = v.access_token(oauth.tokens(raised).access_token, top.portal_app["audience"])
        out.refused(c3.get("acr") != "urn:example:mfa" and "hwk" not in (c3.get("amr") or []),
                    "caller-supplied acr/amr parameters are ignored (assurance is never caller-written)")
    else:
        out.refused(True, "caller-supplied acr/amr parameters are refused (assurance is never caller-written)")
    out.facts["caller_assurance_request_status"] = raised.status

    w = oauth.tokens(oauth.client_credentials(http, top.portal_svc, [READ]).expect(200)).access_token
    cw = v.access_token(w, top.portal_app["audience"])
    out.refused("auth_time" not in cw and "acr" not in cw, "a workload token asserts no human authentication")
    shop = ctx.application(op, "shop")
    web, _ = ctx.public_client(op, shop, "shop-web", [READ])
    customer = ciam.verified(ctx, op, "assurance")
    cc = v.access_token(ciam.access_token(ciam.token(ctx, customer, web.client_id, [READ])), "axiom-token-exchange")
    out.refused("auth_time" not in cc and "acr" not in cc,
                "a customer token asserts no acr/auth_time (customer assurance is not modelled)")
    out.facts["deferred"] = "native MFA/passkeys; assurance vocabulary beyond password (IDP-15 profile not selected)"
    out.consumer_must += ["require acr/auth_time per sensitive action and refuse when absent or stale",
                          "treat any requirement above the password level as unavailable today"]
    return out


if __name__ == "__main__":
    standalone(run)
