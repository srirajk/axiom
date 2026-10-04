"""O07 — Renewal. Axiom issues no refresh tokens; the only renewal mechanism is its standing-grant extension.

1. Teaches: how long-running or offline work keeps authority without a person present — and what is *not* offered.
   Population: workforce person (owner) and a workload.
2. Setup: the generic topology; the person holds ``orders.read`` with effect ``allow`` in the workload's application;
   the workload has an explicit edge to the resource.
3. Records: one standing grant (Axiom-specific; ``urn:openwolf:params:oauth:grant-type:standing-grant`` is an
   extension grant, not RFC 6749 refresh).
4. Calls: ``POST /api/me/standing-grants`` (owner, with an interactive login no older than the server's limit);
   ``POST /oauth/token`` ``grant_type=…standing-grant`` + ``standing_grant`` + ``renewal_handle`` (the workload's
   client authentication); ``POST /api/me/standing-grants/{id}/revoke``.
5. Tokens: each redemption returns a short-lived access token for the resource (``sub``=owner, ``act``=workload) and
   a *new* single-use renewal handle; the previous handle is spent.
6. Positive: first claim, rotation. Denials: the standard ``refresh_token`` grant for this *service* client (standard
   refresh exists for confidential web clients granted ``offline_access``: IDP-06; this extension is separate); reuse of a spent
   handle (and the grant is withdrawn as compromised); concurrent redemption with one handle (exactly one wins);
   an access token offered as renewal input; renewal after withdrawal; renewal after the grant expires.
7. Expiry: the grant has its own expiry (bounded by the edge); its tokens live at most 5 minutes.
8. Cleanup: grants revoked; topology disabled.
9. Consumer must: persist the newest handle atomically, serialize renewals per grant, never retry with an old handle.
"""
from __future__ import annotations

import datetime as dt
import threading
import time

from axiom_cookbook import oauth, topology
from axiom_cookbook.context import ADMIN_CLIENT, Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret

READ = topology.READ
GRANT = "urn:openwolf:params:oauth:grant-type:standing-grant"


def _approve(ctx: Context, owner_token: Secret, top, seconds: int) -> dict:
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()
    return ctx.http.post("/api/me/standing-grants", bearer=owner_token, json_body={
        "agentWorkloadId": top.portal_workload["id"], "audience": top.orders_app["audience"], "scopes": [READ],
        "purpose": "nightly reconciliation", "expiresAt": expires}).expect(201).json()


def _redeem(ctx: Context, top, grant: str, handle: Secret | None, extra: dict | None = None):
    form = {"grant_type": GRANT, "standing_grant": grant, "scope": READ}
    if handle is not None:
        form["renewal_handle"] = handle
    form.update(extra or {})
    return ctx.http.post("/oauth/token", basic=top.portal_svc.basic(), form=form)


def _handle(response) -> Secret:
    return Secret(response.json()["renewal_handle"], "renewal handle")


def run(ctx: Context) -> Outcome:
    out = Outcome("O07 renewal (standing-grant extension)")
    op = ctx.operator()
    top = topology.build(ctx, op)
    refresh = ctx.http.post("/oauth/token", basic=top.portal_svc.basic(), form={
        "grant_type": "refresh_token", "refresh_token": "anything"})
    out.facts["refresh_token_probe"] = {"status": refresh.status, "error": refresh.oauth_error()}
    out.refused(refresh.status == 400 and refresh.oauth_error() in ("unsupported_grant_type", "unauthorized_client", "invalid_grant"),
                "the workload's service client is not registered for the standard refresh grant (see IDP-06)")
    owner = oauth.browser_login(ctx.http, ADMIN_CLIENT, top.member, top.member_password, ("openid",)).access_token

    grant = _approve(ctx, owner, top, 1800)
    first = _redeem(ctx, top, grant["id"], None).expect(200)
    h1 = _handle(first)
    access = oauth.tokens(first).access_token
    claims = ctx.validator.access_token(access, top.orders_app["audience"])
    out.ok(claims["sub"] == top.member and claims["act"]["client_id"] == top.portal_svc.client_id
           and claims["exp"] - claims["iat"] <= 300, "the workload acts for the absent owner with a short-lived token")
    out.refused(_redeem(ctx, top, grant["id"], None, {"subject_token": access.reveal()}).oauth_error()
                == "invalid_request", "an access token is never accepted as renewal input")
    second = _redeem(ctx, top, grant["id"], h1).expect(200)
    h2 = _handle(second)
    out.ok(h2 != h1, "each renewal rotates the handle")
    out.refused(_redeem(ctx, top, grant["id"], h1).oauth_error() == "invalid_grant", "a spent handle is refused")
    out.refused(_redeem(ctx, top, grant["id"], h2).oauth_error() == "invalid_grant",
                "reuse of a spent handle withdraws the whole grant (the current handle stops too)")
    out.refused(not oauth.introspect(ctx.http, top.orders_receiver, oauth.tokens(second).access_token)["active"],
                "tokens of a withdrawn grant are inactive")

    racing = _approve(ctx, owner, top, 1800)
    handle = _handle(_redeem(ctx, top, racing["id"], None).expect(200))
    statuses: list[int] = []
    threads = [threading.Thread(target=lambda: statuses.append(_redeem(ctx, top, racing["id"], handle).status))
               for _ in range(5)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    out.ok(statuses.count(200) == 1, "five concurrent renewals with one handle: exactly one succeeds")
    out.facts["concurrent_statuses"] = sorted(statuses)

    withdrawn = _approve(ctx, owner, top, 1800)
    wh = _handle(_redeem(ctx, top, withdrawn["id"], None).expect(200))
    ctx.http.post(f"/api/me/standing-grants/{withdrawn['id']}/revoke", bearer=owner,
                  json_body={"reason": "no longer needed"}).expect(200)
    out.refused(_redeem(ctx, top, withdrawn["id"], wh).oauth_error() == "invalid_grant",
                "after the owner withdraws, renewal is refused")

    short = _approve(ctx, owner, top, 8)
    sh = _handle(_redeem(ctx, top, short["id"], None).expect(200))
    time.sleep(9)
    out.refused(_redeem(ctx, top, short["id"], sh).oauth_error() == "invalid_grant", "an expired grant cannot renew")
    out.consumer_must += ["store the newest renewal handle atomically and serialize renewals per grant",
                          "never retry a renewal with an older handle (Axiom treats it as theft)"]
    return out


if __name__ == "__main__":
    standalone(run)
