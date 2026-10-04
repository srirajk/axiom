"""Opt-in dependency outage and restart checks (AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1), only on the run's own estate.

Outages pause the run's own PostgreSQL/Redis containers; the restart restarts only the run's Axiom process. Each test
restores health and verifies recovery without reviving withdrawn authority.
"""
from __future__ import annotations

import os
import time

import pytest

from axiom_cookbook import estate as estate_module, oauth, topology
from axiom_cookbook.context import ADMIN_CLIENT
from axiom_cookbook.example import Outcome
from oauth.o07_renewal import _approve, _handle, _redeem
from tests.conftest import record

pytestmark = pytest.mark.disruptive

READ = topology.READ


@pytest.fixture
def owned(ctx):
    if os.environ.get("AXIOM_COOKBOOK_ALLOW_DISRUPTIVE") != "1":
        pytest.skip("disruptive checks need AXIOM_COOKBOOK_ALLOW_DISRUPTIVE=1")
    if ctx.estate is None or os.environ.get("AXIOM_COOKBOOK_STATE"):
        pytest.skip("disruptive checks run only against the estate this session started")
    return ctx.estate


RECOVERY_TIMEOUT_S = 60


def _active(view) -> bool:
    """True only for an introspection response that is a dict with active == True."""
    return isinstance(view, dict) and view.get("active") is True


def _safe(call):
    try:
        return call()
    except Exception as e:  # a timeout or connection failure is also "no authority granted"
        return e


def test_dependency_outages_fail_closed_and_recover(ctx, owned):
    out = Outcome("O06/O05 dependency outages (disruptive)")
    op = ctx.operator()
    top = topology.build(ctx, op)
    person = oauth.browser_login(ctx.http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    estate_module.pause(owned, "redis")
    try:
        view = _safe(lambda: oauth.introspect(ctx.http, top.orders_receiver, person))
        out.refused(not _active(view), "Redis down: introspection never says active")
        issued = _safe(lambda: oauth.client_credentials(ctx.http, top.portal_svc, [READ]))
        out.refused(not (hasattr(issued, "status") and issued.status == 200), "Redis down: no token is issued")
    finally:
        estate_module.unpause(owned, "redis")
    time.sleep(1)
    estate_module.pause(owned, "postgres")
    try:
        exchanged = _safe(lambda: oauth.exchange(ctx.http, top.portal_svc, person, top.portal_app["audience"], [READ]))
        out.refused(not (hasattr(exchanged, "status") and exchanged.status == 200), "PostgreSQL down: no exchange")
    finally:
        estate_module.unpause(owned, "postgres")
    # Recovery means a genuinely active introspection result. An exception, an error body or active=false all keep
    # waiting; the wait is bounded and a service that never recovers fails the test.
    started, recovered = time.monotonic(), False
    while time.monotonic() - started < RECOVERY_TIMEOUT_S:
        if _active(_safe(lambda: oauth.introspect(ctx.http, top.orders_receiver, person))):
            recovered = True
            break
        time.sleep(1)
    out.facts["recovery_seconds"] = round(time.monotonic() - started, 1)
    out.ok(recovered, f"after recovery the token is active again (within {RECOVERY_TIMEOUT_S}s)")
    out.ok(oauth.exchange(ctx.http, top.portal_svc, person, top.portal_app["audience"], [READ]).status == 200,
           "after recovery exchange works again")
    record(out)


def test_restart_keeps_keys_and_does_not_revive_withdrawn_authority(ctx, owned):
    out = Outcome("O08 restart recovery (disruptive)")
    op = ctx.operator()
    kids_before = {k["kid"] for k in ctx.http.get("/oauth2/jwks").expect(200).json()["keys"]}
    erin, password = ctx.workforce_user(op, "restart-user")
    revoked = oauth.browser_login(ctx.http, ADMIN_CLIENT, erin, password, ("openid",)).access_token
    kept = oauth.browser_login(ctx.http, ADMIN_CLIENT, erin, password, ("openid",)).access_token
    sid = ctx.validator.access_token(revoked, "axiom-api")["sid"]
    session = next(s for s in ctx.http.get("/api/me/sessions", bearer=kept).expect(200).json() if s["id"] == sid)
    ctx.http.post(f"/api/me/sessions/{sid}/revoke", bearer=kept, json_body={"expectedRevision": session["revision"]}).expect(200)
    # Renewal authority approved before the restart must survive it; withdrawn authority must not revive.
    top = topology.build(ctx, op)
    owner = oauth.browser_login(ctx.http, ADMIN_CLIENT, top.member, top.member_password, ("openid",)).access_token
    standing = _approve(ctx, owner, top, 1800)
    handle = _handle(_redeem(ctx, top, standing["id"], None).expect(200))
    gone = _approve(ctx, owner, top, 1800)
    gone_handle = _handle(_redeem(ctx, top, gone["id"], None).expect(200))
    ctx.http.post(f"/api/me/standing-grants/{gone['id']}/revoke", bearer=owner,
                  json_body={"reason": "withdrawn before restart"}).expect(200)
    estate_module.restart_server(owned)
    kids_after = {k["kid"] for k in ctx.http.get("/oauth2/jwks").expect(200).json()["keys"]}
    out.ok(kids_before == kids_after, "signing keys survive the restart unchanged")
    out.refused(ctx.http.get("/api/me/sessions", bearer=revoked).status == 401,
                "a session revoked before the restart stays revoked")
    out.ok(ctx.http.get("/api/me/sessions", bearer=kept).status == 200, "an active session survives the restart")
    out.ok(ctx.validator.access_token(oauth.browser_login(ctx.http, ADMIN_CLIENT, erin, password, ("openid",)).access_token,
                                      "axiom-api")["sub"] == erin, "new logins work after the restart")
    out.ok(_redeem(ctx, top, standing["id"], handle).status == 200,
           "a standing grant approved before the restart still renews with its current handle")
    out.refused(_redeem(ctx, top, gone["id"], gone_handle).status in (400, 401),
                "a standing grant withdrawn before the restart is not revived")
    record(out)
