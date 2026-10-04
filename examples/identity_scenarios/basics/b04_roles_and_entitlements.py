"""B04 — Roles and application entitlements, their token effect and their freshness boundary.

1. Teaches: Axiom has two kinds of roles. *Tenant roles* (``platform_admin``, ``tenant_admin``) govern Axiom's own
   administration. *Application roles* carry an application's permissions (each with an effect: ``allow``, ``read``,
   ``scoped`` or ``cosign``) into that application's tokens. Population: workforce.
2. Setup: provisioning operator (application access); root administrator only for tenant roles.
3. Records: an application with a browser client, one application role, a membership for ``<ns>-bob``.
4. Calls: ``POST .../access/roles``, ``POST .../access/memberships``, ``POST .../memberships/{m}/roles``,
   ``DELETE .../memberships/{m}/roles/{role}``; browser login to the application's public client.
5. Tokens: the application access token carries ``roles`` (role keys), ``permissions`` and ``entitlement_revision``.
6. Positive: an assigned role appears in the next login's token. Denials: a non-member cannot log in to the
   application; a role from another application cannot be assigned; after removal a new login lacks the permission.
7. Freshness boundary (documented, observed): a token issued *before* the removal still carries the old claim until it
   expires — Axiom does not rewrite issued JWTs. Axiom's own exchange path re-checks entitlement live (see O05).
8. Cleanup: membership disabled; application and client disabled.
9. Consumer must: authorize on fresh tokens or via an exchange/introspection that re-checks entitlement; never on a
   permission claim older than its risk tolerance.
"""
from __future__ import annotations

from axiom_cookbook import oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.tokens import unverified_claims


def run(ctx: Context) -> Outcome:
    out = Outcome("B04 roles and entitlements")
    op = ctx.operator()
    app = ctx.application(op, "reports")
    web, _ = ctx.public_client(op, app, "reports-web", ["reports.read", "ledger.write"])
    other_app = ctx.application(op, "other")
    reader = ctx.app_role(op, app, "reader", {"reports.read": "allow"})
    foreign = ctx.app_role(op, other_app, "foreign", {"reports.read": "allow"})
    bob, password = ctx.workforce_user(op, "bob")
    scopes = ("openid", "reports.read")

    try:
        oauth.browser_login(ctx.http, web, bob, password, scopes)
        non_member = True
    except oauth.LoginFailed:
        non_member = False
    out.refused(not non_member, "a user without a membership cannot log in to the application")

    member = ctx.membership(op, app, bob, reader["id"])
    access = f"{ctx.admin_base()}/applications/{app['id']}/access/memberships/{member['id']}/roles"
    cross = ctx.http.post(access, bearer=op, json_body={"roleId": foreign["id"], "assignmentSource": "cookbook"})
    out.refused(cross.status in (400, 404, 409), "a role belonging to another application cannot be assigned")

    before = oauth.browser_login(ctx.http, web, bob, password, scopes).access_token
    claims = ctx.validator.access_token(before, app["audience"])
    out.ok("reports.read" in claims.get("permissions", []) and claims["aud"] == app["audience"],
           "the application token carries the role's permission and the application's audience")
    out.facts["entitlement_revision_before"] = claims.get("entitlement_revision")

    ctx.http.delete(f"{access}/{reader['id']}", bearer=op).expect(200)
    try:
        after = oauth.browser_login(ctx.http, web, bob, password, scopes).access_token
        after_permissions = unverified_claims(after).get("permissions", [])
    except oauth.LoginFailed:
        after_permissions = []
    out.refused("reports.read" not in after_permissions, "after removal a new login does not carry the permission")
    out.ok("reports.read" in unverified_claims(before).get("permissions", []),
           "freshness boundary: the earlier token still carries the old claim until it expires")
    out.consumer_must.append("treat permission claims as of issuance; re-check through exchange or a fresh token")
    return out


if __name__ == "__main__":
    standalone(run)
