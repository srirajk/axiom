"""B02 — Workforce user lifecycle: create, read, update, disable; duplicate and wrong-tenant administration refused.

1. Teaches: managing workforce people through ``/users``. Population: workforce.
2. Setup: the provisioning operator (``tenant_admin``). The tenant comes from the operator's token, never from input.
3. Records: one workforce user ``<namespace>-alice``; its id is the token ``sub`` after login.
4. Calls: ``POST /users`` (201), ``GET /users/{id}``, ``PUT /users/{id}`` ``{email}``/``{isActive:false}``,
   ``GET /api/me/sessions``; cross-tenant ``GET /admin/tenants/{other}/sessions`` (refused).
5. Tokens: the user's own Axiom API token (browser login) is bound to a durable session.
6. Positive: create/read/update; the user can list their own sessions. Denials: duplicate id (409); another tenant's
   administration (403); after disable, the existing token and a new login are both refused.
7. Expiry/status: disabling the user revokes every session immediately (no wait for token expiry).
8. Cleanup: soft delete (``DELETE /users/{id}`` disables; Axiom keeps the record for audit).
9. Consumer must: treat 401 on a previously valid token as "re-authenticate", not as a transient error.
"""
from __future__ import annotations

from axiom_cookbook import oauth
from axiom_cookbook.context import ADMIN_CLIENT, Context, strong_password
from axiom_cookbook.example import Outcome, standalone


def run(ctx: Context) -> Outcome:
    out = Outcome("B02 workforce user lifecycle")
    op = ctx.operator()
    alice, password = ctx.workforce_user(op, "alice")
    read = ctx.http.get(f"/users/{alice}", bearer=op).expect(200).json()
    out.ok(read["username"] == alice and read["isActive"] is True, "created user is readable and active")
    updated = ctx.http.put(f"/users/{alice}", bearer=op, json_body={"email": f"{alice}@updated.invalid"}).expect(200).json()
    out.ok(updated["email"].endswith("@updated.invalid"), "user email updated")
    dup = ctx.http.post("/users", bearer=op, json_body={"id": alice, "username": alice + "x",
                                                        "email": "dup@cookbook.invalid",
                                                        "password": strong_password().reveal()})
    out.refused(dup.status == 409, "a duplicate user id is refused (409)")
    other = ctx.http.get("/admin/tenants/some-other-tenant/sessions", bearer=op)
    out.refused(other.status in (403, 404), "a tenant_admin cannot administer another tenant")

    token = oauth.browser_login(ctx.http, ADMIN_CLIENT, alice, password, ("openid",)).access_token
    sessions = ctx.http.get("/api/me/sessions", bearer=token).expect(200).json()
    out.ok(len(sessions) >= 1, "the user sees their own active session")

    ctx.http.put(f"/users/{alice}", bearer=op, json_body={"isActive": False}).expect(200)
    out.refused(ctx.http.get("/api/me/sessions", bearer=token).status == 401,
                "after disable the user's existing token is refused (session revoked)")
    try:
        oauth.browser_login(ctx.http, ADMIN_CLIENT, alice, password, ("openid",))
        relogin = True
    except oauth.LoginFailed:
        relogin = False
    out.refused(not relogin, "a disabled user cannot log in again")
    out.consumer_must.append("re-check status (introspection or a fresh exchange) instead of trusting cached tokens")
    return out


if __name__ == "__main__":
    standalone(run)
