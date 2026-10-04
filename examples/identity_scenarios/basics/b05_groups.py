"""B05 — Groups (teams): membership is not authorization.

1. Teaches: ``/teams`` manages directory groups and their members. Axiom does *not* derive roles or permissions from
   group membership: a team's ``defaultRoles`` is stored descriptive metadata that nothing applies. The relationship
   Axiom does enforce is ownership of a workload identity (see IDP-09/IDP-11). SCIM can also manage groups (not used here).
   Population: workforce.
2. Setup: provisioning operator (``tenant_admin`` may write teams).
3. Records: one team, one member.
4. Calls: ``POST /teams``, ``POST /teams/{id}/members`` ``{userId}``, ``GET /teams/{id}/members``,
   ``GET /users/{id}/teams``, ``DELETE /teams/{id}/members/{userId}``.
5. Tokens: the member's Axiom token before and after joining the team — identical role claims.
6. Positive: add/list/remove members. Denials: a team listed as granting a role does not put it in the token; a
   non-administrator cannot create teams.
7. Expiry: n/a. 8. Cleanup: team deleted (Axiom supports deleting a team), user disabled.
9. Consumer must: if it authorizes by group, read membership from its own authoritative source (SCIM, directory);
   Axiom tokens do not carry groups.
"""
from __future__ import annotations

from axiom_cookbook import oauth
from axiom_cookbook.context import ADMIN_CLIENT, Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.tokens import unverified_claims


def run(ctx: Context) -> Outcome:
    out = Outcome("B05 groups")
    op = ctx.operator()
    carol, password = ctx.workforce_user(op, "carol")
    team = ctx.http.post("/teams", bearer=op, json_body={"name": ctx.name("finance"),
                                                         "defaultRoles": ["tenant_admin"]}).expect(201).json()
    ctx.registry.add("team", team["id"], lambda: ctx.http.delete(f"/teams/{team['id']}", bearer=ctx.operator()), "delete")
    before = unverified_claims(oauth.browser_login(ctx.http, ADMIN_CLIENT, carol, password, ("openid", "roles")).access_token)
    ctx.http.post(f"/teams/{team['id']}/members", bearer=op, json_body={"userId": carol}).expect(201)
    members = [u["id"] for u in ctx.http.get(f"/teams/{team['id']}/members", bearer=op).expect(200).json()]
    out.ok(carol in members, "the user is listed as a team member")
    teams = ctx.http.get(f"/users/{carol}/teams", bearer=op).expect(200).json()
    out.ok(team["name"] in teams["teams"], "the user's teams include the new team")
    after_token = oauth.browser_login(ctx.http, ADMIN_CLIENT, carol, password, ("openid", "roles")).access_token
    after = unverified_claims(after_token)
    out.refused(after.get("roles") == before.get("roles") and "tenant_admin" not in after.get("roles", []),
                "joining a team whose defaultRoles names tenant_admin grants no role")
    out.refused(ctx.http.post("/teams", bearer=after_token, json_body={"name": ctx.name("x")}).status == 403,
                "a non-administrator cannot create teams")
    ctx.http.delete(f"/teams/{team['id']}/members/{carol}", bearer=op).expect(204)
    members = [u["id"] for u in ctx.http.get(f"/teams/{team['id']}/members", bearer=op).expect(200).json()]
    out.ok(carol not in members, "membership removed")
    out.consumer_must.append("source group membership from the directory; Axiom tokens carry no groups")
    return out


if __name__ == "__main__":
    standalone(run)
