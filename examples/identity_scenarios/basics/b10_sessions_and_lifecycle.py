"""B10 — Sessions, workload suspension/retirement and authorized versus unauthorized administration.

1. Teaches: ending authority deliberately. Population: workforce person, workload, operators.
2. Setup: provisioning operator; a person with two independent logins; a workload.
3. Records: person, application, workload.
4. Calls: ``GET /api/me/sessions``, ``POST /api/me/sessions/{id}/revoke`` ``{expectedRevision}``;
   ``GET /admin/tenants/{t}/sessions``; ``POST …/ciam/agent-workloads/{id}/suspend|reactivate|retire``;
   ``POST /admin/tenants/{t}/identity-control-requests`` (credential rotation proposal) as a non-administrator.
5. Tokens: each login is its own durable session; revoking one does not touch the other.
6. Positive: self-service revocation of one session; suspension and reactivation; retirement. Denials: the revoked
   session's token; revoking someone else's session (404); a stale ``expectedRevision`` (409); reactivating a retired
   workload (409); a non-administrator proposing a credential rotation (403).
7. Status: session revocation is immediate for every session-checking validator and introspection.
8. Cleanup: person disabled, workload retired (already), application disabled.
9. Consumer must: surface "signed out elsewhere" to users; stop scheduling work for a suspended workload.
"""
from __future__ import annotations

from axiom_cookbook import oauth
from axiom_cookbook.context import ADMIN_CLIENT, Context
from axiom_cookbook.example import Outcome, standalone


def run(ctx: Context) -> Outcome:
    out = Outcome("B10 sessions and lifecycle")
    op = ctx.operator()
    erin, password = ctx.workforce_user(op, "erin")
    one = oauth.browser_login(ctx.http, ADMIN_CLIENT, erin, password, ("openid",)).access_token
    two = oauth.browser_login(ctx.http, ADMIN_CLIENT, erin, password, ("openid",)).access_token
    mine = ctx.http.get("/api/me/sessions", bearer=one).expect(200).json()
    out.ok(len(mine) >= 2, "the person sees each login as its own session")
    sid_one = ctx.validator.access_token(one, "axiom-api")["sid"]
    target = next(s for s in mine if s["id"] == sid_one)
    stale = ctx.http.post(f"/api/me/sessions/{sid_one}/revoke", bearer=two,
                          json_body={"expectedRevision": target["revision"] + 5})
    out.refused(stale.status == 409, "a stale expectedRevision is refused")
    ctx.http.post(f"/api/me/sessions/{sid_one}/revoke", bearer=two,
                  json_body={"expectedRevision": target["revision"]}).expect(200)
    out.refused(ctx.http.get("/api/me/sessions", bearer=one).status == 401, "the revoked session's token is refused")
    out.ok(ctx.http.get("/api/me/sessions", bearer=two).status == 200, "the other session continues")
    operator_sid = ctx.validator.access_token(op, "axiom-api")["sid"]
    out.refused(ctx.http.post(f"/api/me/sessions/{operator_sid}/revoke", bearer=two,
                              json_body={"expectedRevision": 0}).status == 404,
                "a person cannot revoke someone else's session")
    listed = ctx.http.get(f"{ctx.admin_base()}/sessions", bearer=op, params={"principalId": erin}).expect(200).json()
    out.ok(len(listed["content"]) >= 2, "an administrator lists the person's sessions")

    app = ctx.application(op, "lifecycle")
    svc, record = ctx.service_client(op, app, "lifecycle-svc", ["reports.read"])
    w = ctx.workload(op, svc, "lifecycle-svc")
    base = f"{ctx.admin_base()}/ciam/agent-workloads/{w['id']}"
    ctx.http.post(base + "/suspend", bearer=op, json_body={"reason": "investigation"}).expect(200)
    out.refused(oauth.client_credentials(ctx.http, svc, ["reports.read"]).status in (400, 401),
                "a suspended workload gets no token")
    ctx.http.post(base + "/reactivate", bearer=op).expect(200)
    out.ok(oauth.client_credentials(ctx.http, svc, ["reports.read"]).status == 200, "reactivation restores issuance")
    ctx.http.post(base + "/retire", bearer=op, json_body={"reason": "decommissioned"}).expect(200)
    out.refused(ctx.http.post(base + "/reactivate", bearer=op).status == 409, "retirement is terminal")
    out.refused(ctx.http.post(f"{ctx.admin_base()}/identity-control-requests", bearer=two, json_body={
        "action": "ROTATE_APPLICATION_CLIENT_SECRET", "targetType": "APPLICATION_CLIENT", "targetId": record["id"],
        "expectedTargetRevision": record["revision"], "payload": {}}).status == 403,
                "a non-administrator cannot propose a credential rotation")
    out.consumer_must += ["treat 401 on a known token as 'session ended' and re-authenticate",
                          "stop scheduling work for a suspended or retired workload"]
    return out


if __name__ == "__main__":
    standalone(run)
