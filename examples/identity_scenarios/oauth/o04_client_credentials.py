"""O04 — Confidential client credentials: a workload authenticating as itself, with no person involved.

1. Teaches: service-to-service tokens. Population: workload-only.
2. Setup: operator creates an application with a confidential client and registers the client as a workload
   identity (so its lifecycle — suspend/retire — applies).
3. Records: application, confidential client, workload identity.
4. Calls: ``POST /oauth/token`` ``grant_type=client_credentials`` with HTTP Basic client authentication.
5. Tokens: ``sub`` = the client id, ``identity_kind=workload``, ``aud`` = the client's application audience, no
   ``act``, no person. ``expires_in`` is reported in the facts.
6. Positive: token issued and validated for the application audience. Denials: wrong secret (401
   ``invalid_client``); scope outside the client's registration (``invalid_scope``); suspended workload
   (``unauthorized_client``); disabled client (401).
7. Status: client-credentials tokens are not bound to a human session (see O06 for their status semantics).
8. Cleanup: workload retired, client and application disabled.
9. Consumer must: request only the scopes it needs and cache tokens no longer than ``expires_in``.
"""
from __future__ import annotations

from axiom_cookbook import oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.oauth import Client
from axiom_cookbook.redaction import Secret


def run(ctx: Context) -> Outcome:
    out = Outcome("O04 client credentials")
    op = ctx.operator()
    app = ctx.application(op, "nightly")
    svc, record = ctx.service_client(op, app, "nightly-job", ["reports.read"])
    workload = ctx.workload(op, svc, "nightly-job")
    issued = oauth.tokens(oauth.client_credentials(ctx.http, svc, ["reports.read"]).expect(200))
    claims = ctx.validator.access_token(issued.access_token, app["audience"])
    out.ok(claims["sub"] == svc.client_id and claims.get("identity_kind") == "workload" and "act" not in claims,
           "token subject is the client itself; no person, no actor")
    out.ok(claims.get("scope") in (["reports.read"], "reports.read"), "token carries exactly the requested scope")
    out.facts.update(expires_in=issued.expires_in, lifetime_seconds=claims["exp"] - claims["iat"])

    wrong = Client(svc.client_id, Secret("not-the-secret-" + "x" * 30, "wrong secret"))
    out.refused(oauth.client_credentials(ctx.http, wrong, ["reports.read"]).status == 401, "a wrong secret is 401")
    out.refused(oauth.client_credentials(ctx.http, svc, ["ledger.write"]).oauth_error() == "invalid_scope",
                "a scope outside the client's registration is refused")
    wl = f"{ctx.admin_base()}/ciam/agent-workloads/{workload['id']}"
    ctx.http.post(wl + "/suspend", bearer=op, json_body={"reason": "cookbook"}).expect(200)
    out.refused(oauth.client_credentials(ctx.http, svc, ["reports.read"]).oauth_error() == "unauthorized_client",
                "a suspended workload's client gets no token")
    ctx.http.post(wl + "/reactivate", bearer=op).expect(200)
    out.ok(oauth.client_credentials(ctx.http, svc, ["reports.read"]).status == 200, "reactivation restores issuance")
    ctx.http.delete(f"{ctx.admin_base()}/applications/{app['id']}/clients/{record['id']}", bearer=op).expect(204)
    out.refused(oauth.client_credentials(ctx.http, svc, ["reports.read"]).status == 401, "a disabled client is 401")
    out.consumer_must.append("cache client-credentials tokens no longer than expires_in; request minimal scopes")
    return out


if __name__ == "__main__":
    standalone(run)
