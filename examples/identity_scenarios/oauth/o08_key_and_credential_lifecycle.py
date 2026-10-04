"""O08 — Signing-key rotation with overlap, and confidential-client secret rotation with a declared overlap.

1. Teaches: lifecycle of the two credentials a consumer depends on. Population: n/a (operators, a service client).
2. Setup: signing keys are deployment-wide, so only a ``platform_admin`` (the root administrator) may change them;
   client-secret rotation is a two-person identity-control flow between two tenant administrators.
3. Records: one staged-then-active signing key (the previous key stays verification-only for its overlap window);
   one rotated client secret.
4. Calls: ``POST /admin/tenants/{t}/signing-keys``, ``…/{id}/activate``, ``…/{id}/retire``, ``GET /oauth2/jwks``;
   ``POST /admin/tenants/{t}/identity-control-requests`` (``ROTATE_APPLICATION_CLIENT_SECRET``), ``…/approve``,
   ``…/apply`` (returns the new secret exactly once).
5. Tokens: tokens signed before the rotation keep validating through the JWKS; new tokens carry the new ``kid``.
6. Positive: rotation without breaking issued tokens; old client secret valid only inside the overlap. Denials:
   tenant administrator changing keys (403); retiring the previous key inside its overlap (409); self-approval of a
   rotation; the old secret after the overlap.
7. Expiry: the verification-only key's window equals the maximum token/session lifetime; the client-secret overlap
   is a deployment policy (15 s in the cookbook profile, default 0).
8. Cleanup: nothing to undo (rotations are forward-only); the client is disabled with its application.
9. Consumer must: refresh JWKS on an unknown ``kid`` (rate-limited), never pin a single key; roll its secret during
   the overlap.
"""
from __future__ import annotations

import time

from axiom_cookbook import oauth
from axiom_cookbook.context import ADMIN_CLIENT, Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.oauth import Client
from axiom_cookbook.redaction import Secret
from axiom_cookbook.tokens import Validator
import jwt


def run(ctx: Context) -> Outcome:
    out = Outcome("O08 key and credential lifecycle")
    root, op = ctx.root(), ctx.operator()
    keys = f"{ctx.admin_base()}/signing-keys"
    before_token = oauth.browser_login(ctx.http, ADMIN_CLIENT, ctx.operator_username, ctx.operator_password,
                                       ("openid",)).access_token
    old_kid = jwt.get_unverified_header(before_token.reveal())["kid"]
    out.refused(ctx.http.post(keys, bearer=op).status == 403, "a tenant administrator cannot change signing keys")
    staged = ctx.http.post(keys, bearer=root).expect(201).json()
    ctx.http.post(f"{keys}/{staged['id']}/activate", bearer=root).expect(200)
    jwks = {k["kid"] for k in ctx.http.get("/oauth2/jwks").expect(200).json()["keys"]}
    out.ok({old_kid, staged["kid"]} <= jwks, "JWKS publishes the new key and keeps the previous one for verification")
    fresh_validator = Validator.discover(ctx.http)
    out.ok(fresh_validator.access_token(before_token, "axiom-api")["sub"] == ctx.operator_username,
           "a token signed before the rotation still validates")
    after_token = oauth.browser_login(ctx.http, ADMIN_CLIENT, ctx.operator_username, ctx.operator_password,
                                      ("openid",)).access_token
    out.ok(jwt.get_unverified_header(after_token.reveal())["kid"] == staged["kid"], "new tokens use the new key")
    previous = next(k for k in ctx.http.get(keys, bearer=root).expect(200).json() if k["kid"] == old_kid)
    out.refused(ctx.http.post(f"{keys}/{previous['id']}/retire", bearer=root).status == 409,
                "the previous key cannot be retired inside its verification overlap")
    out.facts["previous_key_state"] = previous["state"]

    app = ctx.application(op, "rotating")
    svc, record = ctx.service_client(op, app, "rotating-svc", ["reports.read"])
    requests_base = f"{ctx.admin_base()}/identity-control-requests"
    proposed = ctx.http.post(requests_base, bearer=op, json_body={
        "action": "ROTATE_APPLICATION_CLIENT_SECRET", "targetType": "APPLICATION_CLIENT", "targetId": record["id"],
        "expectedTargetRevision": record["revision"], "payload": {}}).expect(201).json()
    request_url = f"{requests_base}/{proposed['id']}"
    out.refused(ctx.http.post(request_url + "/approve", bearer=op, json_body={"expectedRevision": 1}).status == 409,
                "the proposer cannot approve their own rotation")
    second = ctx.second_operator()
    ctx.http.post(request_url + "/approve", bearer=second, json_body={"expectedRevision": 1}).expect(200)
    applied = ctx.http.post(request_url + "/apply", bearer=second, json_body={"expectedRevision": 2}).expect(200).json()
    new = Client(svc.client_id, Secret(applied["oneTimeSecret"], "rotated secret"))
    out.ok(oauth.client_credentials(ctx.http, svc, ["reports.read"]).status == 200,
           "the previous secret still works inside the declared overlap")
    out.ok(oauth.client_credentials(ctx.http, new, ["reports.read"]).status == 200, "the new secret works")
    time.sleep(16)
    out.refused(oauth.client_credentials(ctx.http, svc, ["reports.read"]).status == 401,
                "the previous secret is refused after the overlap")
    out.consumer_must += ["refresh JWKS when a kid is unknown; never pin one key",
                          "switch to a rotated client secret within the published overlap"]
    return out


if __name__ == "__main__":
    standalone(run)
