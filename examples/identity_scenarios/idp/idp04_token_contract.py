"""IDP-04 — tokens for the intended resource and permissions (RFC 9068 JWT access-token profile, RFC 8707/8693
``resource``, RFC 7519).

1. Teaches: what a receiver checks on every Axiom access token, and how the audience and scope are fixed at issuance.
   Population: workforce person (the same rules hold for customers and software, see IDP-02/03/05).
2. Setup (setup adapter): an application ``api`` with a workforce sign-in client limited to a 300-second access-token
   lifetime, an app role granting ``orders.read`` only, a member, and a second application for wrong-audience checks.
3. Records: two applications, clients, role, member.
4. Calls: code flow (IDP-02), token exchange with ``resource`` instead of ``audience``, ``GET /users/{id}`` (Axiom's own
   API) with an ID token.
5. Tokens: access token: header ``typ=at+jwt``, ``alg=RS256``, ``kid``; claims ``iss``, ``sub``, ``aud`` (one
   audience), ``exp``, ``iat``, ``jti``, ``client_id``, ``scope``. ID token: audience is the client.
6. Positive: the token validates for its audience with the declared lifetime and only the entitled scope; a token
   exchange may name its target with ``resource`` and gets the same audience. Denials: another audience; an edited
   payload; ``alg=none``; an ID token used as an access token (locally and at Axiom's API); a scope the person is not
   entitled to is not issued; the client lifetime cannot exceed the deployment ceiling.
7. Status: offline validity lasts until ``exp`` (here at most 300 s); see IDP-07/08 for online status.
8. Cleanup: applications/clients disabled, user disabled.
9. Consumer must: check signature, iss, aud, exp (small leeway), typ and scope on every request; reject ID tokens and
   other audiences; treat scope as the upper bound only — resource-level authorization remains the consumer's.
"""
from __future__ import annotations

import base64
import json

from axiom_cookbook import oauth, topology
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret
from axiom_cookbook.tokens import InvalidToken, unverified_claims
from axiom_cookbook.topology import READ, WRITE


def _rejected(fn) -> bool:
    try:
        fn()
        return False
    except InvalidToken:
        return True


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-04 token contract (audience, scope, type, lifetime)")
    http, v = ctx.http, ctx.validator
    op = ctx.operator()
    app = ctx.application(op, "api")
    other = ctx.application(op, "other-api")
    web, _ = ctx.interactive_client(op, app, "api-web", [READ, WRITE], access_ttl=300)
    reader = ctx.app_role(op, app, "reader", {READ: "allow"})
    person, password = ctx.workforce_user(op, "ana")
    ctx.membership(op, app, person, reader["id"])

    t = oauth.browser_login(http, web, person, password, ("openid", READ))
    claims = v.access_token(t.access_token, app["audience"])
    header = json.loads(base64.urlsafe_b64decode(t.access_token.reveal().split(".")[0] + "=="))
    out.ok(header["typ"] == "at+jwt" and header["alg"] == "RS256" and header.get("kid"),
           "header: typ=at+jwt, alg=RS256, kid present")
    out.ok(all(k in claims for k in ("iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope")),
           "claims: iss, sub, aud, exp, iat, jti, client_id, scope")
    out.ok(claims["exp"] - claims["iat"] == 300, "the client's declared 300-second lifetime is applied")
    out.facts["declared_lifetime_s"] = claims["exp"] - claims["iat"]
    widened = oauth.browser_login(http, web, person, password, ("openid", READ, WRITE))
    out.refused(WRITE not in str(v.access_token(widened.access_token, app["audience"]).get("scope")),
                "a requested scope the person is not entitled to is not issued")
    out.refused(_rejected(lambda: v.access_token(t.access_token, other["audience"])), "another audience is rejected")
    h, p, s = t.access_token.reveal().split(".")
    edited = json.loads(base64.urlsafe_b64decode(p + "=="))
    edited["scope"] = f"{READ} {WRITE}"
    forged = h + "." + base64.urlsafe_b64encode(json.dumps(edited).encode()).decode().rstrip("=") + "." + s
    out.refused(_rejected(lambda: v.access_token(Secret(forged, "edited"), app["audience"])), "an edited payload fails the signature")
    none = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "at+jwt"}).encode()).decode().rstrip("=") + "." + p + "."
    out.refused(_rejected(lambda: v.access_token(Secret(none, "alg none"), app["audience"])), "alg=none is rejected")
    out.refused(_rejected(lambda: v.access_token(t.id_token, web.client_id)), "an ID token is not an access token (typ)")
    out.refused(http.get(f"/users/{person}", bearer=t.id_token).status == 401, "Axiom's API refuses an ID token as bearer")
    too_long = http.post(f"{ctx.admin_base()}/applications/{app['id']}/clients", bearer=op, json_body={
        "clientId": ctx.name("api-long"), "clientType": "PUBLIC_BROWSER", "redirectUris": ["http://127.0.0.1:9/cb"],
        "scopes": ["openid"], "accessTokenTtlSeconds": 86400})
    out.refused(too_long.status == 400, "a client lifetime above the deployment ceiling is refused at registration")

    # RFC 8693 lets the exchange name its target with `resource` (absolute URI) instead of `audience`.
    top = topology.build(ctx, op)
    person_token = oauth.browser_login(http, top.web, top.member, top.member_password, ("openid", READ)).access_token
    by_resource = http.post("/oauth/token", basic=top.portal_svc.basic(), form=[
        ("grant_type", oauth.TOKEN_EXCHANGE), ("subject_token", person_token),
        ("subject_token_type", oauth.ACCESS_TOKEN_TYPE), ("resource", top.portal_app["audience"]), ("scope", READ)])
    out.ok(by_resource.status == 200 and unverified_claims(oauth.tokens(by_resource).access_token)["aud"]
           in (top.portal_app["audience"], [top.portal_app["audience"]]),
           "token exchange accepts the standard resource parameter as the target")
    both = http.post("/oauth/token", basic=top.portal_svc.basic(), form=[
        ("grant_type", oauth.TOKEN_EXCHANGE), ("subject_token", person_token),
        ("subject_token_type", oauth.ACCESS_TOKEN_TYPE), ("resource", top.portal_app["audience"]),
        ("audience", top.portal_app["audience"]), ("scope", READ)])
    out.refused(both.status == 400, "naming both resource and audience is refused (one target per request)")
    out.consumer_must += ["validate signature, iss, aud, exp, typ and scope on every request; reject ID tokens",
                          "scope is a ceiling; decide resource-level access yourself"]
    return out


if __name__ == "__main__":
    standalone(run)
