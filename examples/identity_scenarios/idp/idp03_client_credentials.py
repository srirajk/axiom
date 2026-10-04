"""IDP-03 — software authenticates as itself: client credentials with ``client_secret_basic`` and with asymmetric
``private_key_jwt`` (RFC 6749 section 4.4, RFC 7523 section 2.2, OIDC Core section 9).

1. Teaches: a service or job obtaining its own token without inventing a person, with a shared secret or (preferred
   for workloads) a registered public key whose private key never leaves the client. Population: software only.
2. Setup (setup adapter, tenant_admin): an application with two confidential service clients — one secret-based, one
   registered with a public JWK set.
3. Records: application and two clients; the generated secret is returned once and held in memory only.
4. Calls: ``POST /oauth/token`` ``grant_type=client_credentials`` with HTTP Basic, or with ``client_id``,
   ``client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`` and ``client_assertion``.
5. Tokens: an access token whose ``sub`` and ``client_id`` are the client itself, audience the application, no ``act``,
   lifetime the deployment's client-credentials TTL.
6. Positive: both methods issue a validated token for the client. Denials: wrong secret; scope beyond the registration;
   assertion signed by another key; wrong audience; expired; lifetime above five minutes; missing ``jti``; a replayed
   assertion (single use); disabled client (both methods).
7. Status: a client-credentials token introspects active only while its client is active.
8. Cleanup: clients and application disabled.
9. Consumer must: keep secrets/private keys in its own secret store, request minimal scope, cache tokens no longer than
   ``expires_in``, use a fresh ``jti`` per assertion, and remember that client authentication does not sender-bind the
   resulting access token (IDP-13 not selected).
"""
from __future__ import annotations

from urllib.parse import urlsplit

from axiom_cookbook import keys as client_keys, oauth
from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret
from axiom_cookbook.topology import READ, WRITE


def run(ctx: Context) -> Outcome:
    out = Outcome("IDP-03 client credentials (secret and private_key_jwt)")
    http, v = ctx.http, ctx.validator
    op = ctx.operator()
    app = ctx.application(op, "jobs")
    svc, svc_record = ctx.service_client(op, app, "jobs-svc", [READ])
    receiver, _ = ctx.service_client(op, app, "jobs-rs", [READ])
    key = client_keys.generate("RS256")
    key_client, key_created = ctx.key_client(op, app, "jobs-key", [READ], client_keys.jwks(key))
    out.ok(key_created.get("serviceSecret") is None and "private_key_jwt" in key_created["client"]["tokenEndpointAuthMethods"]
           and key_created["client"]["publicKeyIds"] == [key.kid],
           "a key-authenticated client is registered with its public key id and no secret")
    token_endpoint = http.get("/.well-known/oauth-authorization-server").expect(200).json()["token_endpoint"]

    t = oauth.tokens(oauth.client_credentials(http, svc, [READ]).expect(200))
    claims = v.access_token(t.access_token, app["audience"])
    out.ok(claims["sub"] == svc.client_id == claims["client_id"] and "act" not in claims,
           "secret client: the token's subject is the client itself; no person, no actor")
    out.ok(oauth.introspect(http, receiver, t.access_token)["active"] is True, "the software token is introspectable without a human session")
    out.facts["client_credentials_lifetime_s"] = claims["exp"] - claims["iat"]

    a = oauth.client_assertion(key_client, key.private_key, key.kid, token_endpoint)
    kt = oauth.tokens(oauth.client_credentials_with_assertion(http, key_client, a, [READ]).expect(200))
    kc = v.access_token(kt.access_token, app["audience"])
    out.ok(kc["sub"] == key_client == kc["client_id"], "private_key_jwt client: token for the client itself")
    out.refused(oauth.client_credentials_with_assertion(http, key_client, a, [READ]).status == 401,
                "a replayed assertion (same jti) is refused")

    # The same key authenticates the client at introspection and revocation (both advertise private_key_jwt).
    meta = http.get("/.well-known/oauth-authorization-server").expect(200).json()
    def key_form(endpoint_url, token):
        return [("token", token), ("client_id", key_client), ("client_assertion_type", oauth.JWT_BEARER_ASSERTION),
                ("client_assertion", oauth.client_assertion(key_client, key.private_key, key.kid, endpoint_url))]
    view = http.post(urlsplit(meta["introspection_endpoint"]).path, form=key_form(meta["introspection_endpoint"], kt.access_token))
    out.ok(view.status == 200 and view.json().get("active") is True, "private_key_jwt authenticates introspection")
    revoked = http.post(urlsplit(meta["revocation_endpoint"]).path, form=key_form(meta["revocation_endpoint"], kt.access_token))
    out.ok(revoked.status == 200, "private_key_jwt authenticates revocation of the client's own token")
    out.refused(oauth.introspect(http, receiver, kt.access_token)["active"] is False, "the revoked token is inactive")

    stranger = client_keys.generate("RS256")
    stranger.kid = key.kid
    for label, assertion in (
            ("an assertion signed by another key", oauth.client_assertion(key_client, stranger.private_key, key.kid, token_endpoint)),
            ("an assertion for another audience", oauth.client_assertion(key_client, key.private_key, key.kid, "https://elsewhere.invalid/token")),
            ("an expired assertion", oauth.client_assertion(key_client, key.private_key, key.kid, token_endpoint, lifetime_s=-30)),
            ("an assertion living longer than five minutes", oauth.client_assertion(key_client, key.private_key, key.kid, token_endpoint, lifetime_s=3600)),
            ("an assertion without jti", oauth.client_assertion(key_client, key.private_key, key.kid, token_endpoint, jti=None))):
        out.refused(oauth.client_credentials_with_assertion(http, key_client, assertion, [READ]).status == 401,
                    f"{label} is refused (invalid_client)")
    wrong = oauth.Client(svc.client_id, Secret("not-the-secret-0123456789", "wrong secret"))
    out.refused(oauth.client_credentials(http, wrong, [READ]).status == 401, "a wrong secret is refused")
    out.refused(oauth.client_credentials(http, svc, [READ, WRITE]).status == 400, "a scope beyond the registration is refused")
    http.delete(f"{ctx.admin_base()}/applications/{app['id']}/clients/{svc_record['id']}", bearer=op).expect(204)
    http.delete(f"{ctx.admin_base()}/applications/{app['id']}/clients/{key_created['client']['id']}", bearer=op).expect(204)
    out.refused(oauth.client_credentials(http, svc, [READ]).status == 401, "a disabled secret client gets no token")
    out.refused(oauth.client_credentials_with_assertion(http, key_client, oauth.client_assertion(
        key_client, key.private_key, key.kid, token_endpoint), [READ]).status == 401, "a disabled key client gets no token")
    out.refused(oauth.introspect(http, receiver, t.access_token)["active"] is False,
                "the disabled client's outstanding token introspects inactive")
    out.consumer_must += ["keep secrets and private keys in your own secret store; use a fresh jti per assertion",
                          "client authentication does not bind the access token to the key (bearer token)"]
    return out


if __name__ == "__main__":
    standalone(run)
