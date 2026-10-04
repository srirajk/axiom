"""O01 — Discovery, JWKS and real token validation (not just decoding).

1. Teaches: what a receiver must check on every Axiom access token. Population: any.
2. Setup: the operator token (any Axiom-issued token works).
3. Records: none.
4. Calls: ``GET /.well-known/openid-configuration``, ``GET /oauth2/jwks``; local validation with PyJWT.
5. Tokens: an RFC 9068 access token (``typ=at+jwt``, ``alg=RS256``, ``kid``) and an OIDC ID token (no ``at+jwt``).
6. Positive: signature, ``iss``, ``aud``, ``exp``/``iat`` and ``typ`` all verify. Denials: wrong audience; broken
   signature; unknown algorithm (``none``); an ID token presented as an access token — refused both by the local
   validator and by Axiom's own API.
7. Expiry: ``exp`` is enforced with a small leeway.
8. Cleanup: nothing created.
9. Consumer must: validate all of the above locally *and* decide how fresh status must be (see O06, IDP-07/IDP-08).
"""
from __future__ import annotations

import base64
import json

from axiom_cookbook import oauth
from axiom_cookbook.context import ADMIN_CLIENT, Context
from axiom_cookbook.example import Outcome, standalone
from axiom_cookbook.redaction import Secret
from axiom_cookbook.tokens import InvalidToken


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except InvalidToken:
        return True


def run(ctx: Context) -> Outcome:
    out = Outcome("O01 discovery and validation")
    meta = ctx.http.get("/.well-known/openid-configuration").expect(200).json()
    out.ok(meta["jwks_uri"].startswith(ctx.target.base_url) and "RS256" in meta["id_token_signing_alg_values_supported"],
           "discovery names a JWKS on the issuer and RS256")
    tokens = oauth.browser_login(ctx.http, ADMIN_CLIENT, ctx.operator_username, ctx.operator_password,
                                 ("openid", "profile", "roles"))
    claims = ctx.validator.access_token(tokens.access_token, "axiom-api")
    out.ok(claims["iss"] == ctx.target.base_url, "access token validates: signature, iss, aud, exp, iat, typ=at+jwt")
    id_claims = ctx.validator.id_token(tokens.id_token, "axiom-admin")
    out.ok(id_claims["aud"] in ("axiom-admin", ["axiom-admin"]), "ID token validates for the client as audience")

    out.refused(_raises(lambda: ctx.validator.access_token(tokens.access_token, "https://someone-else.invalid")),
                "wrong audience is refused")
    value = tokens.access_token.reveal()
    head, body, sig = value.split(".")
    tampered_body = json.loads(base64.urlsafe_b64decode(body + "=="))
    tampered_body["roles"] = ["platform_admin"]
    forged_body = base64.urlsafe_b64encode(json.dumps(tampered_body).encode()).rstrip(b"=").decode()
    forged = Secret(".".join([head, forged_body, sig]), "tampered token")
    out.refused(_raises(lambda: ctx.validator.access_token(forged, "axiom-api")),
                "a token whose claims were edited fails signature validation")
    out.refused(ctx.http.get("/roles", bearer=forged).status == 401, "Axiom refuses the edited token too")
    none_head = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "at+jwt", "kid": "x"}).encode()).rstrip(b"=").decode()
    unsigned = Secret(f"{none_head}.{body}.", "unsigned token")
    out.refused(_raises(lambda: ctx.validator.access_token(unsigned, "axiom-api")), "alg=none is refused")
    out.refused(_raises(lambda: ctx.validator.access_token(tokens.id_token, "axiom-admin")),
                "an ID token is not accepted as an access token (typ check)")
    out.refused(ctx.http.get("/roles", bearer=tokens.id_token).status == 401, "Axiom's API refuses an ID token as bearer")
    out.consumer_must.append("validate signature, iss, aud, exp and typ on every token; decoding is not validation")
    return out


if __name__ == "__main__":
    standalone(run)
