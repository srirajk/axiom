"""O09 — Every advertised grant and client-authentication method, linked to evidence; unsupported ones refused.

1. Teaches: read Axiom's discovery documents as a contract. Population: n/a.
2. Setup: a confidential client for the negative probes.
3. Records: one application + client.
4. Calls: both discovery documents; ``POST /oauth/token`` with each unsupported grant/method.
5. Advertised grants and their evidence in this cookbook:
   ``authorization_code`` (O02, standard OAuth 2.0 / OIDC with RFC 7636 PKCE, S256 only); ``refresh_token`` (IDP-06,
   confidential web clients granted ``offline_access``); ``client_credentials`` (O04, RFC 6749 §4.4); ``urn:ietf:params:oauth:grant-type:token-exchange`` (O05, RFC 8693,
   Axiom profile: no ``actor_token``); ``urn:openwolf:params:oauth:grant-type:standing-grant`` and
   ``…:approved-action`` (O07 and the approved-action extension, **Axiom-specific extensions**, not standards). Client authentication:
   ``client_secret_basic`` and ``private_key_jwt`` (confidential; IDP-03) and ``none`` (public browser clients with
   PKCE). Axiom also accepts a
   workload-federation client assertion type that is deliberately *not* advertised (no provider profile selected).
6. Positive: discovery lists exactly the above. Denials: ``device_code`` and ``password`` grants, ``refresh_token`` for a
   service client, ``client_secret_post``, and a ``private_key_jwt`` assertion from a client without registered keys.
7/8. n/a / client disabled at cleanup.
9. Consumer must: negotiate from discovery, not assumptions; treat Axiom-specific grants as optional extensions.
"""
from __future__ import annotations

import base64
import json
import time

from axiom_cookbook.context import Context
from axiom_cookbook.example import Outcome, standalone

ADVERTISED_GRANTS = {"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange",
                     "urn:openwolf:params:oauth:grant-type:standing-grant",
                     "urn:openwolf:params:oauth:grant-type:approved-action"}


def run(ctx: Context) -> Outcome:
    out = Outcome("O09 capability enumeration")
    for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        meta = ctx.http.get(path).expect(200).json()
        out.ok(set(meta["grant_types_supported"]) == ADVERTISED_GRANTS
               and len(meta["grant_types_supported"]) == len(ADVERTISED_GRANTS),
               f"{path}: grants advertised are exactly the supported set (no duplicates)")
        out.ok(set(meta["token_endpoint_auth_methods_supported"]) == {"client_secret_basic", "private_key_jwt", "none"},
               f"{path}: client authentication advertised is client_secret_basic, private_key_jwt and none")
        out.ok("dpop_signing_alg_values_supported" not in meta and "tls_client_certificate_bound_access_tokens" not in meta,
               f"{path}: no sender-constraint feature is advertised (none is enforced)")
        out.ok(meta.get("code_challenge_methods_supported") == ["S256"], f"{path}: PKCE S256 only")
    op = ctx.operator()
    app = ctx.application(op, "probe")
    svc, _ = ctx.service_client(op, app, "probe-svc", ["reports.read"])
    for grant in ("refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "password"):
        r = ctx.http.post("/oauth/token", basic=svc.basic(), form={"grant_type": grant, "refresh_token": "x",
                                                                   "device_code": "x", "username": "x", "password": "x"})
        out.refused(r.status == 400 and r.oauth_error() in ("unsupported_grant_type", "invalid_grant", "unauthorized_client"),
                    f"grant {grant} is refused" + (" for a service client" if grant == "refresh_token" else ""))
    post = ctx.http.post("/oauth/token", form={"grant_type": "client_credentials", "client_id": svc.client_id,
                                               "client_secret": svc.secret, "scope": "reports.read"})
    out.refused(post.status == 401, "client_secret_post is refused (not advertised)")
    head = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps({"iss": svc.client_id, "sub": svc.client_id, "aud": ctx.target.base_url,
                                                "exp": int(time.time()) + 60, "jti": "probe"}).encode()).rstrip(b"=").decode()
    pkjwt = ctx.http.post("/oauth/token", form={"grant_type": "client_credentials", "scope": "reports.read",
                                                "client_id": svc.client_id, "client_assertion": f"{head}.{body}.sig",
                                                "client_assertion_type":
                                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"})
    out.refused(pkjwt.status in (400, 401),
                "a private_key_jwt assertion from a client registered without keys is refused (IDP-03 covers key clients)")
    out.consumer_must.append("negotiate capabilities from discovery; Axiom-specific grants are optional extensions")
    return out


if __name__ == "__main__":
    standalone(run)
