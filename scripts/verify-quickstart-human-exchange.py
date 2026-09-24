#!/usr/bin/env python3
"""Verify the supported public-PKCE plus confidential-BFF quickstart flow."""

from __future__ import annotations

import hashlib
import http.cookiejar
import importlib.util
import os
import pathlib
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("axiom_exchange_common", ROOT / "verify-argus-agent-exchange.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Axiom exchange verification helpers")
COMMON = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMMON
SPEC.loader.exec_module(COMMON)

SCOPE = "quickstart:invoke"
CALLBACK = "http://localhost:18085/callback"
PUBLIC_CLIENT = "quickstart-human-web"
BFF_CLIENT = "quickstart-bff"
BFF_AUDIENCE = "agent:meridian:quickstart-bff"
BFF_REF = "agent:quickstart-bff:development"
GATEWAY_CLIENT = "argus-gateway-broker"
GATEWAY_AUDIENCE = "argus-gateway"
AGENT_AUDIENCE = "agent:meridian:quickstart-agent"


class CallbackHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if newurl.startswith(CALLBACK):
            raise COMMON.RedirectCaptured(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def authorization_code(base: str, username: str, password: str) -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = COMMON.b64url(hashlib.sha256(verifier.encode()).digest())
    state = secrets.token_urlsafe(24)
    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": PUBLIC_CLIENT,
        "redirect_uri": CALLBACK,
        "scope": f"openid profile email {SCOPE}",
        "state": state,
        "nonce": secrets.token_urlsafe(24),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), CallbackHandler()
    )
    login_page = opener.open(base + "/oauth/authorize?" + params, timeout=30)
    csrf = COMMON.hidden_input(login_page.read().decode(), "_csrf")
    form = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "_csrf": csrf,
    }).encode()
    try:
        opener.open(urllib.request.Request(
            base + "/login", data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST",
        ), timeout=30)
    except COMMON.RedirectCaptured as callback:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(callback.location).query)
        COMMON.expect(query.get("state") == [state], "OIDC state mismatch")
        COMMON.expect(len(query.get("code", [])) == 1, "authorization code is absent")
        return query["code"][0], verifier
    raise AssertionError("OIDC authorization did not return a callback")


def missing_membership_is_denied(base: str, password: str) -> None:
    try:
        authorization_code(base, "daniel.kim", password)
    except urllib.error.HTTPError as error:
        COMMON.expect(error.code in {401, 403}, f"missing membership returned HTTP {error.code}")
        return
    except AssertionError:
        return
    raise AssertionError("user without quickstart membership received an authorization code")


def main() -> int:
    base = os.environ.get("AXIOM_BASE_URL", "http://127.0.0.1:8180").rstrip("/")
    issuer = os.environ.get("AXIOM_ISSUER", "https://identity.meridian.com:8443").rstrip("/")
    password = COMMON.required("AXIOM_SEED_USER_PASSWORD")
    bff_secret = COMMON.kubernetes_secret_value(
        "quickstart", "quickstart-bff-workload-oauth-client", "client_secret"
    )
    broker_secret = COMMON.kubernetes_secret_value(
        "argus-system", "argus-gateway-agent-exchange-oauth-client", "client_secret"
    )

    def exchange(subject: str, client: str, secret: str, audience: str, expected: int = 200) -> str:
        response = COMMON.request(
            base + "/oauth/token", method="POST",
            form={
                "grant_type": COMMON.TOKEN_EXCHANGE,
                "subject_token": subject,
                "subject_token_type": COMMON.ACCESS_TOKEN,
                "requested_token_type": COMMON.ACCESS_TOKEN,
                "audience": audience,
                "scope": SCOPE,
            },
            basic=(client, secret),
        )
        COMMON.expect(response.status == expected,
                      f"{client} exchange to {audience} HTTP {response.status}: {COMMON.oauth_error(response)}")
        return str(response.json()["access_token"]) if expected == 200 else COMMON.oauth_error(response)

    def check(token: str, audience: str, client: str, profile: str | None,
              token_use: str | None, actor: str | None) -> dict[str, Any]:
        COMMON.verify_signature(base, token)
        claims = COMMON.jwt_claims(token)
        COMMON.expect(claims.get("iss") == issuer, "issuer mismatch")
        COMMON.expect(claims.get("tenant_id") == "meridian", "tenant mismatch")
        COMMON.expect(COMMON.audiences(claims) == {audience}, "audience mismatch")
        COMMON.expect(SCOPE in COMMON.scopes(claims), "scope mismatch")
        COMMON.expect(claims.get("sub") == "quickstart_user", "human subject changed")
        COMMON.expect(claims.get("client_id") == client, "requesting client mismatch")
        COMMON.expect(int(claims.get("exp", 0)) > time.time(), "token expired")
        if profile is None:
            COMMON.expect(claims.get("identity_kind") == "workforce", "workforce identity is absent")
            COMMON.expect("act" not in claims, "browser token contains an actor")
        else:
            COMMON.expect(claims.get("authority_profile") == profile, "profile mismatch")
            COMMON.expect(claims.get("token_use") == token_use, "token use mismatch")
            COMMON.expect(isinstance(claims.get("act"), dict)
                          and claims["act"].get("sub") == actor, "actor mismatch")
            COMMON.expect(int(claims["exp"]) - int(claims["iat"]) <= 300,
                          "exchange lifetime exceeds five minutes")
        return claims

    code, verifier = authorization_code(base, "quickstart_user", password)
    browser = COMMON.request(
        base + "/oauth/token", method="POST",
        form={
            "grant_type": "authorization_code",
            "client_id": PUBLIC_CLIENT,
            "code": code,
            "redirect_uri": CALLBACK,
            "code_verifier": verifier,
        },
    )
    COMMON.expect(browser.status == 200, f"authorization-code redemption HTTP {browser.status}")
    human = str(browser.json()["access_token"])
    claims = check(human, BFF_AUDIENCE, PUBLIC_CLIENT, None, None, None)
    COMMON.expect("quickstart-operator" in set(claims.get("roles", [])), "quickstart role is absent")
    print("PASS public Authorization Code + S256 PKCE login")

    wrong_code, _ = authorization_code(base, "quickstart_user", password)
    wrong = COMMON.request(
        base + "/oauth/token", method="POST",
        form={
            "grant_type": "authorization_code",
            "client_id": PUBLIC_CLIENT,
            "code": wrong_code,
            "redirect_uri": CALLBACK,
            "code_verifier": secrets.token_urlsafe(48),
        },
    )
    COMMON.expect(wrong.status == 400, f"wrong verifier returned HTTP {wrong.status}")
    print("PASS wrong PKCE verifier denied")

    missing_membership_is_denied(base, password)
    print("PASS missing quickstart application membership denied")

    bff = exchange(human, BFF_CLIENT, bff_secret, BFF_AUDIENCE)
    check(bff, BFF_AUDIENCE, BFF_CLIENT, "workforce", "exchange_subject", BFF_REF)
    print("PASS human token to independently authenticated BFF")
    gateway = exchange(bff, BFF_CLIENT, bff_secret, GATEWAY_AUDIENCE)
    check(gateway, GATEWAY_AUDIENCE, BFF_CLIENT,
          "workload_continuation", "gateway_authorization", BFF_REF)
    print("PASS BFF to Gateway with human subject and BFF actor")
    agent = exchange(gateway, GATEWAY_CLIENT, broker_secret, AGENT_AUDIENCE)
    check(agent, AGENT_AUDIENCE, GATEWAY_CLIENT, "gateway_backend", "exchange_subject", BFF_REF)
    print("PASS Gateway to approved quickstart Agent")

    direct = exchange(human, GATEWAY_CLIENT, broker_secret, AGENT_AUDIENCE, 400)
    COMMON.expect(direct in {"invalid_grant", "invalid_target"},
                  "browser token bypassed the BFF and Gateway authority chain")
    print("PASS direct browser-token broker bypass denied")
    print("AXIOM QUICKSTART HUMAN EXCHANGE PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print("AXIOM QUICKSTART HUMAN EXCHANGE FAIL: " + COMMON.safe_error(error), file=sys.stderr)
        raise SystemExit(1) from None
