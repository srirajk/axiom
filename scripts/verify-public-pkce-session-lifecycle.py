#!/usr/bin/env python3
"""Verify Axiom's public-browser PKCE and login-session lifecycle over public HTTP surfaces.

Required environment:
  AXIOM_PKCE_PASSWORD
  AXIOM_PKCE_SECOND_USERNAME
  AXIOM_PKCE_SECOND_PASSWORD
  AXIOM_PKCE_DISABLED_CLIENT_ID

The script never prints credentials, cookies, authorization codes, or tokens.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import html
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: str

    def header(self, name: str) -> str | None:
        expected = name.lower()
        return next((value for key, value in self.headers.items() if key.lower() == expected), None)


@dataclass(frozen=True)
class Authorization:
    code: str
    state: str
    verifier: str


class LifecycleVerifier:
    def __init__(self, args: argparse.Namespace):
        self.issuer = os.environ.get("AXIOM_PKCE_ISSUER", "http://localhost:8180").rstrip("/")
        self.client_id = os.environ.get("AXIOM_PKCE_CLIENT_ID", "axiom-admin")
        self.redirect_uri = os.environ.get(
            "AXIOM_PKCE_REDIRECT_URI", "http://localhost:5182/callback"
        )
        self.post_logout_uri = os.environ.get(
            "AXIOM_PKCE_POST_LOGOUT_URI", "http://localhost:5182/login"
        )
        self.scope = os.environ.get("AXIOM_PKCE_SCOPE", "openid profile email roles")
        self.username = os.environ.get("AXIOM_PKCE_USERNAME", "admin")
        self.password = required("AXIOM_PKCE_PASSWORD")
        self.second_username = required("AXIOM_PKCE_SECOND_USERNAME")
        self.second_password = required("AXIOM_PKCE_SECOND_PASSWORD")
        self.disabled_client_id = required("AXIOM_PKCE_DISABLED_CLIENT_ID")
        self.origin = origin(self.redirect_uri)
        self.restart_command = args.restart_command
        self.repo_root = Path(__file__).resolve().parents[1]
        self.failures: list[str] = []
        self.discovery = self._discovery()
        self.authorization_endpoint = self.discovery["authorization_endpoint"]
        self.token_endpoint = self.discovery["token_endpoint"]
        self.end_session_endpoint = self.discovery["end_session_endpoint"]

    def pass_act(self, name: str, detail: str) -> None:
        print(f"PASS {name}: {detail}")

    def fail_act(self, name: str, detail: str) -> None:
        self.failures.append(name)
        print(f"FAIL {name}: {detail}")

    def run(self) -> int:
        self._act_discovery_and_cors()

        primary = browser()
        first = self._login_and_authorize(primary, self.username, self.password)
        first_tokens, first_response = self._redeem(first)
        if first_tokens is None:
            self.fail_act("fresh-login-authorize-token", safe_error(first_response))
            return self.finish()
        self.pass_act(
            "fresh-login-authorize-token",
            "S256 code redeemed without the browser login cookie",
        )
        if first_response.header("Access-Control-Allow-Origin") == self.origin:
            self.pass_act(
                "cookie-independent-token",
                "registered browser origin received a CORS token response without credentials",
            )
        else:
            self.fail_act(
                "cookie-independent-token",
                "token response omitted the registered Access-Control-Allow-Origin",
            )

        replay, replay_response = self._redeem(first)
        if replay is None and oauth_error(replay_response) == "invalid_grant":
            self.pass_act("code-replay", "second redemption failed as invalid_grant")
        else:
            self.fail_act("code-replay", "authorization code was not one-time")

        self._act_concurrent_redemption(primary)
        self._act_wrong_verifier(primary)
        self._act_wrong_redirect(primary)
        self._act_wrong_client(primary)
        self._act_logout(primary, first_tokens)
        self._act_second_user()
        self._act_restart()
        self._act_disabled_client()
        return self.finish()

    def finish(self) -> int:
        if self.failures:
            print(f"RESULT FAIL ({len(self.failures)} act(s))")
            return 1
        print("RESULT PASS (all public PKCE/session lifecycle acts)")
        return 0

    def _act_discovery_and_cors(self) -> None:
        methods = self.discovery.get("code_challenge_methods_supported", [])
        if methods == ["S256"]:
            self.pass_act("discovery", "authorization code flow advertises S256 PKCE")
        else:
            self.fail_act("discovery", f"unexpected PKCE methods {methods}")
        preflight = http(
            tokenless(),
            self.token_endpoint,
            method="OPTIONS",
            headers={
                "Origin": self.origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        if (
            preflight.status in (200, 204)
            and preflight.header("Access-Control-Allow-Origin") == self.origin
            and "POST" in (preflight.header("Access-Control-Allow-Methods") or "")
        ):
            self.pass_act("token-cors-preflight", "registered public-browser origin may POST")
        else:
            self.fail_act("token-cors-preflight", f"HTTP {preflight.status}")

    def _act_wrong_verifier(self, session) -> None:
        grant = self._authorize_authenticated(session)
        _, rejected = self._redeem(grant, verifier=secrets.token_urlsafe(64))
        recovered, accepted = self._redeem(grant)
        if (
            oauth_error(rejected) == "invalid_grant"
            and recovered is not None
            and accepted.status == 200
        ):
            self.pass_act(
                "wrong-verifier",
                "wrong verifier failed closed and did not consume the valid S256 code",
            )
        else:
            self.fail_act("wrong-verifier", "PKCE verifier binding or recovery failed")

    def _act_concurrent_redemption(self, session) -> None:
        grant = self._authorize_authenticated(session)
        barrier = threading.Barrier(3)

        def redeem_together() -> HttpResult:
            barrier.wait()
            _, response = self._redeem(grant)
            return response

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            attempts = [executor.submit(redeem_together) for _ in range(2)]
            barrier.wait()
            responses = [attempt.result(timeout=10) for attempt in attempts]
        successes = [response for response in responses if response.status == 200]
        rejections = [
            response
            for response in responses
            if oauth_error(response) == "invalid_grant"
        ]
        if len(successes) == 1 and len(rejections) == 1:
            self.pass_act(
                "concurrent-code-redemption",
                "two simultaneous valid requests produced one token and one invalid_grant",
            )
        else:
            self.fail_act(
                "concurrent-code-redemption",
                "authorization code was not atomically consumed exactly once",
            )

    def _act_wrong_redirect(self, session) -> None:
        grant = self._authorize_authenticated(session)
        wrong = self.redirect_uri + "/wrong"
        _, rejected = self._redeem(grant, redirect_uri=wrong)
        recovered, accepted = self._redeem(grant)
        if (
            oauth_error(rejected) == "invalid_grant"
            and recovered is not None
            and accepted.status == 200
        ):
            self.pass_act(
                "wrong-redirect-uri",
                "redirect mismatch failed closed and did not consume the valid code",
            )
        else:
            self.fail_act("wrong-redirect-uri", "redirect binding or recovery failed")

    def _act_wrong_client(self, session) -> None:
        grant = self._authorize_authenticated(session)
        _, rejected = self._redeem(grant, client_id=self.client_id + "-wrong")
        recovered, accepted = self._redeem(grant)
        if (
            oauth_error(rejected) in {"invalid_client", "invalid_grant"}
            and recovered is not None
            and accepted.status == 200
        ):
            self.pass_act(
                "wrong-client",
                "client mismatch failed closed and did not consume the valid code",
            )
        else:
            self.fail_act("wrong-client", "client binding or recovery failed")

    def _act_logout(self, session, tokens: dict[str, Any]) -> None:
        params = {
            "id_token_hint": tokens["id_token"],
            "post_logout_redirect_uri": self.post_logout_uri,
            "state": secrets.token_urlsafe(24),
        }
        response = http(
            session,
            self.end_session_endpoint + "?" + urllib.parse.urlencode(params),
        )
        no_login_cookie = not any(cookie.name == "JSESSIONID" for cookie in session.cookie_jar)
        _, final, _ = self._walk(session, self._authorize_url(*pkce_pair()))
        requires_login = urllib.parse.urlsplit(final).path == "/login"
        if response.status in (302, 303) and no_login_cookie and requires_login:
            self.pass_act(
                "logout",
                "server session invalidated, JSESSIONID cleared, next authorize requires login",
            )
        else:
            self.fail_act(
                "logout",
                "end-session did not clear both server authentication and browser cookie",
            )

    def _act_second_user(self) -> None:
        session = browser()
        grant = self._login_and_authorize(
            session, self.second_username, self.second_password
        )
        tokens, response = self._redeem(grant)
        if tokens is not None and response.status == 200:
            self.pass_act(
                "logout-login-another-user",
                "a different user completed a new login and cookie-independent token exchange",
            )
        else:
            self.fail_act("logout-login-another-user", safe_error(response))

    def _act_restart(self) -> None:
        session = browser()
        before = self._login_and_authorize(session, self.username, self.password)
        tokens, response = self._redeem(before)
        if tokens is None:
            self.fail_act("application-restart", "could not establish pre-restart session")
            return
        command = shlex.split(self.restart_command)
        restarted = subprocess.run(
            command,
            cwd=self.repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
            check=False,
        )
        if restarted.returncode != 0 or not self._wait_healthy():
            self.fail_act("application-restart", "Axiom application-only restart failed")
            return
        _, final, _ = self._walk(session, self._authorize_url(*pkce_pair()))
        stale_requires_login = urllib.parse.urlsplit(final).path == "/login"
        after = self._login_and_authorize(session, self.username, self.password)
        after_tokens, after_response = self._redeem(after)
        if stale_requires_login and after_tokens is not None and after_response.status == 200:
            self.pass_act(
                "application-restart",
                "retained stale cookie required login; new S256 code redeemed after restart",
            )
        else:
            self.fail_act(
                "application-restart",
                "restart left a stale session able to mint a code or blocked the fresh flow",
            )

    def _act_disabled_client(self) -> None:
        verifier, challenge = pkce_pair()
        params = self._authorize_params(verifier, challenge)
        params["client_id"] = self.disabled_client_id
        response, final, _ = self._walk(
            browser(),
            self.authorization_endpoint + "?" + urllib.parse.urlencode(params),
        )
        callback = final.startswith(self.redirect_uri) and "code=" in final
        if response.status in (400, 401, 403) and not callback:
            self.pass_act(
                "disabled-client",
                "disabled client failed at authorize without a callback code",
            )
        else:
            self.fail_act(
                "disabled-client",
                "disabled client reached a callback or was not rejected at authorize",
            )

    def _discovery(self) -> dict[str, Any]:
        response = http(
            tokenless(),
            self.issuer + "/.well-known/openid-configuration",
        )
        if response.status != 200:
            raise RuntimeError(f"OIDC discovery returned HTTP {response.status}")
        return json.loads(response.body)

    def _login_and_authorize(self, session, username: str, password: str) -> Authorization:
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(32)
        response, final, _ = self._walk(
            session, self._authorize_url(verifier, challenge, state)
        )
        if response.status != 200 or urllib.parse.urlsplit(final).path != "/login":
            raise RuntimeError("authorization did not reach the controlled login page")
        csrf = csrf_token(response.body)
        login = http(
            session,
            self.issuer + "/login",
            method="POST",
            data={"username": username, "password": password, "_csrf": csrf},
        )
        target = login.header("Location")
        if login.status not in (302, 303) or not target:
            raise RuntimeError("login was rejected")
        callback_response, callback, _ = self._walk(
            session, urllib.parse.urljoin(self.issuer + "/login", target)
        )
        return callback_grant(callback_response, callback, state, verifier)

    def _authorize_authenticated(self, session) -> Authorization:
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(32)
        response, final, _ = self._walk(
            session, self._authorize_url(verifier, challenge, state)
        )
        return callback_grant(response, final, state, verifier)

    def _authorize_url(
        self, verifier: str, challenge: str, state: str | None = None
    ) -> str:
        return self.authorization_endpoint + "?" + urllib.parse.urlencode(
            self._authorize_params(verifier, challenge, state)
        )

    def _authorize_params(
        self, verifier: str, challenge: str, state: str | None = None
    ) -> dict[str, str]:
        del verifier
        return {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state or secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }

    def _redeem(
        self,
        authorization: Authorization,
        *,
        verifier: str | None = None,
        redirect_uri: str | None = None,
        client_id: str | None = None,
    ) -> tuple[dict[str, Any] | None, HttpResult]:
        response = http(
            tokenless(),
            self.token_endpoint,
            method="POST",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id or self.client_id,
                "redirect_uri": redirect_uri or self.redirect_uri,
                "code": authorization.code,
                "code_verifier": verifier or authorization.verifier,
            },
            headers={
                "Origin": self.origin,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if response.status != 200:
            return None, response
        payload = json.loads(response.body)
        if not payload.get("access_token") or not payload.get("id_token"):
            return None, response
        return payload, response

    def _walk(self, session, url: str, limit: int = 10) -> tuple[HttpResult, str, list[str]]:
        current = url
        paths: list[str] = []
        for _ in range(limit):
            response = http(session, current)
            paths.append(urllib.parse.urlsplit(current).path)
            target = response.header("Location")
            if not target:
                return response, current, paths
            target = urllib.parse.urljoin(current, target)
            if target.startswith(self.redirect_uri) or target.startswith(self.post_logout_uri):
                return response, target, paths
            current = target
        raise RuntimeError("redirect limit exceeded")

    def _wait_healthy(self) -> bool:
        deadline = time.monotonic() + 60
        health = self.issuer + "/actuator/health"
        while time.monotonic() < deadline:
            try:
                if http(tokenless(), health).status == 200:
                    return True
            except OSError:
                pass
            time.sleep(0.5)
        return False


class BrowserOpener:
    def __init__(self):
        self.cookie_jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar), NoRedirect()
        )

    def open(self, request):
        return self.opener.open(request)


def browser() -> BrowserOpener:
    return BrowserOpener()


def tokenless():
    return urllib.request.build_opener(NoRedirect())


def http(
    opener,
    url: str,
    *,
    method: str = "GET",
    data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> HttpResult:
    body = None if data is None else urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(
        url, data=body, headers=headers or {}, method=method
    )
    actual = opener
    if isinstance(opener, BrowserOpener):
        actual = opener.opener
    try:
        response = actual.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        return HttpResult(
            error.code,
            dict(error.headers.items()),
            error.read().decode(errors="replace"),
        )
    return HttpResult(
        response.status,
        dict(response.headers.items()),
        response.read().decode(errors="replace"),
    )


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def origin(uri: str) -> str:
    parsed = urllib.parse.urlsplit(uri)
    return f"{parsed.scheme}://{parsed.netloc}"


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def csrf_token(body: str) -> str:
    match = re.search(r'name="_csrf"\s+value="([^"]+)"', body)
    if not match:
        raise RuntimeError("login page did not expose a CSRF token")
    return html.unescape(match.group(1))


def callback_grant(
    response: HttpResult, callback: str, expected_state: str, verifier: str
) -> Authorization:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(callback).query)
    if response.status not in (302, 303):
        raise RuntimeError(f"authorize callback returned HTTP {response.status}")
    if query.get("state") != [expected_state] or not query.get("code"):
        raise RuntimeError("authorize callback state/code contract failed")
    return Authorization(query["code"][0], expected_state, verifier)


def oauth_error(response: HttpResult) -> str | None:
    try:
        return json.loads(response.body).get("error")
    except (json.JSONDecodeError, AttributeError):
        return None


def safe_error(response: HttpResult) -> str:
    error = oauth_error(response)
    return f"HTTP {response.status}" + (f" {error}" if error else "")


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--restart-command",
        default="docker compose restart axiom",
        help="application-only restart command; defaults to the repository Compose service",
    )
    return parser.parse_args()


if __name__ == "__main__":
    try:
        sys.exit(LifecycleVerifier(arguments()).run())
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL harness: {error}")
        print("RESULT FAIL (harness)")
        sys.exit(1)
