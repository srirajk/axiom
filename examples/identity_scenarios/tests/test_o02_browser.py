"""O02 in a real browser: workforce authorization code + PKCE through Axiom's own login page.

The HTTP example (``oauth/o02_workforce_authorization_code.py``) proves the protocol. This test proves what only a
browser can: that the real login page, its CSRF-protected form and the redirect chain work in Chromium and end at a
loopback callback; and four browser-side protections — a login form posted from another origin is refused, the login
page cannot be framed, the session cookie is invisible to page script, and the password never appears in any URL.
(The authorization code itself does arrive in the callback URL, as the code flow requires; the callback keeps it in
memory only and never logs, renders or stores it.)

Artifacts: no trace, video or HAR is recorded. A screenshot is written to ``artifacts/`` only when the test fails; the
callback page never renders the code and the password field is masked. Failure messages are scrubbed of codes, state,
tokens and the password before they reach pytest.
"""
from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from axiom_cookbook import oauth
from axiom_cookbook.example import Outcome
from axiom_cookbook.redaction import Secret, scrub_text
from tests.conftest import record

playwright_api = pytest.importorskip("playwright.sync_api", reason="install the 'browser' extra (playwright==1.63.0)")

pytestmark = pytest.mark.browser
ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts"
SCOPES = ("openid", "reports.read")


class LoopbackCallback:
    """A real 127.0.0.1 redirect target. It keeps the query of each hit in memory only, never logs it, and answers
    with a page that does not echo it. It can also serve a foreign-origin page (for the CSRF and framing checks)."""

    def __init__(self) -> None:
        self.hits: list[dict[str, list[str]]] = []
        self.pages: dict[str, str] = {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                url = urlparse(self.path)
                if url.path == "/callback":
                    owner.hits.append(parse_qs(url.query))
                    body = "<!doctype html><title>callback</title><p>Sign-in returned to the application.</p>"
                else:
                    body = owner.pages.get(url.path, "<!doctype html><title>404</title>")
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):  # never write request lines (they contain the code) anywhere
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.redirect_uri = self.origin + "/callback"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _authorize_url(base: str, client_id: str, redirect_uri: str, challenge: str, state: str, nonce: str) -> str:
    return base + "/oauth/authorize?" + urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "scope": " ".join(SCOPES),
        "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})


def _sign_in(page, username: str, password: Secret) -> None:
    page.wait_for_selector("form input[name=password]")
    page.fill("input[name=username]", username)
    page.fill("input[name=password]", password.reveal())
    page.click("form [type=submit]")


def test_o02_workforce_login_in_a_real_browser(ctx):
    out = Outcome("O02 browser: authorization code + PKCE through the real login page")
    callback = LoopbackCallback()
    op = ctx.operator()
    app = ctx.application(op, "browser-workspace")
    web, _ = ctx.public_client(op, app, "browser-web", ["reports.read"], redirect_uri=callback.redirect_uri)
    role = ctx.app_role(op, app, "user", {"reports.read": "allow"})
    user, password = ctx.workforce_user(op, "browser-user")
    ctx.membership(op, app, user, role["id"])
    base = ctx.http.base_url
    verifier, challenge = oauth.pkce_pair()
    state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    sensitive = [password.reveal(), state]

    request_urls: list[str] = []
    page = None
    try:
        with playwright_api.sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                context = browser.new_context()       # no record_video / record_har / tracing
                page = context.new_page()
                page.on("request", lambda r: request_urls.append(r.url))

                # ---------------------------------------------------------------- the real flow
                page.goto(_authorize_url(base, web.client_id, web.redirect_uri, challenge, state, nonce))
                form = page.locator("form:has(input[name=password])")
                csrf_values = form.locator("input[name=_csrf]").evaluate_all("els => els.map(e => e.value.length > 0)")
                landed = (urlparse(page.url).path, form.count(), len(csrf_values), all(csrf_values))
                # Observed: the Thymeleaf form carries the CSRF field twice (explicit + auto-injected); harmless.
                out.facts["login_page"] = {"path": landed[0], "login_forms": landed[1], "csrf_fields": landed[2]}
                out.ok(landed[0] == "/login" and landed[1] == 1 and landed[2] >= 1 and landed[3],
                       f"the authorization request lands on Axiom's login page with a CSRF-protected form {landed}")
                _sign_in(page, user, password)
                page.wait_for_url(callback.redirect_uri + "?**", timeout=15000)
                out.ok(len(callback.hits) == 1, "the browser is redirected once to the registered loopback callback")
                params = callback.hits[0]
                out.ok(params.get("state") == [state], "the callback receives the exact state that was sent")
                out.ok(len(params.get("code", [""])[0]) >= 16 and "error" not in params,
                       "the callback receives an authorization code and no error")
                code = Secret(params["code"][0], "authorization code")

                # ---------------------------------------------------------------- redeem with the HTTP helper
                issued = oauth.tokens(oauth.redeem_code(ctx.http, web, code, verifier).expect(200))
                claims = ctx.validator.access_token(issued.access_token, app["audience"])
                id_claims = ctx.validator.id_token(issued.id_token, web.client_id, nonce=nonce)
                out.ok(claims["sub"] == user and claims.get("identity_kind") == "workforce"
                       and id_claims["sub"] == user, "the code redeems (PKCE) to tokens that validate for the person")

                # ---------------------------------------------------------------- browser-only protections
                cookies = context.cookies(base)
                session_cookies = [c for c in cookies if c["name"].upper().startswith(("JSESSIONID", "SESSION"))]
                axiom_page = context.new_page()
                axiom_page.goto(base + "/login")
                script_cookies = axiom_page.evaluate("() => document.cookie")
                out.refused(bool(session_cookies) and all(c["httpOnly"] for c in session_cookies)
                            and not any(c["name"] in script_cookies for c in session_cookies),
                            "the login session cookie is HttpOnly: page script on Axiom's origin cannot read it")
                out.facts["session_cookie"] = [{"name": c["name"], "httpOnly": c["httpOnly"],
                                                "sameSite": c.get("sameSite")} for c in session_cookies]
                axiom_page.close()

                out.refused(not any(password.reveal() in u for u in request_urls),
                            "the password never appears in any request URL (the form posts its body)")

                # A page on another origin frames the login page: the browser must refuse to render it.
                callback.pages["/frame"] = f'<!doctype html><iframe id="f" src="{base}/login"></iframe>'
                framer = context.new_page()
                with framer.expect_response(lambda r: r.url == base + "/login", timeout=15000) as framed_response:
                    framer.goto(callback.origin + "/frame")
                headers = framed_response.value.headers
                framer.wait_for_timeout(500)
                framed = [f for f in framer.frames if f != framer.main_frame]
                rendered = any(f.locator("input[name=password]").count() > 0 for f in framed if not f.is_detached())
                out.facts["framing_headers"] = {k: headers.get(k) for k in ("x-frame-options", "content-security-policy")
                                                if headers.get(k)}
                out.refused(framed_response.value.status == 200 and bool(out.facts["framing_headers"]) and not rendered,
                            "Axiom's login page cannot be framed by another origin (the page arrived, the browser "
                            "refused to render it: clickjacking)")
                framer.close()

                # Login CSRF: another origin auto-posts credentials to /login without Axiom's CSRF token.
                fresh = browser.new_context()
                attacker = fresh.new_page()
                callback.pages["/csrf"] = (
                    f'<!doctype html><form id="x" method="post" action="{base}/login">'
                    f'<input name="username" value="{user}"><input name="password" value="{password.reveal()}">'
                    '</form><script>document.getElementById("x").submit()</script>')
                responses: list[int] = []
                attacker.on("response", lambda r: responses.append(r.status) if r.url.startswith(base + "/login")
                            and r.request.method == "POST" else None)
                attacker.goto(callback.origin + "/csrf")
                attacker.wait_for_load_state("load")
                hits_before = len(callback.hits)
                attacker.goto(_authorize_url(base, web.client_id, web.redirect_uri, challenge, "csrf-probe", nonce))
                out.refused(responses and responses[0] in (302, 403) and urlparse(attacker.url).path == "/login"
                            and len(callback.hits) == hits_before,
                            "a login form posted from another origin without the CSRF token signs nobody in "
                            "(the next authorization request still asks for a login; no code is issued)")
                out.facts["cross_origin_login_post_status"] = responses[:1]
                callback.pages.clear()
                fresh.close()
                context.close()
            except BaseException:
                # Failure-only screenshot, taken while the browser is still open. The callback page never renders
                # the code and the password field is masked; no trace, video or HAR exists.
                if page is not None and not page.is_closed():
                    ARTIFACTS.mkdir(exist_ok=True)
                    try:
                        page.screenshot(path=str(ARTIFACTS / "o02-browser-failure.png"))
                    except Exception:
                        pass
                raise
            finally:
                browser.close()
    except BaseException as failure:
        message = scrub_text(str(failure))
        for value in sensitive:
            message = message.replace(value, "[redacted]")
        raise AssertionError(message) from None
    finally:
        callback.close()
    out.facts["requests_seen"] = len(request_urls)
    out.consumer_must += ["register an exact loopback or https redirect URI; check state before redeeming",
                          "keep the code and PKCE verifier out of logs, history and analytics"]
    record(out)
