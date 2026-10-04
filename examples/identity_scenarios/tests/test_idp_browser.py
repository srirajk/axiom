"""IDP-02/08/12 in a real browser: customer (CIAM) and workforce sign-in through Axiom's own pages, the OAuth consent
page, the population boundary inside one browser session, and RP-initiated logout ending the browser session.

Protocol correctness is proven by the HTTP contracts (``idp/idp02_browser_signin.py``, ``idp08``, ``idp12``). This test
proves what needs a browser: the real pages, forms (CSRF), consent UI, cookies and redirect chains in Chromium.

Artifacts: none. No screenshot, trace, video or HAR is ever written (even on failure), so no code, token, cookie or
password can reach disk. Failure messages are scrubbed. The loopback callback keeps queries in memory only.
"""
from __future__ import annotations

import html
import secrets
from urllib.parse import urlencode, urlparse

import pytest

from axiom_cookbook import ciam, oauth
from axiom_cookbook.example import Outcome
from axiom_cookbook.redaction import Secret
from tests.conftest import record
from tests.test_o02_browser import LoopbackCallback

playwright_api = pytest.importorskip("playwright.sync_api", reason="install the 'browser' extra (playwright==1.63.0)")
pytestmark = pytest.mark.browser
READ, WRITE = "orders.read", "orders.write"


def _authorize(base, client, challenge, state, nonce, scopes):
    return base + "/oauth/authorize?" + urlencode({
        "response_type": "code", "client_id": client.client_id, "redirect_uri": client.redirect_uri,
        "scope": " ".join(scopes), "state": state, "nonce": nonce, "code_challenge": challenge,
        "code_challenge_method": "S256"})


def _sign_in(page, username, password: Secret):
    page.wait_for_selector("form input[name=password]")
    page.fill("input[name=username]", username)
    page.fill("input[name=password]", password.reveal())
    page.click("form [type=submit]")


def test_idp_browser_ciam_consent_population_and_logout(ctx):
    out = Outcome("IDP-02/08/12 browser: CIAM and workforce sign-in, consent, population boundary, logout")
    callback = LoopbackCallback()
    http, v = ctx.http, ctx.validator
    op = ctx.operator()
    app = ctx.application(op, "browser-shop")
    shop, _ = ctx.interactive_client(op, app, "browser-shop-web", [READ, WRITE], population="CUSTOMER",
                                     require_consent=True, redirect_uri=callback.redirect_uri,
                                     post_logout_redirect_uri=callback.origin + "/logged-out")
    staff, _ = ctx.interactive_client(op, app, "browser-staff-web", [READ], require_consent=True,
                                      redirect_uri=callback.redirect_uri,
                                      post_logout_redirect_uri=callback.origin + "/logged-out")
    rs, _ = ctx.service_client(op, app, "browser-rs", [READ])
    role = ctx.app_role(op, app, "reader", {READ: "allow"})
    person, person_pw = ctx.workforce_user(op, "browser-person")
    ctx.membership(op, app, person, role["id"])
    customer = ciam.verified(ctx, op, "browser-customer")
    base = http.base_url
    urls: list[str] = []
    try:
        with playwright_api.sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                context = browser.new_context()  # no record_video / record_har / tracing
                page = context.new_page()
                page.on("request", lambda r: urls.append(r.url))

                # Customer: customer login page, consent page, callback.
                verifier, challenge = oauth.pkce_pair()
                state, nonce = secrets.token_urlsafe(12), secrets.token_urlsafe(12)
                page.goto(_authorize(base, shop, challenge, state, nonce, ("openid", READ, WRITE)))
                out.ok(urlparse(page.url).path == "/login/customer" and page.locator("form input[name=_csrf]").count() >= 1,
                       "a customer-facing client sends the browser to the customer login page (CSRF form)")
                _sign_in(page, customer.email, customer.password)
                page.wait_for_selector("form[name=consent_form]", timeout=15000)
                offered = page.locator("input[name=scope]").evaluate_all("els => els.map(e => e.value)")
                out.ok(set(offered) == {READ, WRITE}, "Axiom's consent page asks for the requested scopes")
                page.check(f"input[name=scope][value='{READ}']")
                if page.locator(f"input[name=scope][value='{WRITE}']").is_checked():
                    page.uncheck(f"input[name=scope][value='{WRITE}']")
                page.click("#submit-consent")
                page.wait_for_url(callback.redirect_uri + "?**", timeout=15000)
                hit = callback.hits[-1]
                out.ok(hit.get("state") == [state] and "code" in hit, "the callback receives the state and a code")
                tokens = oauth.tokens(oauth.redeem_code(http, shop, Secret(hit["code"][0], "code"), verifier).expect(200))
                claims = v.access_token(tokens.access_token, app["audience"])
                out.ok(claims["sub"] == customer.id and v.id_token(tokens.id_token, shop.client_id, nonce)["sub"] == customer.id,
                       "the code redeems to tokens for the customer")
                out.ok(READ in str(claims["scope"]) and WRITE not in str(claims["scope"]), "only the approved scope is issued")

                # Population boundary inside the same browser session.
                v2, c2 = oauth.pkce_pair()
                hits_before = len(callback.hits)
                page.goto(_authorize(base, staff, c2, "s-wf", "n-wf", ("openid", READ)))
                out.refused(urlparse(page.url).path == "/login" and len(callback.hits) == hits_before,
                            "the signed-in customer's browser gets no workforce code: it lands on the workforce login")

                # Workforce sign-in in the same browser replaces the customer login; the workforce client also asks
                # for consent on Axiom's own consent page.
                _sign_in(page, person, person_pw)
                page.wait_for_selector("form[name=consent_form]", timeout=15000)
                out.ok(urlparse(page.url).path == "/oauth2/consent"
                       and page.locator("input[name=scope]").evaluate_all("els => els.map(e => e.value)") == [READ],
                       "the workforce consent page (Axiom-hosted) asks for the requested scope")
                page.click("#submit-consent")
                page.wait_for_url(callback.redirect_uri + "?**", timeout=15000)
                wf_hit = callback.hits[-1]
                wf = oauth.tokens(oauth.redeem_code(http, staff, Secret(wf_hit["code"][0], "code"), v2).expect(200))
                out.ok(v.access_token(wf.access_token, app["audience"])["sub"] == person, "the workforce person signs in")

                # RP-initiated logout from the browser (form POST; the ID token is never in a URL).
                callback.pages["/logout"] = (
                    f'<!doctype html><form id="l" method="post" action="{base}/connect/logout">'
                    f'<input type="hidden" name="id_token_hint" value="{html.escape(wf.id_token.reveal())}">'
                    f'<input type="hidden" name="post_logout_redirect_uri" value="{callback.origin}/logged-out">'
                    '</form><script>document.getElementById("l").submit()</script>')
                callback.pages["/logged-out"] = "<!doctype html><title>logged out</title><p>Signed out.</p>"
                logout_responses: list[tuple[int, str]] = []
                page.on("response", lambda r: logout_responses.append((r.status, urlparse(r.url).path))
                        if "/connect/logout" in r.url else None)
                page.goto(callback.origin + "/logout")
                try:
                    page.wait_for_url(callback.origin + "/logged-out", timeout=15000)
                except Exception:
                    raise AssertionError(f"logout did not reach the post-logout URI: {logout_responses} "
                                         f"now at {urlparse(page.url).path}") from None
                callback.pages.pop("/logout")
                out.ok(True, "logout redirects to the registered post-logout URI")
                out.refused(oauth.introspect(http, rs, wf.access_token)["active"] is False,
                            "after logout the person's access token is inactive")
                hits_before = len(callback.hits)
                page.goto(_authorize(base, staff, oauth.pkce_pair()[1], "s-again", "n-again", ("openid", READ)))
                out.refused(urlparse(page.url).path == "/login" and len(callback.hits) == hits_before,
                            "the browser session ended: the next authorization request asks for a login again")
                out.ok(oauth.introspect(http, rs, tokens.access_token)["active"] is True,
                       "the customer's independent login (another session) is unaffected by the person's logout")
                out.refused(not any(person_pw.reveal() in u or customer.password.reveal() in u for u in urls),
                            "no password appears in any request URL")
                out.refused(not any("id_token_hint" in u for u in urls), "no ID token appears in any request URL")
                foreign = sorted({urlparse(u).netloc for u in urls if urlparse(u).scheme in ("http", "https")}
                                 - {urlparse(base).netloc, urlparse(callback.origin).netloc})
                out.refused(not foreign, "login, consent and logout pages load nothing from third-party origins")
                out.facts["third_party_hosts"] = foreign
                context.close()
            finally:
                browser.close()
    finally:
        callback.close()
    record(out)
    assert out.allowed and out.denied
