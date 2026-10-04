"""OAuth 2.0 / OIDC handshakes against Axiom, exactly as a consumer performs them over HTTP.

* :func:`browser_login` — authorization code with S256 PKCE (RFC 7636), state and OIDC nonce, through Axiom's real
  login form (CSRF-protected, cookie session). There is no password grant: the form is what a browser would submit.
* :func:`client_credentials` — RFC 6749 §4.4 for a confidential client; no person involved.
* :func:`exchange` — RFC 8693 token exchange (Axiom's on-behalf-of profile; ``actor_token`` is not used: the
  authenticated client is the exchanging party and Axiom records the acting workload in ``act``).
* :func:`introspect` / :func:`revoke` — RFC 7662 / RFC 7009, authenticated with client credentials.
* :func:`refresh` — RFC 6749 section 6 for a confidential web client granted ``offline_access``.
* :func:`client_assertion` — a ``private_key_jwt`` client assertion (RFC 7523 section 2.2), signed with the client's
  own private key, which never leaves the client.

The login page a browser lands on depends on the client's population: workforce clients use ``/login``, customer
(CIAM) clients ``/login/customer``. Both are real CSRF-protected forms; neither is a password grant.
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Iterable, Mapping
from urllib.parse import parse_qs, urlencode, urlparse

from .http import AxiomHttp, Response
from .redaction import Secret

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


@dataclass(frozen=True)
class Client:
    """An OAuth client as the consumer holds it. ``secret`` is None for public (browser) clients."""
    client_id: str
    secret: Secret | None = None
    redirect_uri: str | None = None

    def basic(self) -> tuple[str, Secret]:
        if self.secret is None:
            raise ValueError(f"{self.client_id} is a public client")
        return (self.client_id, self.secret)


@dataclass(frozen=True)
class Tokens:
    access_token: Secret
    id_token: Secret | None
    expires_in: int
    scope: str
    raw_fields: Mapping[str, object]
    refresh_token: Secret | None = None


class LoginFailed(AssertionError):
    pass


def pkce_pair() -> tuple[Secret, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return Secret(verifier, "PKCE verifier"), challenge


class ConsentRequired(AssertionError):
    """The authorization server showed its consent page and the caller chose not to approve."""


def authorize_code(http: AxiomHttp, client: Client, username: str, password: Secret, scopes: Iterable[str],
                   challenge: str, state: str, nonce: str, approve: Iterable[str] | None = None,
                   session=None) -> tuple[Secret, object]:
    """Drives the browser part of the flow and returns (authorization code, session). The code never prints.

    The login page is whichever one Axiom redirects to (workforce ``/login`` or customer ``/login/customer``). If the
    client requires consent, Axiom's consent page is answered with ``approve`` (default: every scope it offers); an
    empty ``approve`` denies. ``session`` reuses an existing browser session (no form if it is still signed in)."""
    session = session or http.session()
    query = urlencode({"response_type": "code", "client_id": client.client_id, "redirect_uri": client.redirect_uri,
                       "scope": " ".join(scopes), "state": state, "nonce": nonce, "code_challenge": challenge,
                       "code_challenge_method": "S256"})
    first = http.get("/oauth/authorize?" + query, session=session, headers={"Accept": "text/html"})
    location = first.headers.get("Location", "")
    if first.status == 302 and ("/login" in urlparse(location).path) and not location.startswith(client.redirect_uri or "\u0000"):
        login_path = urlparse(location).path
        form = http.get(login_path, session=session, headers={"Accept": "text/html"}).expect(200)
        match = re.search(r'name="_csrf"\s+value="([^"]+)"', form.text) or re.search(r'value="([^"]+)"\s+name="_csrf"', form.text)
        if not match:
            raise LoginFailed("login form has no CSRF token")
        posted = http.post(login_path, session=session, headers={"Accept": "text/html"},
                           form={"username": username, "password": password, "_csrf": match.group(1)})
        location = posted.headers.get("Location", "")
        if posted.status != 302 or "error" in location:
            raise LoginFailed("login was refused")
        resumed = http.get(location, session=session, headers={"Accept": "text/html"})
    elif first.status == 302:
        resumed = first
    else:
        raise LoginFailed(f"authorize did not redirect: {first.status}")
    consent_location = resumed.headers.get("Location", "")
    if resumed.status == 302 and urlparse(consent_location).path == "/oauth2/consent":
        # Axiom's own consent page (the authorization server redirects there when the client requires consent).
        resumed = http.get(consent_location, session=session, headers={"Accept": "text/html"}).expect(200)
    if resumed.status == 200 and 'name="consent_form"' in resumed.text:
        resumed = _answer_consent(http, session, resumed.text, approve)
    location = resumed.headers.get("Location", "")
    if resumed.status != 302 or not location.startswith(client.redirect_uri or "\u0000"):
        raise LoginFailed(f"authorization did not return to the client (status {resumed.status})")
    params = parse_qs(urlparse(location).query)
    if params.get("state") != [state]:
        raise LoginFailed("state mismatch")
    if "code" not in params:
        error = ",".join(params.get("error", ["?"]))
        if error == "access_denied":
            raise ConsentRequired("consent was not given")
        raise LoginFailed("no authorization code: " + error)
    return Secret(params["code"][0], "authorization code"), session


def consent_scopes(page: str) -> list[str]:
    """The scopes Axiom's consent page asks the person to approve."""
    return re.findall(r'type="checkbox"\s+name="scope"\s+value="([^"]+)"', page)


def _answer_consent(http: AxiomHttp, session, page: str, approve: Iterable[str] | None):
    hidden = dict(re.findall(r'type="hidden"\s+name="(client_id|state)"\s+value="([^"]*)"', page))
    if "client_id" not in hidden or "state" not in hidden:
        raise LoginFailed("consent page without client_id/state")
    offered = consent_scopes(page)
    chosen = offered if approve is None else [s for s in approve if s in offered]
    form = [("client_id", hidden["client_id"]), ("state", hidden["state"])] + [("scope", s) for s in chosen]
    return http.post("/oauth/authorize", session=session, headers={"Accept": "text/html"}, form=form)


def redeem_code(http: AxiomHttp, client: Client, code: Secret, verifier: Secret,
                redirect_uri: str | None = None) -> Response:
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri or client.redirect_uri,
            "client_id": client.client_id, "code_verifier": verifier}
    if client.secret is not None:
        return http.post("/oauth/token", form=form, basic=client.basic())
    return http.post("/oauth/token", form=form)


def browser_login(http: AxiomHttp, client: Client, username: str, password: Secret,
                  scopes: Iterable[str], approve: Iterable[str] | None = None, session=None) -> Tokens:
    """Full authorization-code + PKCE login; returns the token response as Secrets."""
    verifier, challenge = pkce_pair()
    state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    code, _ = authorize_code(http, client, username, password, scopes, challenge, state, nonce, approve, session)
    return tokens(redeem_code(http, client, code, verifier).expect(200))


def tokens(response: Response) -> Tokens:
    body = response.json()
    return Tokens(Secret(body["access_token"], "access token"),
                  Secret(body["id_token"], "ID token") if body.get("id_token") else None,
                  int(body.get("expires_in", 0)), body.get("scope", ""),
                  {k: v for k, v in body.items() if k not in ("access_token", "id_token", "refresh_token",
                                                                "renewal_handle")},
                  Secret(body["refresh_token"], "refresh token") if body.get("refresh_token") else None)


def client_credentials(http: AxiomHttp, client: Client, scopes: Iterable[str]) -> Response:
    return http.post("/oauth/token", basic=client.basic(),
                     form={"grant_type": "client_credentials", "scope": " ".join(scopes)})


def exchange(http: AxiomHttp, client: Client, subject_token: Secret, audience: str, scopes: Iterable[str],
             extra: Mapping[str, str] | None = None) -> Response:
    form = [("grant_type", TOKEN_EXCHANGE), ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TOKEN_TYPE), ("requested_token_type", ACCESS_TOKEN_TYPE),
            ("audience", audience), ("scope", " ".join(scopes))]
    form += list((extra or {}).items())
    return http.post("/oauth/token", basic=client.basic(), form=form)


def introspect(http: AxiomHttp, caller: Client, token: Secret) -> dict:
    return http.post("/oauth/introspect", basic=caller.basic(), form={"token": token}).expect(200).json()


def revoke(http: AxiomHttp, caller: Client, token: Secret, hint: str = "access_token") -> Response:
    return http.post("/oauth/revoke", basic=caller.basic(), form={"token": token, "token_type_hint": hint})


def refresh(http: AxiomHttp, client: Client, refresh_token: Secret, scopes: Iterable[str] | None = None) -> Response:
    form = [("grant_type", "refresh_token"), ("refresh_token", refresh_token)]
    if scopes is not None:
        form.append(("scope", " ".join(scopes)))
    return http.post("/oauth/token", basic=client.basic(), form=form)


JWT_BEARER_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def client_assertion(client_id: str, private_key, kid: str, audience: str, lifetime_s: int = 60,
                     jti: str | None = "random", algorithm: str = "RS256", issued_at: int | None = None) -> Secret:
    """A ``private_key_jwt`` assertion: iss = sub = client_id, aud = the token endpoint, short exp, single-use jti."""
    import time
    import jwt as pyjwt
    now = int(time.time()) if issued_at is None else issued_at
    claims = {"iss": client_id, "sub": client_id, "aud": audience, "iat": now, "exp": now + lifetime_s}
    if jti is not None:
        claims["jti"] = secrets.token_urlsafe(16) if jti == "random" else jti
    value = pyjwt.encode(claims, private_key, algorithm=algorithm, headers={"kid": kid, "typ": "JWT"})
    return Secret(value, "client assertion")


def client_credentials_with_assertion(http: AxiomHttp, client_id: str, assertion: Secret,
                                      scopes: Iterable[str]) -> Response:
    return http.post("/oauth/token", form=[("grant_type", "client_credentials"), ("scope", " ".join(scopes)),
                                           ("client_id", client_id), ("client_assertion_type", JWT_BEARER_ASSERTION),
                                           ("client_assertion", assertion)])


def logout(http: AxiomHttp, id_token: Secret, session=None, post_logout_redirect_uri: str | None = None) -> Response:
    """OIDC RP-Initiated Logout 1.0 as a form POST: the ID token never appears in a URL."""
    form = [("id_token_hint", id_token)]
    if post_logout_redirect_uri:
        form.append(("post_logout_redirect_uri", post_logout_redirect_uri))
    return http.post("/connect/logout", form=form, session=session, headers={"Accept": "text/html"})
