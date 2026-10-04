"""A thin HTTP client for Axiom with redacted errors and request timing.

Every call returns an :class:`Response` you can assert on; nothing raises on a 4xx unless you ask it to with
``expect(...)``. Failures show the method, path, status and a *scrubbed* body, never a credential.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urljoin, urlsplit

import requests

from .redaction import Secret, scrub, scrub_text


class UnexpectedStatus(AssertionError):
    pass


class ForeignOrigin(RuntimeError):
    """A request or redirect would leave the verified Axiom origin. Raised before anything is sent."""


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    port = parts.port or {"http": 80, "https": 443}.get(scheme, -1)
    return scheme, (parts.hostname or "").lower(), port


@dataclass
class Response:
    method: str
    path: str
    status: int
    headers: Mapping[str, str]
    text: str
    elapsed_ms: float

    def json(self) -> Any:
        return json.loads(self.text) if self.text else None

    def expect(self, *statuses: int) -> "Response":
        if self.status not in statuses:
            raise UnexpectedStatus(f"{self.method} {self.path} -> {self.status} (expected {statuses}): "
                                   f"{scrub_text(self.text)}")
        return self

    def oauth_error(self) -> str | None:
        try:
            body = self.json()
        except ValueError:
            return None
        return body.get("error") if isinstance(body, dict) else None

    def __repr__(self) -> str:
        return f"<{self.method} {self.path} {self.status} {self.elapsed_ms:.0f}ms>"


@dataclass
class Timings:
    """Request timings in milliseconds, for information only (not a benchmark)."""
    samples: list[tuple[str, float]] = field(default_factory=list)

    def add(self, label: str, ms: float) -> None:
        self.samples.append((label, ms))


class AxiomHttp:
    MAX_REDIRECTS = 5

    def __init__(self, base_url: str, timeout: float = 20.0, timings: Timings | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.origin = _origin(self.base_url)
        if not self.origin[0] in ("http", "https") or not self.origin[1]:
            raise ForeignOrigin(f"not an http(s) origin: {base_url!r}")
        self.timeout = timeout
        self.timings = timings or Timings()

    def resolve(self, path: str) -> str:
        """Maps a path (or a same-origin absolute URL, e.g. a Location header) to a URL on the verified origin.
        Anything else — another scheme, host or port, or a scheme-relative ``//host`` reference — is refused, so no
        credential, cookie or form can ever be sent anywhere but the target the guard approved."""
        if path.startswith("//"):
            raise ForeignOrigin("scheme-relative URLs are not allowed")
        if path.startswith("/"):
            return self.base_url + path
        if _origin(path) != self.origin:
            raise ForeignOrigin(f"refusing to send a request to another origin: {urlsplit(path).netloc or path[:40]!r}")
        return path

    def session(self) -> requests.Session:
        """A cookie-carrying session (browser login); never logs cookies."""
        return requests.Session()

    def request(self, method: str, path: str, *, bearer: Secret | None = None, json_body: Any = None,
                form: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
                basic: tuple[str, Secret] | None = None, headers: Mapping[str, str] | None = None,
                session: requests.Session | None = None, allow_redirects: bool = False,
                params: Mapping[str, Any] | None = None, timeout: float | None = None) -> Response:
        h = {"Accept": "application/json"}
        if headers:
            h.update(headers)
        if bearer is not None:
            h["Authorization"] = "Bearer " + bearer.reveal()
        auth = (basic[0], basic[1].reveal()) if basic else None
        data = None
        if form is not None:
            items = form.items() if isinstance(form, Mapping) else form
            data = [(k, v.reveal() if isinstance(v, Secret) else v) for k, v in items]
        url = self.resolve(path)
        sender = session or requests
        started = time.perf_counter()
        # Redirects are never followed by the HTTP library: each hop is checked against the verified origin first.
        r = sender.request(method, url, json=json_body, data=data, auth=auth, headers=h, timeout=timeout or self.timeout,
                           allow_redirects=False, params=params)
        hops = 0
        while allow_redirects and r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            hops += 1
            if hops > self.MAX_REDIRECTS:
                raise ForeignOrigin("too many redirects")
            url = self.resolve(urljoin(url, r.headers["Location"]))
            keep_body = r.status_code in (307, 308)
            r = sender.request(method if keep_body else "GET", url, json=json_body if keep_body else None,
                               data=data if keep_body else None, auth=auth, headers=h, timeout=timeout or self.timeout,
                               allow_redirects=False)
        elapsed = (time.perf_counter() - started) * 1000
        shown = urlsplit(path).path or path.split("?")[0]
        self.timings.add(f"{method} {shown}", elapsed)
        return Response(method, shown, r.status_code, dict(r.headers), r.text, elapsed)

    def get(self, path: str, **kw: Any) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> Response:
        return self.request("POST", path, **kw)

    def put(self, path: str, **kw: Any) -> Response:
        return self.request("PUT", path, **kw)

    def patch(self, path: str, **kw: Any) -> Response:
        return self.request("PATCH", path, **kw)

    def delete(self, path: str, **kw: Any) -> Response:
        return self.request("DELETE", path, **kw)


def describe(body: Any) -> str:
    """Printable, scrubbed rendering of any response body."""
    return json.dumps(scrub(body), indent=2, sort_keys=True, default=str)
