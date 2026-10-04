"""Offline safety contract of the cookbook itself (no Axiom needed): target guard and credential redaction."""
from __future__ import annotations

import json

import pytest

from axiom_cookbook.redaction import Secret, scrub, scrub_text
from axiom_cookbook.target import TargetRefused, guard


@pytest.mark.parametrize("url", ["https://axiom.prod.example.com", "https://iam.openwolf.io", "http://10.0.0.5:8084",
                                 "https://axiom-api.default.svc.cluster.local", "https://argus-gateway.example.test",
                                 "ftp://127.0.0.1"])
def test_refuses_shared_production_and_remote_targets(url):
    with pytest.raises(TargetRefused):
        guard(url, "tenant-a", "ckbk-abcdef12", allow_writes=True)


def test_accepts_only_loopback_with_a_cookbook_namespace():
    assert guard("http://127.0.0.1:8084", "tenant-a", "ckbk-abcdef12", True).base_url == "http://127.0.0.1:8084"
    with pytest.raises(TargetRefused):
        guard("http://127.0.0.1:8084", "tenant-a", "prod-data", True)
    with pytest.raises(TargetRefused):
        guard("http://127.0.0.1:8084", "tenant-a", "ckbk-abcdef12", False).require_writes()


def test_secrets_never_print():
    s = Secret("super-secret-value-1234", "client secret")
    assert "super-secret" not in repr(s) and "super-secret" not in str(s) and "super-secret" not in f"{s}"
    body = {"access_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0abc.c2lnbmF0dXJlLXZhbHVl", "serviceSecret": "abc",
            "nested": [{"password": "pw", "note": "token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0abc.c2lnbmF0dXJl"}]}
    rendered = json.dumps(scrub(body))
    assert "abc" not in rendered.replace("[redacted]", "") and "eyJ" not in rendered and "pw" not in rendered
    assert "code=[redacted]" in scrub_text("http://x/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz")


# --------------------------------------------------------------------------------------------------------------------
# Origin confinement of the HTTP client (regression for a review finding: absolute URLs could bypass the guard).
# --------------------------------------------------------------------------------------------------------------------
import requests  # noqa: E402

from axiom_cookbook.http import AxiomHttp, ForeignOrigin  # noqa: E402

TARGET = "http://127.0.0.1:8084"
BEARER = Secret("eyJhbGciOiJSUzI1NiJ9.e30.c2ln", "access token")
CLIENT_SECRET = Secret("client-secret-value-123456", "client secret")


class _Recorder:
    """Stands in for the network: records every request; answers with a scripted response."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = list(responses or [])

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw.get("headers", {}), kw.get("auth")))
        if self.responses:
            return self.responses.pop(0)
        r = requests.Response()
        r.status_code, r._content = 200, b"{}"
        return r


def _redirect(location: str) -> requests.Response:
    r = requests.Response()
    r.status_code, r._content = 302, b""
    r.headers["Location"] = location
    return r


@pytest.mark.parametrize("url", ["https://attacker.example/steal", "http://127.0.0.1:9999/admin",
                                 "https://127.0.0.1:8084/admin", "//attacker.example/steal", "file:///etc/passwd"])
def test_bearer_requests_cannot_leave_the_verified_origin(url):
    recorder = _Recorder()
    http = AxiomHttp(TARGET)
    with pytest.raises(ForeignOrigin):
        http.get(url, bearer=BEARER, session=recorder)
    assert recorder.calls == [], "nothing may be sent"


@pytest.mark.parametrize("url", ["https://attacker.example/oauth/token", "http://localhost:8084/oauth/token"])
def test_basic_auth_requests_cannot_leave_the_verified_origin(url):
    recorder = _Recorder()
    with pytest.raises(ForeignOrigin):
        AxiomHttp(TARGET).post(url, basic=("client", CLIENT_SECRET), form={"grant_type": "client_credentials"},
                               session=recorder)
    assert recorder.calls == []


def test_same_origin_absolute_urls_and_paths_are_allowed():
    recorder = _Recorder()
    http = AxiomHttp(TARGET)
    http.get("/oauth2/jwks", session=recorder)
    http.get(TARGET + "/login?continue", bearer=BEARER, session=recorder)
    assert [c[1] for c in recorder.calls] == [TARGET + "/oauth2/jwks", TARGET + "/login?continue"]


def test_redirects_to_another_origin_are_never_followed_with_credentials():
    recorder = _Recorder([_redirect("https://attacker.example/collect")])
    with pytest.raises(ForeignOrigin):
        AxiomHttp(TARGET).get("/oauth/authorize", bearer=BEARER, session=recorder, allow_redirects=True)
    assert len(recorder.calls) == 1 and recorder.calls[0][1] == TARGET + "/oauth/authorize"


def test_same_origin_redirects_are_followed_hop_by_hop():
    recorder = _Recorder([_redirect("/login"), _redirect(TARGET + "/done")])
    r = AxiomHttp(TARGET).get("/start", basic=("client", CLIENT_SECRET), session=recorder, allow_redirects=True)
    assert r.status == 200
    assert [c[1] for c in recorder.calls] == [TARGET + "/start", TARGET + "/login", TARGET + "/done"]


def test_the_library_itself_never_auto_follows_redirects():
    recorder = _Recorder([_redirect("https://attacker.example/x")])
    r = AxiomHttp(TARGET).get("/oauth/authorize", bearer=BEARER, session=recorder)
    assert r.status == 302 and len(recorder.calls) == 1


def test_discovery_cannot_point_trust_at_another_origin():
    from axiom_cookbook.tokens import InvalidToken, Validator

    def discovery(body):
        r = requests.Response()
        r.status_code, r._content = 200, json.dumps(body).encode()
        return r

    class FakeHttp(AxiomHttp):
        def __init__(self, body):
            super().__init__(TARGET)
            self.body = body

        def get(self, path, **kw):
            return super().get(path, session=_Recorder([discovery(self.body)]), **kw)

    with pytest.raises(ForeignOrigin):
        Validator.discover(FakeHttp({"issuer": TARGET, "jwks_uri": "https://attacker.example/jwks"}))
    with pytest.raises(InvalidToken):
        Validator.discover(FakeHttp({"issuer": "https://attacker.example", "jwks_uri": TARGET + "/oauth2/jwks"}))


def test_recovery_wait_accepts_only_a_genuinely_active_result():
    """Regression (Codex review): the disruptive recovery wait must not stop on an exception or a non-active body."""
    from tests.test_disruptive import _active
    assert _active({"active": True})
    for not_recovered in (ConnectionError("refused"), TimeoutError(), None, {}, {"active": False},
                          {"active": "true"}, {"error": "server_error"}, [{"active": True}]):
        assert not _active(not_recovered)
