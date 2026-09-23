#!/usr/bin/env python3
"""Functional proof for Axiom workforce, Agent, and Argus Gateway token exchange.

The verifier consumes the reviewed Meridian configuration and its local one-time
service credentials. It never prints credentials, authorization codes, or tokens.
"""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import os
import pathlib
import re
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html import unescape
from typing import Any, Callable


TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
SCOPE = "cards:incident.read"


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: str

    def json(self) -> Any:
        return json.loads(self.body)


class RedirectCaptured(Exception):
    def __init__(self, location: str) -> None:
        super().__init__("authorization callback captured")
        self.location = location


class CallbackRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> urllib.request.Request | None:
        if newurl.startswith("http://127.0.0.1:8765/callback"):
            raise RedirectCaptured(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Verifier:
    def __init__(self) -> None:
        self.base_url = os.environ.get("AXIOM_BASE_URL", "http://127.0.0.1:8180").rstrip("/")
        self.issuer = os.environ.get(
            "AXIOM_ISSUER", "https://identity.meridian.com:8443"
        ).rstrip("/")
        self.tenant = os.environ.get("AXIOM_TENANT_ID", "meridian")
        self.username = os.environ.get("AXIOM_WORKFORCE_USERNAME", "wei.liu")
        self.password = required("AXIOM_SEED_USER_PASSWORD")
        self.admin_password = required("AXIOM_ADMIN_PASSWORD")
        self.public_client = "card-operator-web"
        self.source_client = "card-assistance-agent"
        self.destination_client = "card-actions-agent"
        self.gateway_client = "argus-gateway-broker"
        self.source_audience = "cards-api"
        self.destination_audience = "card-actions-api"
        self.gateway_audience = "argus-gateway"
        self.resource_audience = "card-case-api"
        self.source_ref = "agent:card-assistance:development"
        self.destination_ref = "agent:card-actions:development"
        self.secrets = self.load_secrets()
        self.tokens: list[str] = []
        self.failures: list[str] = []
        self.admin_token = ""
        self.workforce_token = ""
        self.source_subject = ""
        self.source_gateway = ""
        self.destination_subject = ""
        self.destination_gateway = ""
        self.resource_token = ""

    def load_secrets(self) -> dict[str, str]:
        path = pathlib.Path(os.environ.get(
            "AXIOM_AGENT_SECRET_FILE", ".local/configured-agent-clients.json"
        ))
        payload = json.loads(path.read_text(encoding="utf-8"))
        values = payload.get(self.tenant, {})
        needed = {self.source_client, self.destination_client}
        missing = sorted(name for name in needed if not values.get(name))
        if missing:
            raise RuntimeError("configured service credentials are incomplete: " + ", ".join(missing))
        result = {name: str(values[name]) for name in needed}
        result[self.gateway_client] = kubernetes_secret_value(
            "argus-system", "argus-gateway-agent-exchange-oauth-client", "client_secret"
        )
        return result

    def run(self) -> int:
        self.act("health-and-protocol-discovery", self.health)
        self.act("reviewed-authority-inventory", self.authority_inventory)
        self.act("workforce-pkce-authentication", self.workforce_authentication)
        self.act("workforce-to-source-agent", self.workforce_to_source_agent)
        self.act("source-agent-to-gateway", self.source_agent_to_gateway)
        self.act("gateway-to-destination-agent", self.gateway_to_destination_agent)
        self.act("destination-agent-to-gateway", self.destination_agent_to_gateway)
        self.act("gateway-to-resource", self.gateway_to_resource)
        self.act("negative-authority", self.negative_authority)
        self.act("audit-and-secrecy", self.audit_and_secrecy)
        if self.failures:
            print(f"RESULT FAIL ({len(self.failures)} functional act(s))")
            return 1
        print("RESULT PASS (workforce -> Agent -> Argus Gateway -> Agent -> resource)")
        return 0

    def act(self, name: str, operation: Callable[[], str]) -> None:
        try:
            print(f"PASS {name}: {operation()}")
        except Exception as error:
            self.failures.append(name)
            print(f"FAIL {name}: {safe_error(error)}")

    def health(self) -> str:
        health = request(self.base_url + "/actuator/health")
        expect(health.status == 200 and health.json().get("status") == "UP", "health is not UP")
        discovery = request(self.base_url + "/.well-known/openid-configuration")
        expect(discovery.status == 200, f"discovery HTTP {discovery.status}")
        expect(discovery.json().get("issuer") == self.issuer, "issuer mismatch")
        expect(TOKEN_EXCHANGE in set(discovery.json().get("grant_types_supported", [])),
               "RFC 8693 is not advertised")
        return "live issuer is healthy and advertises RFC 8693"

    def authority_inventory(self) -> str:
        login = request(
            self.base_url + "/auth/login", method="POST",
            json_body={"username": "admin", "password": self.admin_password},
        )
        expect(login.status == 200, f"administrator login HTTP {login.status}")
        self.admin_token = str(login.json()["accessToken"])
        brokers = self.admin_get(f"/admin/tenants/{self.tenant}/agent-exchange/brokers")
        routes = self.admin_get(f"/admin/tenants/{self.tenant}/agent-exchange/routes")
        active_brokers = [item for item in brokers if item.get("status") == "ACTIVE"]
        active_routes = [
            item for item in routes
            if item.get("status") == "ACTIVE" and SCOPE in set(item.get("scopes", []))
        ]
        expect(len(active_brokers) == 1, "expected one active trusted broker")
        expect(active_brokers[0].get("oauthClientId") == self.gateway_client,
               "unexpected trusted broker")
        expected = {
            ("GATEWAY", self.gateway_audience),
            ("AGENT", self.destination_audience),
            ("GATEWAY", self.gateway_audience),
            ("RESOURCE", self.resource_audience),
        }
        actual = {(str(item.get("destinationType")), str(item.get("audience")))
                  for item in active_routes}
        expect(len(active_routes) == 4 and actual == expected,
               "reviewed route inventory does not match the four-route contract")
        return "one broker and four active typed routes match the reviewed configuration"

    def workforce_authentication(self) -> str:
        verifier = secrets.token_urlsafe(48)
        challenge = b64url(hashlib.sha256(verifier.encode()).digest())
        state = secrets.token_urlsafe(24)
        redirect_uri = "http://127.0.0.1:8765/callback"
        params = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": self.public_client,
            "redirect_uri": redirect_uri,
            "scope": f"openid profile {SCOPE}",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            CallbackRedirectHandler(),
        )
        login_page = opener.open(self.base_url + "/oauth/authorize?" + params, timeout=30)
        html = login_page.read().decode()
        csrf = hidden_input(html, "_csrf")
        form = urllib.parse.urlencode({
            "username": self.username,
            "password": self.password,
            "_csrf": csrf,
        }).encode()
        try:
            opener.open(urllib.request.Request(
                self.base_url + "/login", data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST",
            ), timeout=30)
            raise AssertionError("OIDC authorization did not return a callback")
        except RedirectCaptured as callback:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(callback.location).query)
        expect(query.get("state") == [state], "OIDC state mismatch")
        expect(len(query.get("code", [])) == 1, "authorization code is absent")
        token = request(
            self.base_url + "/oauth/token", method="POST",
            form={
                "grant_type": "authorization_code",
                "client_id": self.public_client,
                "code": query["code"][0],
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        expect(token.status == 200, f"authorization-code redemption HTTP {token.status}")
        self.workforce_token = str(token.json()["access_token"])
        self.tokens.append(self.workforce_token)
        claims = self.validate(
            self.workforce_token, audience=self.source_audience, profile=None,
            token_use=None, actor_ref=None, client_id=self.public_client,
        )
        expect(claims.get("identity_kind") == "workforce", "workforce identity kind is absent")
        expect(claims.get("sub") == "meridian-1008", "unexpected workforce subject")
        expect("card-incident-operator" in set(claims.get("roles", [])),
               "application role is absent")
        return "S256 PKCE issued a live application-scoped workforce token"

    def workforce_to_source_agent(self) -> str:
        self.source_subject = self.exchange(
            self.workforce_token, self.source_client, self.source_audience
        )
        claims = self.validate(
            self.source_subject, audience=self.source_audience, profile="workforce",
            token_use="exchange_subject", actor_ref=self.source_ref,
            client_id=self.source_client,
        )
        expect(claims.get("sub") == "meridian-1008", "root workforce subject changed")
        return "assigned workforce authority entered only the exact source Agent"

    def source_agent_to_gateway(self) -> str:
        self.source_gateway = self.exchange(
            self.source_subject, self.source_client, self.gateway_audience
        )
        claims = self.validate(
            self.source_gateway, audience=self.gateway_audience,
            profile="workload_continuation", token_use="gateway_authorization",
            actor_ref=self.source_ref, client_id=self.source_client,
        )
        expect(claims.get("sub") == "meridian-1008", "root workforce subject changed")
        return "source Agent minted only its reviewed Gateway authorization"

    def gateway_to_destination_agent(self) -> str:
        self.destination_subject = self.exchange(
            self.source_gateway, self.gateway_client, self.destination_audience
        )
        claims = self.validate(
            self.destination_subject, audience=self.destination_audience,
            profile="gateway_backend", token_use="exchange_subject",
            actor_ref=self.source_ref, client_id=self.gateway_client,
        )
        expect(claims.get("sub") == "meridian-1008", "root workforce subject changed")
        return "trusted Gateway continued authority to the exact downstream Agent"

    def destination_agent_to_gateway(self) -> str:
        self.destination_gateway = self.exchange(
            self.destination_subject, self.destination_client, self.gateway_audience
        )
        claims = self.validate(
            self.destination_gateway, audience=self.gateway_audience,
            profile="workload_continuation", token_use="gateway_authorization",
            actor_ref=self.destination_ref, client_id=self.destination_client,
        )
        expect(claims.get("sub") == "meridian-1008", "root workforce subject changed")
        return "downstream Agent became the current actor without changing the subject"

    def gateway_to_resource(self) -> str:
        self.resource_token = self.exchange(
            self.destination_gateway, self.gateway_client, self.resource_audience
        )
        claims = self.validate(
            self.resource_token, audience=self.resource_audience,
            profile="gateway_backend", token_use="delegated_access",
            actor_ref=self.destination_ref, client_id=self.gateway_client,
        )
        expect(claims.get("sub") == "meridian-1008", "root workforce subject changed")
        expect("delegation_id" not in claims, "workforce flow fabricated customer delegation")
        return "Gateway minted one audience-bound resource token for the current Agent actor"

    def negative_authority(self) -> str:
        wrong_target = self.exchange_response(
            self.source_gateway, self.gateway_client, self.resource_audience
        )
        expect(wrong_target.status == 400, f"unrouted resource returned HTTP {wrong_target.status}")
        wrong_actor = self.exchange_response(
            self.destination_subject, self.source_client, self.gateway_audience
        )
        expect(wrong_actor.status == 400, f"sibling replay returned HTTP {wrong_actor.status}")
        excessive = self.exchange_response(
            self.destination_gateway, self.gateway_client, self.resource_audience,
            scope="cards:freeze.propose",
        )
        expect(excessive.status == 400, f"scope escalation returned HTTP {excessive.status}")
        actor_parameter = self.exchange_response(
            self.destination_gateway, self.gateway_client, self.resource_audience,
            extra={"actor_token": self.workforce_token},
        )
        expect(actor_parameter.status == 400, f"caller actor token returned HTTP {actor_parameter.status}")
        return "wrong route, sibling replay, scope escalation and caller actor data fail closed"

    def audit_and_secrecy(self) -> str:
        audit = request(
            self.base_url + "/admin/audit/export",
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        expect(audit.status == 200, f"audit export HTTP {audit.status}")
        actions = [str(item.get("action")) for item in audit.json()]
        expect(actions.count("TOKEN_EXCHANGE_SUCCEEDED") >= 5,
               "successful exchange audit records are incomplete")
        expect("TOKEN_EXCHANGE_DENIED" in actions, "denied exchange audit is absent")
        material = audit.body
        for secret in [*self.secrets.values(), *self.tokens]:
            expect(secret not in material, "audit contains credential material")
        return "successful and denied exchanges are auditable without credential material"

    def admin_get(self, path: str) -> Any:
        response = request(
            self.base_url + path,
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        expect(response.status == 200, f"{path} HTTP {response.status}")
        return response.json()

    def exchange(self, subject: str, client_id: str, audience: str) -> str:
        response = self.exchange_response(subject, client_id, audience)
        expect(response.status == 200,
               f"token exchange to {audience} HTTP {response.status}: {oauth_error(response)}")
        payload = response.json()
        expect(payload.get("issued_token_type") == ACCESS_TOKEN, "wrong issued_token_type")
        token = str(payload["access_token"])
        self.tokens.append(token)
        return token

    def exchange_response(self, subject: str, client_id: str, audience: str, *,
                          scope: str = SCOPE, extra: dict[str, str] | None = None) -> Response:
        form = {
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": subject,
            "subject_token_type": ACCESS_TOKEN,
            "requested_token_type": ACCESS_TOKEN,
            "audience": audience,
            "scope": scope,
        }
        form.update(extra or {})
        return request(
            self.base_url + "/oauth/token", method="POST", form=form,
            basic=(client_id, self.secrets[client_id]),
        )

    def validate(self, token: str, *, audience: str, profile: str | None,
                 token_use: str | None, actor_ref: str | None, client_id: str) -> dict[str, Any]:
        verify_signature(self.base_url, token)
        claims = jwt_claims(token)
        expect(claims.get("iss") == self.issuer, "token issuer mismatch")
        expect(claims.get("tenant_id") == self.tenant, "token tenant mismatch")
        expect(audiences(claims) == {audience}, "token audience is not exact")
        expect(SCOPE in scopes(claims), "required business scope is absent")
        expect(claims.get("client_id") == client_id, "requesting client claim mismatch")
        expect(int(claims.get("exp", 0)) > int(time.time()), "token is expired")
        if profile is None:
            expect("act" not in claims, "initial workforce token contains an actor")
            return claims
        expect(claims.get("authority_profile") == profile, "authority profile mismatch")
        expect(claims.get("token_use") == token_use, "token use mismatch")
        expect(bool(claims.get("authority_id")), "authority id is absent")
        actor = claims.get("act")
        expect(isinstance(actor, dict), "structured actor is absent")
        expect(actor.get("sub") == actor_ref, "actor workload reference mismatch")
        expect(bool(actor.get("client_id")), "actor OAuth client is absent")
        expect(bool(actor.get("workload_id")), "actor workload id is absent")
        expect(int(claims["exp"]) - int(claims["iat"]) <= 300,
               "exchange token lifetime exceeds five minutes")
        return claims


def request(url: str, *, method: str = "GET", json_body: dict[str, Any] | None = None,
            form: dict[str, str] | None = None, headers: dict[str, str] | None = None,
            basic: tuple[str, str] | None = None) -> Response:
    actual_headers = dict(headers or {})
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        actual_headers["Content-Type"] = "application/json"
    elif form is not None:
        body = urllib.parse.urlencode(form).encode()
        actual_headers["Content-Type"] = "application/x-www-form-urlencoded"
    if basic:
        encoded = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        actual_headers["Authorization"] = f"Basic {encoded}"
    req = urllib.request.Request(url, data=body, headers=actual_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return Response(response.status, dict(response.headers.items()), response.read().decode())
    except urllib.error.HTTPError as error:
        return Response(error.code, dict(error.headers.items()), error.read().decode(errors="replace"))


def hidden_input(html: str, name: str) -> str:
    pattern = rf'<input[^>]+name="{re.escape(name)}"[^>]+value="([^"]+)"'
    match = re.search(pattern, html)
    expect(match is not None, f"hidden input {name} is absent")
    return unescape(match.group(1))


def verify_signature(base_url: str, token: str) -> None:
    parts = token.split(".")
    expect(len(parts) == 3, "token is not a compact JWT")
    header = json.loads(b64url_decode(parts[0]))
    expect(header.get("alg") == "RS256", "JWT algorithm is not RS256")
    jwks = request(base_url + "/oauth2/jwks")
    expect(jwks.status == 200, f"JWKS HTTP {jwks.status}")
    key = next((item for item in jwks.json().get("keys", [])
                if item.get("kid") == header.get("kid")), None)
    expect(key is not None, "JWT signing key is absent from JWKS")
    pem = rsa_jwk_to_pem(str(key["n"]), str(key["e"]))
    with tempfile.TemporaryDirectory(prefix="axiom-argus-") as directory:
        public_key = pathlib.Path(directory) / "public.pem"
        signature = pathlib.Path(directory) / "signature.bin"
        message = pathlib.Path(directory) / "message.bin"
        public_key.write_bytes(pem)
        signature.write_bytes(b64url_decode(parts[2]))
        message.write_bytes(f"{parts[0]}.{parts[1]}".encode())
        checked = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(public_key),
             "-signature", str(signature), str(message)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        expect(checked.returncode == 0, "JWT signature verification failed")


def rsa_jwk_to_pem(modulus: str, exponent: str) -> bytes:
    key = der_sequence(
        der_integer(int.from_bytes(b64url_decode(modulus), "big")),
        der_integer(int.from_bytes(b64url_decode(exponent), "big")),
    )
    oid = bytes.fromhex("300d06092a864886f70d0101010500")
    encoded = base64.encodebytes(der_sequence(oid, der_bit_string(key))).replace(b"\n", b"")
    lines = [encoded[index:index + 64] for index in range(0, len(encoded), 64)]
    return b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(lines) + b"\n-----END PUBLIC KEY-----\n"


def der_sequence(*values: bytes) -> bytes:
    content = b"".join(values)
    return b"\x30" + der_length(len(content)) + content


def der_integer(value: int) -> bytes:
    content = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if content[0] & 0x80:
        content = b"\x00" + content
    return b"\x02" + der_length(len(content)) + content


def der_bit_string(value: bytes) -> bytes:
    content = b"\x00" + value
    return b"\x03" + der_length(len(content)) + content


def der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    expect(len(parts) == 3, "token is not a compact JWT")
    value = json.loads(b64url_decode(parts[1]))
    expect(isinstance(value, dict), "JWT claims are invalid")
    return value


def audiences(claims: dict[str, Any]) -> set[str]:
    value = claims.get("aud")
    if isinstance(value, str):
        return {value}
    return {str(item) for item in value} if isinstance(value, list) else set()


def scopes(claims: dict[str, Any]) -> set[str]:
    value = claims.get("scope")
    if isinstance(value, str):
        return {item for item in value.split() if item}
    return {str(item) for item in value} if isinstance(value, list) else set()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def oauth_error(response: Response) -> str:
    try:
        return str(response.json().get("error", "unknown_error"))
    except Exception:
        return "non_json_error"


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def kubernetes_secret_value(namespace: str, name: str, key: str) -> str:
    completed = subprocess.run(
        ["kubectl", "get", "secret", name, "-n", namespace, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(completed.stdout).get("data", {})
    encoded = data.get(key)
    if not encoded:
        raise RuntimeError(f"Kubernetes Secret {namespace}/{name} lacks {key}")
    return base64.b64decode(encoded).decode("utf-8")


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def safe_error(error: Exception) -> str:
    value = str(error).replace("\n", " ").strip()
    return value[:240] if value else error.__class__.__name__


if __name__ == "__main__":
    raise SystemExit(Verifier().run())
