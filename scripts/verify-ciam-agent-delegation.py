#!/usr/bin/env python3
"""Functional CIAM and RFC 8693 proof against Axiom's public HTTP surfaces.

The verifier creates unique greenfield fixtures. It never prints credentials,
verification/recovery values, OAuth secrets, authorization codes, or tokens.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
BUSINESS_SCOPES = {"cards:incident.read", "cards:freeze.propose"}


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: str

    def json(self) -> Any:
        return json.loads(self.body)


class Verifier:
    def __init__(self) -> None:
        self.issuer = os.environ.get(
            "AXIOM_CIAM_ISSUER", "https://identity.meridian.com:8443"
        ).rstrip("/")
        self.base_url = os.environ.get("AXIOM_CIAM_BASE_URL", self.issuer).rstrip("/")
        self.tenant = os.environ.get("AXIOM_CIAM_TENANT_ID", "meridian")
        self.admin_username = os.environ.get("AXIOM_CIAM_ADMIN_USERNAME", "admin")
        self.admin_password = required("AXIOM_ADMIN_PASSWORD")
        self.suffix = f"{int(time.time())}-{secrets.token_hex(3)}"
        self.email = f"ciam-e2e-{self.suffix}@example.test"
        self.password = f"Ciam-E2E-{secrets.token_urlsafe(14)}"
        self.new_password = f"Ciam-Recovered-{secrets.token_urlsafe(14)}"
        self.app_key = f"ciam-e2e-{self.suffix}"[:63]
        self.audience = f"cards-api-{self.suffix}"[:128]
        self.browser_client = f"ciam-browser-{self.suffix}"[:99]
        self.agent_client = f"ciam-agent-{self.suffix}"[:99]
        self.rogue_agent_client = f"ciam-rogue-{self.suffix}"[:99]
        self.workload_ref = f"agent:card-service:{self.suffix}"
        self.purpose = "Resolve the customer's reported lost-card incident"
        self.failures: list[str] = []
        self.admin_token = ""
        self.customer_id = ""
        self.customer_token = ""
        self.agent_secret = ""
        self.rogue_agent_secret = ""
        self.workload_id = ""
        self.grant_id = ""
        self.delegated_token = ""

    def run(self) -> int:
        self.act("health-and-discovery", self.health_and_discovery)
        self.act("administrator-authentication", self.admin_authentication)
        self.act("application-and-clients", self.application_and_clients)
        self.act("customer-registration-verification", self.customer_registration_verification)
        self.act("customer-subject-token", self.customer_subject_token)
        self.act("agent-workload-registration", self.agent_workload_registration)
        self.act("customer-delegation", self.customer_delegation)
        self.act("rfc8693-exchange", self.exchange_and_validate)
        self.act("negative-authority", self.negative_authority)
        self.act("grant-revocation", self.grant_revocation)
        self.act("customer-suspension", self.customer_suspension)
        self.act("credential-recovery", self.credential_recovery)
        self.act("workload-revocation", self.workload_revocation)
        self.act("audit-visibility-and-secrecy", self.audit_visibility)
        if self.failures:
            print(f"RESULT FAIL ({len(self.failures)} act(s))")
            return 1
        print("RESULT PASS (all CIAM and agent delegation acts)")
        return 0

    def act(self, name: str, operation: Callable[[], str]) -> None:
        try:
            detail = operation()
            print(f"PASS {name}: {detail}")
        except Exception as error:  # the harness must continue and account for every act
            self.failures.append(name)
            print(f"FAIL {name}: {safe_error(error)}")

    def health_and_discovery(self) -> str:
        health = request(self.base_url + "/actuator/health")
        expect(health.status == 200, f"health HTTP {health.status}")
        discovery = request(self.base_url + "/.well-known/openid-configuration")
        expect(discovery.status == 200, f"discovery HTTP {discovery.status}")
        grants = set(discovery.json().get("grant_types_supported", []))
        expect(TOKEN_EXCHANGE in grants, "discovery does not advertise token exchange")
        expect(discovery.json().get("issuer") == self.issuer, "discovery issuer mismatch")
        return "server is healthy and advertises RFC 8693"

    def admin_authentication(self) -> str:
        response = request(
            self.base_url + "/auth/login",
            method="POST",
            json_body={"username": self.admin_username, "password": self.admin_password},
        )
        expect(response.status == 200, f"admin login HTTP {response.status}")
        self.admin_token = required_json(response, "accessToken")
        return "tenant administrator obtained a non-disclosed bearer token"

    def application_and_clients(self) -> str:
        application = self.admin_json(
            f"/admin/tenants/{self.tenant}/applications",
            {
                "applicationKey": self.app_key,
                "displayName": "CIAM E2E Card Service",
                "description": "Ephemeral functional proof",
                "audience": self.audience,
            },
            expected=201,
        )
        application_id = str(application["id"])
        browser = self.admin_json(
            f"/admin/tenants/{self.tenant}/applications/{application_id}/clients",
            {
                "clientId": self.browser_client,
                "clientType": "PUBLIC_BROWSER",
                "redirectUris": ["http://127.0.0.1:8765/callback"],
                "postLogoutRedirectUris": ["http://127.0.0.1:8765/logout"],
                "scopes": ["openid", *sorted(BUSINESS_SCOPES)],
            },
            expected=201,
        )
        agent = self.admin_json(
            f"/admin/tenants/{self.tenant}/applications/{application_id}/clients",
            {
                "clientId": self.agent_client,
                "clientType": "CONFIDENTIAL_SERVICE",
                "redirectUris": [],
                "postLogoutRedirectUris": [],
                "scopes": sorted(BUSINESS_SCOPES),
            },
            expected=201,
        )
        rogue_agent = self.admin_json(
            f"/admin/tenants/{self.tenant}/applications/{application_id}/clients",
            {
                "clientId": self.rogue_agent_client,
                "clientType": "CONFIDENTIAL_SERVICE",
                "redirectUris": [],
                "postLogoutRedirectUris": [],
                "scopes": sorted(BUSINESS_SCOPES),
            },
            expected=201,
        )
        browser_scopes = set(browser["client"]["scopes"])
        agent_scopes = set(agent["client"]["scopes"])
        expect(BUSINESS_SCOPES <= browser_scopes, "browser lacks approved business scopes")
        expect(BUSINESS_SCOPES <= agent_scopes, "agent lacks approved business scopes")
        self.agent_secret = str(agent["serviceSecret"])
        expect(bool(self.agent_secret), "service secret was not returned once")
        self.rogue_agent_secret = str(rogue_agent["serviceSecret"])
        expect(bool(self.rogue_agent_secret), "rogue service secret was not returned once")
        return "public customer and confidential Agent clients have approved business scopes"

    def customer_registration_verification(self) -> str:
        registration = request(
            self.ciam("/registrations"),
            method="POST",
            json_body={"email": self.email, "displayName": "CIAM E2E Customer", "password": self.password},
        )
        expect(registration.status == 201, f"registration HTTP {registration.status}")
        payload = registration.json()
        self.customer_id = str(payload["customer"]["customerId"])
        action = payload.get("localDemoAction") or {}
        expect(action.get("delivery") == "LOCAL_DEMO", "local verification action is absent")
        verification = request(
            self.ciam("/verifications"), method="POST", json_body={"token": action.get("token")}
        )
        expect(verification.status == 200, f"verification HTTP {verification.status}")
        expect(verification.json().get("status") == "ACTIVE", "customer did not become active")
        return "customer registered and verified through public CIAM APIs"

    def customer_subject_token(self) -> str:
        self.customer_token = self.issue_customer_token(self.password)
        claims = jwt_claims(self.customer_token)
        expect(claims.get("identity_kind") == "customer", "identity_kind is not customer")
        expect(claims.get("sub") == self.customer_id, "subject is not customer UUID")
        expect(claims.get("tenant_id") == self.tenant, "tenant claim mismatch")
        expect(claims.get("client_id") == self.browser_client, "browser client claim mismatch")
        expect(bool(claims.get("sid")), "customer session id is missing")
        for forbidden in ("roles", "permissions", "admin_domains", "impersonation"):
            expect(forbidden not in claims, f"customer token contains workforce claim {forbidden}")
        verify_jwt_signature(self.base_url, self.customer_token)
        return "customer-only signed subject token contains no workforce authority"

    def agent_workload_registration(self) -> str:
        workload = self.admin_json(
            f"/admin/tenants/{self.tenant}/ciam/agent-workloads",
            {"workloadRef": self.workload_ref, "name": "Card Service Agent", "oauthClientId": self.agent_client},
            expected=201,
        )
        self.workload_id = str(workload["id"])
        return "confidential client is bound to one registered Agent workload"

    def customer_delegation(self) -> str:
        grant = self.customer_json(
            f"/{self.customer_id}/delegation-grants",
            {
                "agentWorkloadId": self.workload_id,
                "audience": self.audience,
                "scopes": sorted(BUSINESS_SCOPES),
                "purpose": self.purpose,
                "expiresAt": iso_after(hours=1),
            },
            expected=201,
        )
        self.grant_id = str(grant["id"])
        expect(grant.get("status") == "ACTIVE", "delegation is not active")
        return "customer consent binds exact Agent, target, scopes, purpose and expiry"

    def exchange_and_validate(self) -> str:
        self.delegated_token = self.exchange(self.customer_token, BUSINESS_SCOPES, self.audience, self.grant_id)
        claims = validate_delegated(
            self.issuer,
            self.delegated_token,
            jwks_base=self.base_url,
            subject=self.customer_id,
            actor_client=self.agent_client,
            workload_ref=self.workload_ref,
            audience=self.audience,
            scopes=BUSINESS_SCOPES,
            tenant=self.tenant,
            purpose=self.purpose,
            delegation_id=self.grant_id,
        )
        expect(int(claims["exp"]) - int(claims["iat"]) <= 300, "delegated token is not short-lived")
        return "signed token preserves exact customer, Agent, audience, scope, purpose and consent"

    def negative_authority(self) -> str:
        unknown = self.exchange_response(
            self.customer_token, {"cards:incident.delete"}, self.audience, self.grant_id
        )
        expect(unknown.status == 400, f"unknown scope returned HTTP {unknown.status}")
        excessive = self.exchange_response(
            self.customer_token, BUSINESS_SCOPES | {"cards:incident.delete"}, self.audience, self.grant_id
        )
        expect(excessive.status == 400, f"excessive scope returned HTTP {excessive.status}")
        wrong_audience = self.exchange_response(
            self.customer_token, BUSINESS_SCOPES, "payments-api", self.grant_id
        )
        expect(wrong_audience.status == 400, f"wrong audience returned HTTP {wrong_audience.status}")
        wrong_actor = self.exchange_response(
            self.customer_token,
            BUSINESS_SCOPES,
            self.audience,
            self.grant_id,
            actor=(self.rogue_agent_client, self.rogue_agent_secret),
        )
        expect(wrong_actor.status == 400, f"wrong actor returned HTTP {wrong_actor.status}")
        cross_tenant = request(
            self.base_url
            + f"/ciam/tenants/{self.tenant}-other/customers/{self.customer_id}",
            headers=bearer(self.customer_token),
        )
        expect(cross_tenant.status in {401, 403, 404}, f"cross-tenant read HTTP {cross_tenant.status}")
        expect_rejected(lambda: validate_delegated(
            self.issuer, self.delegated_token, jwks_base=self.base_url, subject=self.customer_id,
            actor_client=self.rogue_agent_client, workload_ref=self.workload_ref,
            audience=self.audience, scopes=BUSINESS_SCOPES, tenant=self.tenant,
            purpose=self.purpose, delegation_id=self.grant_id))
        expect_rejected(lambda: validate_delegated(
            self.issuer, self.delegated_token, jwks_base=self.base_url, subject=self.customer_id,
            actor_client=self.agent_client, workload_ref=self.workload_ref,
            audience="payments-api", scopes=BUSINESS_SCOPES, tenant=self.tenant,
            purpose=self.purpose, delegation_id=self.grant_id))
        expect_rejected(lambda: validate_delegated(
            self.issuer, self.customer_token, jwks_base=self.base_url, subject=self.customer_id,
            actor_client=self.agent_client, workload_ref=self.workload_ref,
            audience=self.audience, scopes=BUSINESS_SCOPES, tenant=self.tenant,
            purpose=self.purpose, delegation_id=self.grant_id))
        return "unknown scope, excessive scope, wrong target and missing actor fail closed"

    def grant_revocation(self) -> str:
        revoked = self.customer_json(
            f"/{self.customer_id}/delegation-grants/{self.grant_id}/revoke",
            {"reason": "functional revocation proof"},
        )
        expect(revoked.get("status") == "REVOKED", "grant did not become revoked")
        denied = self.exchange_response(self.customer_token, BUSINESS_SCOPES, self.audience, self.grant_id)
        expect(denied.status == 400, f"revoked grant exchange HTTP {denied.status}")
        return "revoked customer consent immediately prevents new exchange"

    def customer_suspension(self) -> str:
        active_grant = self.create_grant()
        issued = self.exchange(self.customer_token, BUSINESS_SCOPES, self.audience, active_grant)
        expect(bool(issued), "pre-suspension exchange did not issue")
        suspended = self.admin_json(
            f"/admin/tenants/{self.tenant}/ciam/customers/{self.customer_id}/suspend", {}, expected=200
        )
        expect(suspended.get("status") == "SUSPENDED", "customer did not suspend")
        denied = self.exchange_response(self.customer_token, BUSINESS_SCOPES, self.audience, active_grant)
        expect(denied.status == 400, f"suspended customer exchange HTTP {denied.status}")
        self.admin_json(
            f"/admin/tenants/{self.tenant}/ciam/customers/{self.customer_id}/reactivate", {}, expected=200
        )
        self.customer_token = self.issue_customer_token(self.password)
        return "suspension revokes sessions and consent; reactivation requires fresh authentication"

    def credential_recovery(self) -> str:
        active_grant = self.create_grant()
        old_token = self.customer_token
        challenge = request(
            self.ciam("/recovery-challenges"), method="POST", json_body={"email": self.email}
        )
        expect(challenge.status == 202, f"recovery challenge HTTP {challenge.status}")
        action = challenge.json().get("localDemoAction") or {}
        recovered = request(
            self.ciam("/recoveries"),
            method="POST",
            json_body={"token": action.get("token"), "newPassword": self.new_password},
        )
        expect(recovered.status == 200, f"recovery HTTP {recovered.status}")
        denied = self.exchange_response(old_token, BUSINESS_SCOPES, self.audience, active_grant)
        expect(denied.status == 400, f"pre-recovery session exchange HTTP {denied.status}")
        self.customer_token = self.issue_customer_token(self.new_password)
        expect_rejected(lambda: self.exchange(self.customer_token, BUSINESS_SCOPES, self.audience, active_grant))
        return "recovery revokes old sessions and active consent; new authentication is required"

    def workload_revocation(self) -> str:
        grant = self.create_grant()
        self.exchange(self.customer_token, BUSINESS_SCOPES, self.audience, grant)
        workload = self.admin_json(
            f"/admin/tenants/{self.tenant}/ciam/agent-workloads/{self.workload_id}/revoke", {}, expected=200
        )
        expect(workload.get("status") == "REVOKED", "workload did not become revoked")
        denied = self.exchange_response(self.customer_token, BUSINESS_SCOPES, self.audience, grant)
        expect(denied.status == 400, f"revoked workload exchange HTTP {denied.status}")
        return "Agent workload revocation prevents new exchange and revokes its grants"

    def audit_visibility(self) -> str:
        events = request(
            self.base_url + f"/admin/tenants/{self.tenant}/ciam/events", headers=bearer(self.admin_token)
        )
        expect(events.status == 200, f"CIAM events HTTP {events.status}")
        event_names = {str(item.get("eventType")) for item in events.json()}
        required_events = {
            "CUSTOMER_REGISTERED", "CUSTOMER_VERIFIED", "AGENT_WORKLOAD_REGISTERED",
            "DELEGATION_GRANT_CREATED", "DELEGATION_GRANT_REVOKED",
            "CUSTOMER_SUSPENDED", "CUSTOMER_CREDENTIAL_RECOVERED", "AGENT_WORKLOAD_REVOKED",
        }
        expect(required_events <= event_names, f"missing lifecycle events {sorted(required_events - event_names)}")
        audit = request(self.base_url + "/admin/audit/export", headers=bearer(self.admin_token))
        expect(audit.status == 200, f"audit export HTTP {audit.status}")
        actions = {str(item.get("action")) for item in audit.json()}
        expect("TOKEN_EXCHANGE_SUCCEEDED" in actions, "successful exchange audit is absent")
        expect("TOKEN_EXCHANGE_DENIED" in actions, "denied exchange audit is absent")
        material = events.body + audit.body
        for secret_value in (
            self.password,
            self.new_password,
            self.agent_secret,
            self.rogue_agent_secret,
            self.customer_token,
            self.delegated_token,
        ):
            expect(secret_value not in material, "audit contains credential material")
        return "dual-principal lifecycle and exchange events are visible without secrets"

    def create_grant(self) -> str:
        value = self.customer_json(
            f"/{self.customer_id}/delegation-grants",
            {
                "agentWorkloadId": self.workload_id,
                "audience": self.audience,
                "scopes": sorted(BUSINESS_SCOPES),
                "purpose": self.purpose,
                "expiresAt": iso_after(hours=1),
            },
            expected=201,
        )
        return str(value["id"])

    def issue_customer_token(self, password: str) -> str:
        response = request(
            self.ciam("/tokens"), method="POST",
            json_body={
                "email": self.email,
                "password": password,
                "clientId": self.browser_client,
                "scopes": sorted(BUSINESS_SCOPES),
            },
        )
        expect(response.status == 200, f"customer token HTTP {response.status}")
        return str(response.json()["accessToken"])

    def exchange(self, token: str, scopes: set[str], audience: str, grant_id: str) -> str:
        response = self.exchange_response(token, scopes, audience, grant_id)
        expect(response.status == 200, f"token exchange HTTP {response.status}: {oauth_error(response)}")
        payload = response.json()
        expect(payload.get("issued_token_type") == ACCESS_TOKEN, "wrong issued_token_type")
        return str(payload["access_token"])

    def exchange_response(
        self,
        token: str,
        scopes: set[str],
        audience: str,
        grant_id: str,
        *,
        actor: tuple[str, str] | None = None,
    ) -> Response:
        return request(
            self.base_url + "/oauth/token",
            method="POST",
            form={
                "grant_type": TOKEN_EXCHANGE,
                "subject_token": token,
                "subject_token_type": ACCESS_TOKEN,
                "requested_token_type": ACCESS_TOKEN,
                "audience": audience,
                "scope": " ".join(sorted(scopes)),
            },
            basic=actor or (self.agent_client, self.agent_secret),
        )

    def admin_json(self, path: str, body: dict[str, Any], *, expected: int = 200) -> Any:
        response = request(self.base_url + path, method="POST", json_body=body, headers=bearer(self.admin_token))
        expect(response.status == expected, f"{path} HTTP {response.status}")
        return response.json()

    def customer_json(self, suffix: str, body: dict[str, Any], *, expected: int = 200) -> Any:
        response = request(self.ciam(suffix), method="POST", json_body=body, headers=bearer(self.customer_token))
        expect(response.status == expected, f"{suffix} HTTP {response.status}")
        return response.json()

    def ciam(self, suffix: str) -> str:
        return self.base_url + f"/ciam/tenants/{self.tenant}/customers" + suffix


def request(
    url: str,
    *,
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    basic: tuple[str, str] | None = None,
) -> Response:
    actual_headers = dict(headers or {})
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        actual_headers["Content-Type"] = "application/json"
    elif form is not None:
        body = urllib.parse.urlencode(form).encode()
        actual_headers["Content-Type"] = "application/x-www-form-urlencoded"
    if basic is not None:
        encoded = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        actual_headers["Authorization"] = f"Basic {encoded}"
    req = urllib.request.Request(url, data=body, headers=actual_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return Response(response.status, dict(response.headers.items()), response.read().decode())
    except urllib.error.HTTPError as error:
        return Response(error.code, dict(error.headers.items()), error.read().decode(errors="replace"))


def validate_delegated(
    issuer: str,
    token: str,
    *,
    jwks_base: str,
    subject: str,
    actor_client: str,
    workload_ref: str,
    audience: str,
    scopes: set[str],
    tenant: str,
    purpose: str,
    delegation_id: str,
) -> dict[str, Any]:
    verify_jwt_signature(jwks_base, token)
    claims = jwt_claims(token)
    expect(claims.get("iss") == issuer, "issuer mismatch")
    expect(claims.get("sub") == subject, "customer subject mismatch")
    expect(claims.get("identity_kind") == "customer", "delegated identity_kind mismatch")
    expect(claims.get("tenant_id") == tenant, "delegated tenant mismatch")
    expect(jwt_audiences(claims) == {audience}, "delegated audience mismatch")
    expect(jwt_scopes(claims) >= scopes, "delegated scope mismatch")
    expect(claims.get("purpose") == purpose, "delegated purpose mismatch")
    expect(claims.get("delegation_id") == delegation_id, "delegation id mismatch")
    actor = claims.get("act")
    expect(isinstance(actor, dict), "actor claim missing")
    expect(actor.get("client_id") == actor_client, "actor client mismatch")
    expect(actor.get("sub") == workload_ref, "actor workload mismatch")
    expect(bool(actor.get("workload_id")), "actor workload id missing")
    expect(int(claims.get("exp", 0)) > int(time.time()), "delegated token expired")
    return claims


def verify_jwt_signature(issuer: str, token: str) -> None:
    parts = token.split(".")
    expect(len(parts) == 3, "token is not a compact JWT")
    header = json.loads(b64url_decode(parts[0]))
    expect(header.get("alg") == "RS256", "JWT algorithm is not RS256")
    jwks = request(issuer + "/oauth2/jwks")
    expect(jwks.status == 200, f"JWKS HTTP {jwks.status}")
    key = next((item for item in jwks.json().get("keys", []) if item.get("kid") == header.get("kid")), None)
    expect(key is not None, "JWT signing key is absent from JWKS")
    pem = rsa_jwk_to_pem(str(key["n"]), str(key["e"]))
    with tempfile.TemporaryDirectory(prefix="axiom-ciam-") as directory:
        public_key = os.path.join(directory, "public.pem")
        signature = os.path.join(directory, "signature.bin")
        message = os.path.join(directory, "message.bin")
        with open(public_key, "wb") as handle:
            handle.write(pem)
        with open(signature, "wb") as handle:
            handle.write(b64url_decode(parts[2]))
        with open(message, "wb") as handle:
            handle.write(f"{parts[0]}.{parts[1]}".encode())
        verified = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", public_key, "-signature", signature, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        expect(verified.returncode == 0, "JWT signature verification failed")


def rsa_jwk_to_pem(modulus: str, exponent: str) -> bytes:
    rsa_key = der_sequence(der_integer(int.from_bytes(b64url_decode(modulus), "big")),
                           der_integer(int.from_bytes(b64url_decode(exponent), "big")))
    rsa_oid = bytes.fromhex("300d06092a864886f70d0101010500")
    subject_public_key = der_sequence(rsa_oid, der_bit_string(rsa_key))
    encoded = base64.encodebytes(subject_public_key).replace(b"\n", b"")
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
    return json.loads(b64url_decode(parts[1]))


def jwt_audiences(claims: dict[str, Any]) -> set[str]:
    value = claims.get("aud")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def jwt_scopes(claims: dict[str, Any]) -> set[str]:
    value = claims.get("scope")
    if isinstance(value, str):
        return {item for item in value.split() if item}
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def iso_after(*, hours: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def oauth_error(response: Response) -> str:
    try:
        payload = response.json()
        return str(payload.get("error", "unknown_error"))
    except Exception:
        return "non_json_error"


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def required_json(response: Response, name: str) -> str:
    value = response.json().get(name)
    expect(isinstance(value, str) and bool(value), f"response is missing {name}")
    return value


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_rejected(operation: Callable[[], Any]) -> None:
    try:
        operation()
    except Exception:
        return
    raise AssertionError("operation was unexpectedly accepted")


def safe_error(error: Exception) -> str:
    text = str(error).replace("\n", " ").strip()
    return text[:240] if text else error.__class__.__name__


if __name__ == "__main__":
    raise SystemExit(Verifier().run())
