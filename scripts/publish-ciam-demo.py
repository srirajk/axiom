#!/usr/bin/env python3
"""Publish and reconcile the greenfield Axiom CIAM demonstration estate.

All mutations use public HTTP APIs. The generated confidential-client secret is
written once to a gitignored mode-0600 file and is never printed.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


APP_KEY = "ciam-card-assistance-demo"
APP_NAME = "CIAM Card Assistance Demo"
APP_DESCRIPTION = "Greenfield customer-to-Agent delegation demonstration"
AUDIENCE = "cards-api"
BUSINESS_SCOPE = "cards:incident.read"
BROWSER_CLIENT_ID = "ciam-card-customer-spa"
AGENT_CLIENT_ID = "ciam-card-agent"
CUSTOMER_EMAIL = "card.customer.demo@meridian.example"
CUSTOMER_NAME = "Card Customer Demo"
WORKLOAD_REF = "agent:card-assistance:development"
WORKLOAD_NAME = "Card Assistance Agent"
PURPOSE = "Review the customer's reported lost-card incident"
GRANT_LIFETIME_DAYS = 30


@dataclass(frozen=True)
class Response:
    status: int
    body: str

    def json(self) -> Any:
        return json.loads(self.body)


class Publisher:
    def __init__(self) -> None:
        self.issuer = os.environ.get("AXIOM_CIAM_ISSUER", "http://localhost:8180").rstrip("/")
        self.tenant = os.environ.get("AXIOM_CIAM_TENANT_ID", "meridian")
        self.admin_username = os.environ.get("AXIOM_CIAM_ADMIN_USERNAME", "admin")
        self.admin_password = required("AXIOM_ADMIN_PASSWORD")
        self.customer_password = required("AXIOM_CIAM_DEMO_CUSTOMER_PASSWORD")
        default_secret = pathlib.Path(__file__).resolve().parents[1] / ".local/ciam-demo/agent-client.json"
        self.secret_path = pathlib.Path(
            os.environ.get("AXIOM_CIAM_DEMO_SECRET_FILE", str(default_secret))
        ).expanduser().resolve()
        require_safe_secret_path(self.secret_path)
        self.admin_token = ""
        self.customer_token = ""

    def run(self) -> int:
        self.require_healthy()
        self.admin_token = self.admin_login()
        first = self.reconcile()
        audit_before = self.audit_counts()
        second = self.reconcile()
        audit_after = self.audit_counts()
        expect(first == second, "replay changed the stable demo inventory")
        expect(audit_before == audit_after, "replay created audit or lifecycle events")
        self.prove_exchange(second)
        self.print_inventory(second, audit_after)
        print("RESULT PASS (CIAM demo publisher replay produced no duplicates or mutations)")
        return 0

    def require_healthy(self) -> None:
        response = request(self.issuer + "/actuator/health")
        expect(response.status == 200, f"Axiom health HTTP {response.status}")

    def admin_login(self) -> str:
        response = request(
            self.issuer + "/auth/login",
            method="POST",
            json_body={"username": self.admin_username, "password": self.admin_password},
        )
        expect(response.status == 200, f"administrator login HTTP {response.status}")
        return required_field(response.json(), "accessToken")

    def reconcile(self) -> dict[str, Any]:
        application = self.application()
        browser = self.client(application, BROWSER_CLIENT_ID, "PUBLIC_BROWSER")
        agent, client_secret = self.agent_client(application)
        customer = self.customer()
        if not self.customer_token:
            self.customer_token = self.customer_login()
        workload = self.workload(client_secret)
        grant = self.grant(workload)
        self.verify_exact_inventory(application, customer, workload, grant)
        return self.inventory(application, browser, agent, customer, workload, grant)

    def application(self) -> dict[str, Any]:
        applications = self.admin_get(f"/admin/tenants/{self.tenant}/applications")
        matches = [item for item in applications if item.get("applicationKey") == APP_KEY]
        expect(len(matches) <= 1, "duplicate demo tenant applications")
        if not matches:
            created = self.admin_post(
                f"/admin/tenants/{self.tenant}/applications",
                {
                    "applicationKey": APP_KEY,
                    "displayName": APP_NAME,
                    "description": APP_DESCRIPTION,
                    "audience": AUDIENCE,
                },
                expected=201,
            )
            return created
        value = matches[0]
        expect(value.get("displayName") == APP_NAME, "demo application name conflicts")
        expect(value.get("audience") == AUDIENCE, "demo application audience conflicts")
        expect(value.get("status") == "ACTIVE", "demo application is not active")
        return value

    def client(self, application: dict[str, Any], client_id: str, client_type: str) -> dict[str, Any]:
        application_id = required_field(application, "id")
        clients = self.admin_get(
            f"/admin/tenants/{self.tenant}/applications/{application_id}/clients"
        )
        matches = [item for item in clients if item.get("clientId") == client_id]
        expect(len(matches) <= 1, f"duplicate demo client {client_id}")
        expected_scopes = {"openid", BUSINESS_SCOPE} if client_type == "PUBLIC_BROWSER" else {BUSINESS_SCOPE}
        if not matches:
            response = self.admin_post(
                f"/admin/tenants/{self.tenant}/applications/{application_id}/clients",
                {
                    "clientId": client_id,
                    "clientType": client_type,
                    "redirectUris": ["http://localhost:5190/callback"] if client_type == "PUBLIC_BROWSER" else [],
                    "postLogoutRedirectUris": ["http://localhost:5190/login"] if client_type == "PUBLIC_BROWSER" else [],
                    "scopes": sorted(expected_scopes),
                },
                expected=201,
            )
            return response["client"]
        value = matches[0]
        expect(value.get("clientType") == client_type, f"demo client {client_id} type conflicts")
        expect(value.get("status") == "ACTIVE", f"demo client {client_id} is not active")
        expect(set(value.get("scopes", [])) == expected_scopes, f"demo client {client_id} scopes conflict")
        return value

    def agent_client(self, application: dict[str, Any]) -> tuple[dict[str, Any], str]:
        application_id = required_field(application, "id")
        clients = self.admin_get(
            f"/admin/tenants/{self.tenant}/applications/{application_id}/clients"
        )
        matches = [item for item in clients if item.get("clientId") == AGENT_CLIENT_ID]
        expect(len(matches) <= 1, "duplicate demo Agent clients")
        if not matches:
            response = self.admin_post(
                f"/admin/tenants/{self.tenant}/applications/{application_id}/clients",
                {
                    "clientId": AGENT_CLIENT_ID,
                    "clientType": "CONFIDENTIAL_SERVICE",
                    "redirectUris": [],
                    "postLogoutRedirectUris": [],
                    "scopes": [BUSINESS_SCOPE],
                },
                expected=201,
            )
            secret = required_field(response, "serviceSecret")
            write_secret_file(self.secret_path, application_id, response["client"], secret)
            value = response["client"]
        else:
            value = matches[0]
        expect(value.get("clientType") == "CONFIDENTIAL_SERVICE", "demo Agent client type conflicts")
        expect(value.get("status") == "ACTIVE", "demo Agent client is not active")
        expect(set(value.get("scopes", [])) == {BUSINESS_SCOPE}, "demo Agent client scopes conflict")
        state = read_secret_file(self.secret_path)
        expect(state.get("application_id") == application_id, "local secret belongs to another application")
        expect(state.get("client_id") == AGENT_CLIENT_ID, "local secret belongs to another client")
        return value, required_field(state, "client_secret")

    def customer(self) -> dict[str, Any]:
        customers = self.admin_get(f"/admin/tenants/{self.tenant}/ciam/customers")
        matches = [item for item in customers if str(item.get("email", "")).lower() == CUSTOMER_EMAIL]
        expect(len(matches) <= 1, "duplicate demo customers")
        if matches:
            customer = matches[0]
            expect(customer.get("status") == "ACTIVE", "demo customer is not active")
            return customer
        registration = request(
            self.ciam("/registrations"),
            method="POST",
            json_body={
                "email": CUSTOMER_EMAIL,
                "displayName": CUSTOMER_NAME,
                "password": self.customer_password,
            },
        )
        expect(registration.status == 201, f"customer registration HTTP {registration.status}")
        payload = registration.json()
        action = payload.get("localDemoAction") or {}
        expect(action.get("delivery") == "LOCAL_DEMO", "local verification token disclosure is disabled")
        verification = request(
            self.ciam("/verifications"),
            method="POST",
            json_body={"token": required_field(action, "token")},
        )
        expect(verification.status == 200, f"customer verification HTTP {verification.status}")
        customer = verification.json()
        expect(customer.get("status") == "ACTIVE", "demo customer did not become active")
        return customer

    def customer_login(self) -> str:
        response = request(
            self.ciam("/tokens"),
            method="POST",
            json_body={
                "email": CUSTOMER_EMAIL,
                "password": self.customer_password,
                "clientId": BROWSER_CLIENT_ID,
                "scopes": [BUSINESS_SCOPE],
            },
        )
        expect(response.status == 200, f"demo customer authentication HTTP {response.status}")
        return required_field(response.json(), "accessToken")

    def workload(self, client_secret: str) -> dict[str, Any]:
        expect(bool(client_secret), "local Agent credential is missing")
        workloads = self.admin_get(f"/admin/tenants/{self.tenant}/ciam/agent-workloads")
        matches = [item for item in workloads if item.get("workloadRef") == WORKLOAD_REF]
        expect(len(matches) <= 1, "duplicate demo Agent workloads")
        if not matches:
            return self.admin_post(
                f"/admin/tenants/{self.tenant}/ciam/agent-workloads",
                {"workloadRef": WORKLOAD_REF, "name": WORKLOAD_NAME, "oauthClientId": AGENT_CLIENT_ID},
                expected=201,
            )
        value = matches[0]
        expect(value.get("name") == WORKLOAD_NAME, "demo Agent workload name conflicts")
        expect(value.get("oauthClientId") == AGENT_CLIENT_ID, "demo Agent workload client conflicts")
        expect(value.get("status") == "ACTIVE", "demo Agent workload is not active")
        return value

    def grant(self, workload: dict[str, Any]) -> dict[str, Any]:
        customer_id = self.customer_id()
        grants = self.customer_get(f"/{customer_id}/delegation-grants")
        candidates = [
            item
            for item in grants
            if item.get("status") == "ACTIVE"
            and item.get("agentWorkloadId") == workload.get("id")
            and item.get("audience") == AUDIENCE
            and set(item.get("scopes", [])) >= {BUSINESS_SCOPE}
        ]
        expect(len(candidates) <= 1, "multiple active grants would make token exchange ambiguous")
        if candidates:
            value = candidates[0]
            expect(value.get("purpose") == PURPOSE, "demo delegation purpose conflicts")
            return value
        return self.customer_post(
            f"/{customer_id}/delegation-grants",
            {
                "agentWorkloadId": required_field(workload, "id"),
                "audience": AUDIENCE,
                "scopes": [BUSINESS_SCOPE],
                "purpose": PURPOSE,
                "expiresAt": iso_after(days=GRANT_LIFETIME_DAYS),
            },
            expected=201,
        )

    def customer_id(self) -> str:
        customers = self.admin_get(f"/admin/tenants/{self.tenant}/ciam/customers")
        match = [item for item in customers if str(item.get("email", "")).lower() == CUSTOMER_EMAIL]
        expect(len(match) == 1, "demo customer inventory is not exact")
        return required_field(match[0], "customerId")

    def verify_exact_inventory(
        self,
        application: dict[str, Any],
        customer: dict[str, Any],
        workload: dict[str, Any],
        grant: dict[str, Any],
    ) -> None:
        applications = self.admin_get(f"/admin/tenants/{self.tenant}/applications")
        expect(sum(item.get("applicationKey") == APP_KEY for item in applications) == 1,
               "expected exactly one demo application")
        application_id = required_field(application, "id")
        clients = self.admin_get(
            f"/admin/tenants/{self.tenant}/applications/{application_id}/clients"
        )
        expect(
            {item.get("clientId") for item in clients} == {BROWSER_CLIENT_ID, AGENT_CLIENT_ID},
            "demo application must contain exactly the two canonical clients",
        )
        customers = self.admin_get(f"/admin/tenants/{self.tenant}/ciam/customers")
        expect(sum(str(item.get("email", "")).lower() == CUSTOMER_EMAIL for item in customers) == 1,
               "expected exactly one demo customer")
        workloads = self.admin_get(f"/admin/tenants/{self.tenant}/ciam/agent-workloads")
        expect(sum(item.get("workloadRef") == WORKLOAD_REF for item in workloads) == 1,
               "expected exactly one demo Agent workload")
        customer_id = required_field(customer, "customerId")
        grants = self.customer_get(f"/{customer_id}/delegation-grants")
        active = [item for item in grants if item.get("status") == "ACTIVE"]
        expect(len(active) == 1, "demo customer must have exactly one active delegation")
        expect(active[0].get("id") == grant.get("id"), "active delegation differs from canonical grant")
        expect(grant.get("agentWorkloadId") == workload.get("id"), "delegation workload differs")

    def inventory(
        self,
        application: dict[str, Any],
        browser: dict[str, Any],
        agent: dict[str, Any],
        customer: dict[str, Any],
        workload: dict[str, Any],
        grant: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "application": {"key": APP_KEY, "id": required_field(application, "id")},
            "clients": [
                {"client_id": BROWSER_CLIENT_ID, "id": required_field(browser, "id")},
                {"client_id": AGENT_CLIENT_ID, "id": required_field(agent, "id")},
            ],
            "customer": {"email": CUSTOMER_EMAIL, "id": required_field(customer, "customerId")},
            "workload": {"ref": WORKLOAD_REF, "id": required_field(workload, "id")},
            "grant": {"id": required_field(grant, "id"), "scope": BUSINESS_SCOPE, "audience": AUDIENCE},
        }

    def audit_counts(self) -> tuple[int, int]:
        audit = self.admin_get("/admin/audit/export")
        events = self.admin_get(f"/admin/tenants/{self.tenant}/ciam/events")
        return len(audit), len(events)

    def prove_exchange(self, inventory: dict[str, Any]) -> None:
        state = read_secret_file(self.secret_path)
        response = request(
            self.issuer + "/oauth/token",
            method="POST",
            form={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": self.customer_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": AUDIENCE,
                "scope": BUSINESS_SCOPE,
            },
            basic=(AGENT_CLIENT_ID, required_field(state, "client_secret")),
        )
        expect(response.status == 200, f"seeded delegation exchange HTTP {response.status}")
        token = required_field(response.json(), "access_token")
        claims = jwt_claims(token)
        expect(claims.get("sub") == inventory["customer"]["id"], "seeded exchange customer differs")
        expect(jwt_audiences(claims) == {AUDIENCE}, "seeded exchange audience differs")
        expect(jwt_scopes(claims) == {BUSINESS_SCOPE},
               "seeded exchange scope differs")
        expect(claims.get("delegation_id") == inventory["grant"]["id"],
               "seeded exchange delegation differs")
        actor = claims.get("act")
        expect(isinstance(actor, dict), "seeded exchange actor is missing")
        expect(actor.get("client_id") == AGENT_CLIENT_ID, "seeded exchange actor client differs")
        expect(actor.get("sub") == WORKLOAD_REF, "seeded exchange actor workload differs")

    def print_inventory(self, inventory: dict[str, Any], counts: tuple[int, int]) -> None:
        safe = dict(inventory)
        safe["expected_counts"] = {
            "applications_with_key": 1,
            "application_clients": 2,
            "customers_with_email": 1,
            "agent_workloads_with_ref": 1,
            "active_matching_delegations": 1,
        }
        safe["audit_record_count"] = counts[0]
        safe["ciam_event_count"] = counts[1]
        safe["local_secret_file"] = str(self.secret_path)
        print(json.dumps(safe, indent=2, sort_keys=True))

    def admin_get(self, path: str) -> Any:
        response = request(self.issuer + path, headers=bearer(self.admin_token))
        expect(response.status == 200, f"GET {path} HTTP {response.status}")
        return response.json()

    def admin_post(self, path: str, body: dict[str, Any], *, expected: int) -> Any:
        response = request(
            self.issuer + path,
            method="POST",
            json_body=body,
            headers=bearer(self.admin_token),
        )
        expect(response.status == expected, f"POST {path} HTTP {response.status}: {safe_error(response)}")
        return response.json()

    def customer_get(self, suffix: str) -> Any:
        response = request(self.ciam(suffix), headers=bearer(self.customer_token))
        expect(response.status == 200, f"GET {suffix} HTTP {response.status}")
        return response.json()

    def customer_post(self, suffix: str, body: dict[str, Any], *, expected: int) -> Any:
        response = request(
            self.ciam(suffix),
            method="POST",
            json_body=body,
            headers=bearer(self.customer_token),
        )
        expect(response.status == expected, f"POST {suffix} HTTP {response.status}: {safe_error(response)}")
        return response.json()

    def ciam(self, suffix: str) -> str:
        return self.issuer + f"/ciam/tenants/{self.tenant}/customers" + suffix


def request(
    url: str,
    *,
    method: str = "GET",
    json_body: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    basic: tuple[str, str] | None = None,
) -> Response:
    data = None
    actual_headers = dict(headers or {})
    if json_body is not None:
        data = json.dumps(json_body).encode()
        actual_headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        actual_headers["Content-Type"] = "application/x-www-form-urlencoded"
    if basic is not None:
        encoded = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        actual_headers["Authorization"] = f"Basic {encoded}"
    value = urllib.request.Request(url, data=data, headers=actual_headers, method=method)
    try:
        with urllib.request.urlopen(value, timeout=30) as response:
            return Response(response.status, response.read().decode())
    except urllib.error.HTTPError as error:
        return Response(error.code, error.read().decode(errors="replace"))


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


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


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def required_field(value: dict[str, Any], key: str) -> str:
    result = value.get(key)
    expect(isinstance(result, str) and bool(result), f"response is missing {key}")
    return result


def iso_after(*, days: int) -> str:
    value = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)
    return value.isoformat().replace("+00:00", "Z")


def jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    expect(len(parts) == 3, "exchange response is not a JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def require_safe_secret_path(path: pathlib.Path) -> None:
    repo = pathlib.Path(__file__).resolve().parents[1]
    try:
        relative = path.relative_to(repo)
    except ValueError:
        return
    check = subprocess.run(
        ["git", "check-ignore", "--quiet", "--", str(relative)],
        cwd=repo,
        check=False,
    )
    expect(check.returncode == 0, "credential file path inside the repository must be gitignored")


def write_secret_file(
    path: pathlib.Path,
    application_id: str,
    client: dict[str, Any],
    secret: str,
) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    content = {
        "warning": "LOCAL SECRET. DO NOT COMMIT, LOG, OR SHARE.",
        "application_id": application_id,
        "client_id": required_field(client, "clientId"),
        "client_secret": secret,
    }
    descriptor, temporary = tempfile.mkstemp(prefix=".credential-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(content, handle)
            handle.write("\n")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"WARNING: generated Agent credential stored only at {path}", file=sys.stderr)


def read_secret_file(path: pathlib.Path) -> dict[str, Any]:
    expect(path.exists(), f"local Agent credential file is missing: {path}")
    mode = path.stat().st_mode & 0o777
    expect(mode == 0o600, f"local Agent credential file must have mode 0600, not {mode:04o}")
    return json.loads(path.read_text(encoding="utf-8"))


def safe_error(response: Response) -> str:
    try:
        payload = response.json()
        return str(payload.get("message") or payload.get("error") or "request rejected")[:160]
    except Exception:
        return "non-JSON error"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


if __name__ == "__main__":
    try:
        raise SystemExit(Publisher().run())
    except Exception as error:
        print(f"RESULT FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from None
