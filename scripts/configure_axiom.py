#!/usr/bin/env python3
"""Validate and publish Axiom tenant configuration through public HTTP APIs."""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configuration" / "tenants"
DEFAULT_SECRET_FILE = ROOT / ".local" / "configured-agent-clients.json"
KUBERNETES_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")


class ConfigurationError(RuntimeError):
    pass


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"{path} must contain one JSON object")
    return value


def read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigurationError(f"cannot read {path}: {exc}") from exc
    for number, line in enumerate(lines, 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ConfigurationError(f"{path}:{number}: expected one JSON object")
        values.append(value)
    return values


def require(record: dict[str, Any], field: str, source: str) -> Any:
    value = record.get(field)
    if value is None or value == "" or value == []:
        raise ConfigurationError(f"{source}: {field} is required")
    return value


def unique(records: list[dict[str, Any]], field: str, source: str) -> set[str]:
    values: list[str] = []
    for record in records:
        values.append(str(require(record, field, source)))
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise ConfigurationError(f"{source}: duplicate {field}: {', '.join(duplicates)}")
    return set(values)


def validate_kubernetes_secret(record: dict[str, Any], source: str) -> None:
    target = record.get("kubernetesSecret")
    if target is None:
        return
    if not isinstance(target, dict):
        raise ConfigurationError(f"{source}: kubernetesSecret must be an object")
    namespace = str(require(target, "namespace", source))
    name = str(require(target, "name", source))
    if not KUBERNETES_NAME.fullmatch(namespace) or not KUBERNETES_NAME.fullmatch(name):
        raise ConfigurationError(f"{source}: invalid Kubernetes Secret namespace or name")


def load_bundle(directory: pathlib.Path) -> dict[str, Any]:
    bundle = {
        "tenant": read_json(directory / "tenant.json"),
        "groups": read_jsonl(directory / "groups" / "groups.jsonl"),
        "users": read_jsonl(directory / "users" / "users.jsonl"),
        "memberships": read_jsonl(directory / "memberships" / "memberships.jsonl"),
        "applications": read_jsonl(directory / "ciam" / "applications.jsonl"),
        "public_clients": read_jsonl(directory / "ciam" / "public-clients.jsonl"),
        "customers": read_jsonl(directory / "ciam" / "customers.jsonl"),
        "agent_workloads": read_jsonl(directory / "ciam" / "agent-workloads.jsonl"),
        "application_roles": read_jsonl(directory / "ciam" / "application-roles.jsonl"),
        "application_memberships": read_jsonl(directory / "ciam" / "application-memberships.jsonl"),
        "trusted_brokers": read_jsonl(directory / "ciam" / "trusted-brokers.jsonl"),
        "agent_exchange_routes": read_jsonl(directory / "ciam" / "agent-exchange-routes.jsonl"),
    }
    validate_bundle(bundle, directory)
    return bundle


def validate_bundle(bundle: dict[str, Any], directory: pathlib.Path) -> None:
    tenant = bundle["tenant"]
    tenant_id = str(require(tenant, "id", str(directory / "tenant.json")))
    require(tenant, "name", str(directory / "tenant.json"))
    require(tenant, "slug", str(directory / "tenant.json"))
    email_domain = str(require(tenant, "emailDomain", str(directory / "tenant.json"))).lower()
    if directory.name != tenant_id:
        raise ConfigurationError(f"{directory}: folder name must match tenant id {tenant_id!r}")

    group_keys = unique(bundle["groups"], "key", "groups.jsonl")
    unique(bundle["groups"], "name", "groups.jsonl")
    user_ids = unique(bundle["users"], "id", "users.jsonl")
    unique(bundle["users"], "username", "users.jsonl")
    unique(bundle["users"], "email", "users.jsonl")
    for user in bundle["users"]:
        email = str(require(user, "email", "users.jsonl")).lower()
        if not email.endswith("@" + email_domain):
            raise ConfigurationError(f"users.jsonl: {email} is outside {email_domain}")
        require(user, "passwordEnv", "users.jsonl")

    for membership in bundle["memberships"]:
        user_id = str(require(membership, "userId", "memberships.jsonl"))
        group_key = str(require(membership, "groupKey", "memberships.jsonl"))
        if user_id not in user_ids:
            raise ConfigurationError(f"memberships.jsonl: unknown user {user_id}")
        if group_key not in group_keys:
            raise ConfigurationError(f"memberships.jsonl: unknown group {group_key}")

    app_keys = unique(bundle["applications"], "key", "applications.jsonl")
    unique(bundle["applications"], "audience", "applications.jsonl")
    public_ids = unique(bundle["public_clients"], "clientId", "public-clients.jsonl")
    workload_ids = unique(bundle["agent_workloads"], "clientId", "agent-workloads.jsonl")
    broker_ids = unique(bundle["trusted_brokers"], "clientId", "trusted-brokers.jsonl")
    if public_ids & workload_ids or public_ids & broker_ids or workload_ids & broker_ids:
        raise ConfigurationError("a clientId cannot represent more than one authority type")
    workload_refs = unique(bundle["agent_workloads"], "workloadRef", "agent-workloads.jsonl")
    for source, records in (
        ("public-clients.jsonl", bundle["public_clients"]),
        ("agent-workloads.jsonl", bundle["agent_workloads"]),
    ):
        for record in records:
            if str(require(record, "applicationKey", source)) not in app_keys:
                raise ConfigurationError(f"{source}: unknown applicationKey")
            require(record, "scopes", source)
            validate_kubernetes_secret(record, source)

    for broker in bundle["trusted_brokers"]:
        app_key = str(require(broker, "applicationKey", "trusted-brokers.jsonl"))
        if app_key not in app_keys:
            raise ConfigurationError("trusted-brokers.jsonl: unknown applicationKey")
        require(broker, "gatewayAudience", "trusted-brokers.jsonl")
        require(broker, "scopes", "trusted-brokers.jsonl")
        validate_kubernetes_secret(broker, "trusted-brokers.jsonl")

    role_keys: dict[str, set[str]] = {}
    for role in bundle["application_roles"]:
        app_key = str(require(role, "applicationKey", "application-roles.jsonl"))
        if app_key not in app_keys:
            raise ConfigurationError("application-roles.jsonl: unknown applicationKey")
        role_key = str(require(role, "roleKey", "application-roles.jsonl"))
        if role_key in role_keys.setdefault(app_key, set()):
            raise ConfigurationError(f"application-roles.jsonl: duplicate roleKey {app_key}/{role_key}")
        role_keys[app_key].add(role_key)
        require(role, "displayName", "application-roles.jsonl")
        require(role, "permissions", "application-roles.jsonl")
        require(role, "permissionEffects", "application-roles.jsonl")

    for membership in bundle["application_memberships"]:
        app_key = str(require(membership, "applicationKey", "application-memberships.jsonl"))
        if app_key not in app_keys:
            raise ConfigurationError("application-memberships.jsonl: unknown applicationKey")
        principal = str(require(membership, "principalId", "application-memberships.jsonl"))
        if principal not in user_ids:
            raise ConfigurationError(f"application-memberships.jsonl: unknown principalId {principal}")
        for role_key in require(membership, "roleKeys", "application-memberships.jsonl"):
            if str(role_key) not in role_keys.get(app_key, set()):
                raise ConfigurationError(
                    f"application-memberships.jsonl: unknown roleKey {app_key}/{role_key}"
                )
        require(membership, "assignmentSource", "application-memberships.jsonl")

    route_keys: set[tuple[str, str, str]] = set()
    for route in bundle["agent_exchange_routes"]:
        source = str(require(route, "sourceWorkloadRef", "agent-exchange-routes.jsonl"))
        if source not in workload_refs:
            raise ConfigurationError(f"agent-exchange-routes.jsonl: unknown sourceWorkloadRef {source}")
        destination_type = str(require(route, "destinationType", "agent-exchange-routes.jsonl"))
        if destination_type not in {"AGENT", "RESOURCE", "GATEWAY"}:
            raise ConfigurationError("agent-exchange-routes.jsonl: invalid destinationType")
        destination = route.get("destinationWorkloadRef")
        if destination_type == "AGENT":
            if not destination or str(destination) not in workload_refs or str(destination) == source:
                raise ConfigurationError("agent-exchange-routes.jsonl: invalid Agent destination")
        elif destination:
            raise ConfigurationError("agent-exchange-routes.jsonl: only Agent routes name a destination workload")
        audience = str(require(route, "audience", "agent-exchange-routes.jsonl"))
        key = (source, destination_type, audience)
        if key in route_keys:
            raise ConfigurationError(f"agent-exchange-routes.jsonl: duplicate route {key}")
        route_keys.add(key)
        ttl = int(require(route, "ttlSeconds", "agent-exchange-routes.jsonl"))
        if ttl <= 0 or ttl > 90 * 24 * 60 * 60:
            raise ConfigurationError("agent-exchange-routes.jsonl: ttlSeconds must be within 90 days")
        require(route, "scopes", "agent-exchange-routes.jsonl")
        require(route, "purpose", "agent-exchange-routes.jsonl")

    unique(bundle["customers"], "email", "customers.jsonl")
    for customer in bundle["customers"]:
        email = str(require(customer, "email", "customers.jsonl")).lower()
        if not email.endswith("@" + email_domain):
            raise ConfigurationError(f"customers.jsonl: {email} is outside {email_domain}")
        require(customer, "displayName", "customers.jsonl")
        require(customer, "passwordEnv", "customers.jsonl")


class Axiom:
    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        response = self.request(
            "/auth/login", method="POST", body={"username": username, "password": password}, auth=False
        )
        self.token = str(require(response, "accessToken", "login response"))
        self.claims = jwt_claims(self.token)

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        auth: bool = True,
    ) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request_headers = {"Accept": "application/json"}
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        if auth:
            request_headers["Authorization"] = f"Bearer {self.token}"
        request_headers.update(headers or {})
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8")[:500]
            raise RuntimeError(f"{method} {path} returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"cannot reach Axiom at {self.base_url}: {exc.reason}") from exc
        return json.loads(payload) if payload else None


class Publisher:
    def __init__(self, api: Axiom, bundle: dict[str, Any], secret_file: pathlib.Path) -> None:
        self.api = api
        self.bundle = bundle
        self.tenant = str(bundle["tenant"]["id"])
        self.secret_file = secret_file
        self.counts: Counter[str] = Counter()
        self.secrets = read_secret_state(secret_file)

    def run(self) -> Counter[str]:
        token_tenant = str(self.api.claims.get("tenant_id", ""))
        if token_tenant != self.tenant:
            raise ConfigurationError(
                f"authenticated tenant is {token_tenant!r}, but configuration is for {self.tenant!r}"
            )
        self.ensure_tenant()
        self.ensure_kubernetes_secret_access()
        groups = self.ensure_groups()
        self.ensure_users()
        self.ensure_memberships(groups)
        applications = self.ensure_applications()
        self.ensure_public_clients(applications)
        roles = self.ensure_application_roles(applications)
        self.ensure_application_memberships(applications, roles)
        self.ensure_customers()
        workloads = self.ensure_agent_workloads(applications)
        self.ensure_trusted_brokers(applications)
        self.ensure_agent_exchange_routes(workloads)
        self.remove_kubernetes_bound_local_secrets()
        write_secret_state(self.secret_file, self.secrets)
        return self.counts

    def remove_kubernetes_bound_local_secrets(self) -> None:
        tenant_secrets = self.secrets.get(self.tenant)
        if not isinstance(tenant_secrets, dict):
            return
        for spec in self.bundle["agent_workloads"] + self.bundle["trusted_brokers"]:
            if spec.get("kubernetesSecret"):
                tenant_secrets.pop(spec["clientId"], None)
        if not tenant_secrets:
            self.secrets.pop(self.tenant, None)

    def ensure_kubernetes_secret_access(self) -> None:
        namespaces = {
            str(spec["kubernetesSecret"]["namespace"])
            for spec in self.bundle["agent_workloads"] + self.bundle["trusted_brokers"]
            if spec.get("kubernetesSecret")
        }
        for namespace in sorted(namespaces):
            for verb in ("get", "create", "patch"):
                result = subprocess.run(
                    ["kubectl", "auth", "can-i", verb, "secrets", "-n", namespace],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                if result.stdout.strip() != "yes":
                    raise ConfigurationError(
                        f"publisher cannot {verb} Kubernetes Secrets in namespace {namespace}"
                    )

    def ensure_tenant(self) -> None:
        current = self.api.request(f"/admin/tenants/{self.tenant}")
        if current.get("active") is True:
            self.counts["tenants_unchanged"] += 1
            return
        tenant = self.bundle["tenant"]
        self.api.request(
            "/admin/tenants",
            method="POST",
            body={"tenantId": self.tenant, "name": tenant["name"], "slug": tenant["slug"]},
            headers={"Idempotency-Key": f"configuration-v1-{self.tenant}"},
        )
        self.counts["tenants_created"] += 1

    def ensure_groups(self) -> dict[str, dict[str, Any]]:
        existing = {item["name"]: item for item in self.api.request("/teams")}
        resolved: dict[str, dict[str, Any]] = {}
        for spec in self.bundle["groups"]:
            current = existing.get(spec["name"])
            if current is None:
                current = self.api.request(
                    "/teams",
                    method="POST",
                    body={
                        "name": spec["name"],
                        "domainId": None,
                        "description": spec.get("description"),
                        "defaultRoles": [],
                        "segments": [],
                        "allowedDomains": [],
                    },
                )
                self.counts["groups_created"] += 1
            else:
                if current.get("description") != spec.get("description"):
                    raise ConfigurationError(f"group drift: {spec['key']}")
                self.counts["groups_unchanged"] += 1
            resolved[spec["key"]] = current
        return resolved

    def ensure_users(self) -> None:
        page = self.api.request("/users?page=0&size=500")
        existing = {item["id"]: item for item in page["content"]}
        for spec in self.bundle["users"]:
            current = existing.get(spec["id"])
            if current is None:
                password = required_env(str(spec["passwordEnv"]))
                self.api.request(
                    "/users",
                    method="POST",
                    body={
                        "id": spec["id"],
                        "username": spec["username"],
                        "email": spec["email"],
                        "password": password,
                        "attributes": {
                            "display_name": spec["displayName"],
                            "department": spec["department"],
                            "directory_source": "configuration",
                            "external_id": spec["id"],
                        },
                    },
                )
                self.counts["users_created"] += 1
            else:
                if current.get("username") != spec["username"] or current.get("email") != spec["email"]:
                    raise ConfigurationError(f"user identity drift: {spec['id']}")
                self.counts["users_unchanged"] += 1

    def ensure_memberships(self, groups: dict[str, dict[str, Any]]) -> None:
        for spec in self.bundle["memberships"]:
            group = groups[spec["groupKey"]]
            group_id = group["id"]
            members = self.api.request(f"/teams/{group_id}/members")
            if any(member.get("id") == spec["userId"] for member in members):
                self.counts["memberships_unchanged"] += 1
                continue
            self.api.request(
                f"/teams/{group_id}/members", method="POST", body={"userId": spec["userId"]}
            )
            self.counts["memberships_created"] += 1

    def ensure_applications(self) -> dict[str, dict[str, Any]]:
        existing = {
            item["applicationKey"]: item
            for item in self.api.request(f"/admin/tenants/{self.tenant}/applications")
        }
        resolved: dict[str, dict[str, Any]] = {}
        for spec in self.bundle["applications"]:
            current = existing.get(spec["key"])
            if current is None:
                current = self.api.request(
                    f"/admin/tenants/{self.tenant}/applications",
                    method="POST",
                    body={
                        "applicationKey": spec["key"],
                        "displayName": spec["displayName"],
                        "description": spec.get("description"),
                        "audience": spec["audience"],
                    },
                )
                self.counts["applications_created"] += 1
            else:
                if current.get("audience") != spec["audience"]:
                    raise ConfigurationError(f"application audience drift: {spec['key']}")
                self.counts["applications_unchanged"] += 1
            resolved[spec["key"]] = current
        return resolved

    def ensure_public_clients(self, applications: dict[str, dict[str, Any]]) -> None:
        for spec in self.bundle["public_clients"]:
            self.ensure_client(applications[spec["applicationKey"]], spec, "PUBLIC_BROWSER")

    def ensure_customers(self) -> None:
        existing = {
            str(item["email"]).lower(): item
            for item in self.api.request(f"/admin/tenants/{self.tenant}/ciam/customers")
        }
        for spec in self.bundle["customers"]:
            email = str(spec["email"]).lower()
            current = existing.get(email)
            if current is not None:
                if current.get("status") != "ACTIVE":
                    raise ConfigurationError(f"customer is not active: {email}")
                self.counts["customers_unchanged"] += 1
                continue
            registration = self.api.request(
                f"/ciam/tenants/{self.tenant}/customers/registrations",
                method="POST",
                body={
                    "email": email,
                    "displayName": spec["displayName"],
                    "password": required_env(str(spec["passwordEnv"])),
                },
                auth=False,
            )
            action = registration.get("localDemoAction") or {}
            token = action.get("token")
            if not token:
                raise RuntimeError(
                    f"customer {email} requires external verification; no local verification token returned"
                )
            self.api.request(
                f"/ciam/tenants/{self.tenant}/customers/verifications",
                method="POST",
                body={"token": token},
                auth=False,
            )
            self.counts["customers_created"] += 1

    def ensure_application_roles(
        self, applications: dict[str, dict[str, Any]]
    ) -> dict[tuple[str, str], dict[str, Any]]:
        resolved: dict[tuple[str, str], dict[str, Any]] = {}
        for spec in self.bundle["application_roles"]:
            app_key = spec["applicationKey"]
            app_id = applications[app_key]["id"]
            existing = {
                item["roleKey"]: item
                for item in self.api.request(
                    f"/admin/tenants/{self.tenant}/applications/{app_id}/access/roles"
                )
            }
            current = existing.get(spec["roleKey"])
            if current is None:
                current = self.api.request(
                    f"/admin/tenants/{self.tenant}/applications/{app_id}/access/roles",
                    method="POST",
                    body={
                        "roleKey": spec["roleKey"],
                        "displayName": spec["displayName"],
                        "description": spec.get("description"),
                        "permissions": spec["permissions"],
                        "permissionEffects": spec["permissionEffects"],
                    },
                )
                self.counts["application_roles_created"] += 1
            else:
                if (
                    set(current.get("permissions", [])) != set(spec["permissions"])
                    or current.get("permissionEffects", {}) != spec["permissionEffects"]
                ):
                    raise ConfigurationError(f"application role drift: {app_key}/{spec['roleKey']}")
                self.counts["application_roles_unchanged"] += 1
            resolved[(app_key, spec["roleKey"])] = current
        return resolved

    def ensure_application_memberships(
        self,
        applications: dict[str, dict[str, Any]],
        roles: dict[tuple[str, str], dict[str, Any]],
    ) -> None:
        for spec in self.bundle["application_memberships"]:
            app_key = spec["applicationKey"]
            app_id = applications[app_key]["id"]
            existing = {
                item["principalId"]: item
                for item in self.api.request(
                    f"/admin/tenants/{self.tenant}/applications/{app_id}/access/memberships"
                )
            }
            current = existing.get(spec["principalId"])
            if current is None:
                current = self.api.request(
                    f"/admin/tenants/{self.tenant}/applications/{app_id}/access/memberships",
                    method="POST",
                    body={
                        "principalId": spec["principalId"],
                        "assignmentSource": spec["assignmentSource"],
                    },
                )
                self.counts["application_memberships_created"] += 1
            elif current.get("status") != "ACTIVE":
                raise ConfigurationError(f"application membership is disabled: {app_key}/{spec['principalId']}")
            else:
                self.counts["application_memberships_unchanged"] += 1
            assigned = set(current.get("roles", []))
            for role_key in spec["roleKeys"]:
                if role_key in assigned:
                    self.counts["application_role_assignments_unchanged"] += 1
                    continue
                current = self.api.request(
                    f"/admin/tenants/{self.tenant}/applications/{app_id}/access/memberships/{current['id']}/roles",
                    method="POST",
                    body={
                        "roleId": roles[(app_key, role_key)]["id"],
                        "assignmentSource": spec["assignmentSource"],
                    },
                )
                assigned = set(current.get("roles", []))
                self.counts["application_role_assignments_created"] += 1

    def ensure_agent_workloads(
        self, applications: dict[str, dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        existing = {
            item["workloadRef"]: item
            for item in self.api.request(f"/admin/tenants/{self.tenant}/ciam/agent-workloads")
        }
        for spec in self.bundle["agent_workloads"]:
            application = applications[spec["applicationKey"]]
            client = self.ensure_client(application, spec, "CONFIDENTIAL_SERVICE")
            current = existing.get(spec["workloadRef"])
            if current is None:
                self.api.request(
                    f"/admin/tenants/{self.tenant}/ciam/agent-workloads",
                    method="POST",
                    body={
                        "workloadRef": spec["workloadRef"],
                        "name": spec["name"],
                        "oauthClientId": spec["clientId"],
                    },
                )
                self.counts["agent_workloads_created"] += 1
            else:
                if current.get("oauthClientId") != spec["clientId"] or current.get("name") != spec["name"]:
                    raise ConfigurationError(f"Agent workload drift: {spec['workloadRef']}")
                self.counts["agent_workloads_unchanged"] += 1
            if client.get("status") != "ACTIVE":
                raise ConfigurationError(f"Agent client is not active: {spec['clientId']}")
        return {
            item["workloadRef"]: item
            for item in self.api.request(f"/admin/tenants/{self.tenant}/ciam/agent-workloads")
        }

    def ensure_trusted_brokers(self, applications: dict[str, dict[str, Any]]) -> None:
        existing = {
            item["oauthClientId"]: item
            for item in self.api.request(f"/admin/tenants/{self.tenant}/agent-exchange/brokers")
        }
        for spec in self.bundle["trusted_brokers"]:
            client = self.ensure_client(
                applications[spec["applicationKey"]], spec, "CONFIDENTIAL_SERVICE"
            )
            if client.get("status") != "ACTIVE":
                raise ConfigurationError(f"trusted broker client is not active: {spec['clientId']}")
            current = existing.get(spec["clientId"])
            if current is None:
                current = self.api.request(
                    f"/admin/tenants/{self.tenant}/agent-exchange/brokers",
                    method="POST",
                    body={
                        "oauthClientId": spec["clientId"],
                        "gatewayAudience": spec["gatewayAudience"],
                        "scopes": spec["scopes"],
                    },
                )
                self.counts["trusted_brokers_created"] += 1
            else:
                if (
                    current.get("status") != "ACTIVE"
                    or current.get("gatewayAudience") != spec["gatewayAudience"]
                    or set(current.get("scopes", [])) != set(spec["scopes"])
                ):
                    raise ConfigurationError(f"trusted broker drift: {spec['clientId']}")
                self.counts["trusted_brokers_unchanged"] += 1

    def ensure_agent_exchange_routes(self, workloads: dict[str, dict[str, Any]]) -> None:
        existing = self.api.request(f"/admin/tenants/{self.tenant}/agent-exchange/routes")
        now = datetime.now(timezone.utc)
        for spec in self.bundle["agent_exchange_routes"]:
            source = workloads[spec["sourceWorkloadRef"]]
            destination = (
                workloads[spec["destinationWorkloadRef"]]
                if spec.get("destinationWorkloadRef")
                else None
            )
            matches = [
                item
                for item in existing
                if item.get("sourceWorkloadId") == source["id"]
                and item.get("destinationType") == spec["destinationType"]
                and item.get("audience") == spec["audience"]
                and item.get("status") == "ACTIVE"
            ]
            if len(matches) > 1:
                raise ConfigurationError(f"duplicate active exchange route: {spec['audience']}")
            if matches:
                current = matches[0]
                expected_destination = destination["id"] if destination else None
                expires_at = datetime.fromisoformat(current["expiresAt"].replace("Z", "+00:00"))
                if (
                    current.get("destinationWorkloadId") != expected_destination
                    or set(current.get("scopes", [])) != set(spec["scopes"])
                    or current.get("purpose") != spec["purpose"]
                    or expires_at <= now
                ):
                    raise ConfigurationError(f"Agent exchange route drift: {spec['audience']}")
                self.counts["agent_exchange_routes_unchanged"] += 1
                continue
            expires_at = now + timedelta(seconds=int(spec["ttlSeconds"]))
            self.api.request(
                f"/admin/tenants/{self.tenant}/agent-exchange/routes",
                method="POST",
                body={
                    "sourceWorkloadId": source["id"],
                    "destinationType": spec["destinationType"],
                    "destinationWorkloadId": destination["id"] if destination else None,
                    "audience": spec["audience"],
                    "scopes": spec["scopes"],
                    "purpose": spec["purpose"],
                    "expiresAt": expires_at.isoformat().replace("+00:00", "Z"),
                },
            )
            self.counts["agent_exchange_routes_created"] += 1

    def ensure_client(
        self, application: dict[str, Any], spec: dict[str, Any], client_type: str
    ) -> dict[str, Any]:
        app_id = application["id"]
        clients = self.api.request(
            f"/admin/tenants/{self.tenant}/applications/{app_id}/clients"
        )
        matches = [item for item in clients if item.get("clientId") == spec["clientId"]]
        if len(matches) > 1:
            raise ConfigurationError(f"duplicate OAuth client: {spec['clientId']}")
        if matches:
            current = matches[0]
            if current.get("clientType") != client_type or set(current.get("scopes", [])) != set(spec["scopes"]):
                raise ConfigurationError(f"OAuth client drift: {spec['clientId']}")
            if spec.get("kubernetesSecret"):
                verify_kubernetes_secret(spec, current["clientId"])
            self.counts["oauth_clients_unchanged"] += 1
            return current
        response = self.api.request(
            f"/admin/tenants/{self.tenant}/applications/{app_id}/clients",
            method="POST",
            body={
                "clientId": spec["clientId"],
                "clientType": client_type,
                "redirectUris": spec.get("redirectUris", []),
                "postLogoutRedirectUris": spec.get("postLogoutRedirectUris", []),
                "scopes": spec["scopes"],
            },
        )
        current = response["client"]
        service_secret = response.get("serviceSecret")
        if service_secret:
            if spec.get("kubernetesSecret"):
                apply_kubernetes_secret(spec, service_secret)
            else:
                self.secrets.setdefault(self.tenant, {})[spec["clientId"]] = service_secret
        self.counts["oauth_clients_created"] += 1
        return current


def kubernetes_secret(spec: dict[str, Any]) -> tuple[str, str]:
    target = spec["kubernetesSecret"]
    return str(target["namespace"]), str(target["name"])


def apply_kubernetes_secret(spec: dict[str, Any], client_secret: str) -> None:
    namespace, name = kubernetes_secret(spec)
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "axiom-configuration",
                "axiom.openwolf.com/credential-kind": "oauth-client",
            },
        },
        "type": "Opaque",
        "stringData": {
            "client_id": spec["clientId"],
            "client_secret": client_secret,
        },
    }
    subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=json.dumps(manifest),
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    verify_kubernetes_secret(spec, spec["clientId"])


def verify_kubernetes_secret(spec: dict[str, Any], expected_client_id: str) -> None:
    namespace, name = kubernetes_secret(spec)
    result = subprocess.run(
        ["kubectl", "get", "secret", name, "-n", namespace, "-o", "json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ConfigurationError(f"required Kubernetes Secret is missing: {namespace}/{name}")
    payload = json.loads(result.stdout)
    data = payload.get("data", {})
    try:
        client_id = base64.b64decode(data["client_id"]).decode("utf-8")
        client_secret = base64.b64decode(data["client_secret"]).decode("utf-8")
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise ConfigurationError(
            f"Kubernetes Secret {namespace}/{name} lacks valid client_id/client_secret keys"
        ) from exc
    if client_id != expected_client_id or not client_secret:
        raise ConfigurationError(f"Kubernetes Secret identity drift: {namespace}/{name}")


def jwt_claims(token: str) -> dict[str, Any]:
    try:
        segment = token.split(".")[1]
        padding = "=" * (-len(segment) % 4)
        value = json.loads(base64.urlsafe_b64decode(segment + padding))
    except (IndexError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("Axiom returned an invalid access token") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Axiom access token claims are invalid")
    return value


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigurationError(f"required environment variable is not set: {name}")
    return value


def read_secret_state(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = read_json(path)
    return value


def write_secret_state(path: pathlib.Path, value: dict[str, Any]) -> None:
    if not value:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def inventories(bundle: dict[str, Any]) -> dict[str, int]:
    return {
        key: len(bundle[key])
        for key in (
            "groups",
            "users",
            "memberships",
            "applications",
            "public_clients",
            "customers",
            "agent_workloads",
            "application_roles",
            "application_memberships",
            "trusted_brokers",
            "agent_exchange_routes",
        )
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONFIG)
    parser.add_argument("--tenant", help="publish one tenant folder")
    parser.add_argument("--base-url", default=os.environ.get("AXIOM_BASE_URL", "http://localhost:8180"))
    parser.add_argument("--username", default=os.environ.get("AXIOM_ADMIN_USERNAME", "admin"))
    parser.add_argument("--secret-file", type=pathlib.Path, default=DEFAULT_SECRET_FILE)
    parser.add_argument("--check", action="store_true", help="validate configuration without calling Axiom")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.config.resolve()
    directories = sorted(path.parent for path in root.glob("*/tenant.json"))
    if args.tenant:
        directories = [root / args.tenant]
    if not directories:
        raise ConfigurationError(f"no tenant configuration found under {root}")
    bundles = [load_bundle(directory) for directory in directories]
    for bundle in bundles:
        print(json.dumps({"tenant": bundle["tenant"]["id"], "inventory": inventories(bundle)}, sort_keys=True))
    if args.check:
        print("Axiom configuration check PASS")
        return 0
    if len(bundles) != 1:
        raise ConfigurationError("publish one tenant at a time with --tenant")
    password = required_env("AXIOM_ADMIN_PASSWORD")
    api = Axiom(args.base_url, args.username, password)
    counts = Publisher(api, bundles[0], args.secret_file.resolve()).run()
    print("Axiom tenant configuration publish PASS")
    for key in sorted(counts):
        print(f"  {key}: {counts[key]}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConfigurationError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
