"""Run context: who is calling, against which target, and which records this run owns.

The one-time operator bootstrap (example B01 explains it in prose):

1. The disposable estate's *bootstrap process* creates the first tenant and a root administrator (``platform_admin``)
   from protected configuration. That is the only identity not created through the API.
2. The root administrator logs in through the browser authorization-code flow (public client ``axiom-admin``, S256
   PKCE) — never through a password grant — and creates a *provisioning operator*: a workforce user holding only the
   tenant role ``tenant_admin``. Role assignment is a ``platform_admin``-only operation, which is why the root
   administrator is needed exactly once.
3. Every example then provisions through the operator. A second operator exists only for the two-person
   identity-control flows (credential rotation), where Axiom refuses self-approval.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

from . import oauth
from .estate import Estate
from .http import AxiomHttp, Response
from .oauth import Client
from .redaction import Secret
from .target import Target, guard, new_namespace
from .tokens import Validator

ADMIN_CLIENT = Client("axiom-admin", None, "http://127.0.0.1:9/cookbook/callback")
ADMIN_SCOPES = ("openid", "profile", "email", "roles")


def strong_password() -> Secret:
    return Secret(secrets.token_urlsafe(18) + "Aa1!", "password")


@dataclass
class Owned:
    """One record this run created, and how to stop it if the run must clean up."""
    kind: str
    ref: str
    undo: Callable[[], Response] | None
    note: str = ""


@dataclass
class Registry:
    namespace: str
    owned: list[Owned] = field(default_factory=list)

    def add(self, kind: str, ref: str, undo: Callable[[], Response] | None, note: str = "") -> None:
        self.owned.append(Owned(kind, ref, undo, note))

    def cleanup(self) -> dict[str, list[str]]:
        """Disables/revokes this run's records in reverse order. Axiom has few hard deletes, so most records remain
        as disabled residuals; those are reported, never removed with SQL."""
        done, residual, failed = [], [], []
        for item in reversed(self.owned):
            if item.undo is None:
                residual.append(f"{item.kind} {item.ref} ({item.note or 'no delete/disable API'})")
                continue
            r = item.undo()
            if r.status in (200, 201, 202, 204, 404, 409):
                (done if r.status != 409 else residual).append(f"{item.kind} {item.ref} -> {r.status}")
            else:
                failed.append(f"{item.kind} {item.ref} -> {r.status}")
        self.owned.clear()
        return {"disabled_or_revoked": done, "residual": residual, "failed": failed}


@dataclass
class Context:
    http: AxiomHttp
    target: Target
    validator: Validator
    registry: Registry
    root_username: str
    root_password: Secret
    operator_username: str | None = None
    operator_password: Secret | None = None
    second_operator_username: str | None = None
    second_operator_password: Secret | None = None
    quiet: bool = False
    estate: Estate | None = None

    # ------------------------------------------------------------------------------------------------------------
    @classmethod
    def from_estate(cls, estate: Estate, quiet: bool = False) -> "Context":
        target = guard(estate.base_url, estate.tenant_id, new_namespace(), allow_writes=True)
        http = AxiomHttp(target.base_url)
        ctx = cls(http, target, Validator.discover(http), Registry(target.namespace), estate.root_admin_username,
                  estate.root_admin_password, quiet=quiet, estate=estate)
        ctx.ensure_operators()
        return ctx

    @classmethod
    def from_environment(cls) -> "Context":
        """For running one example directly: ``AXIOM_COOKBOOK_STATE`` names an estate state file (0600)."""
        state = os.environ.get("AXIOM_COOKBOOK_STATE")
        if not state:
            raise SystemExit("Start an estate first: `python -m axiom_cookbook.estate up`, then export "
                             "AXIOM_COOKBOOK_STATE=<state file>. See README.md.")
        return cls.from_estate(Estate.load(state))

    def child(self) -> "Context":
        """Same target and operators, fresh fixture namespace and registry (one per example/test)."""
        target = guard(self.target.base_url, self.target.tenant_id, new_namespace(), self.target.allow_writes)
        return Context(self.http, target, self.validator, Registry(target.namespace), self.root_username,
                       self.root_password, self.operator_username, self.operator_password,
                       self.second_operator_username, self.second_operator_password, self.quiet, self.estate)

    def say(self, message: str) -> None:
        if not self.quiet:
            print(message)

    @property
    def tenant(self) -> str:
        return self.target.tenant_id

    def name(self, suffix: str) -> str:
        """Unique, lowercase, run-scoped identifier for a fixture."""
        return f"{self.target.namespace}-{suffix}"

    # ------------------------------------------------------------------------------------------------------------
    def admin_login(self, username: str, password: Secret) -> Secret:
        return oauth.browser_login(self.http, ADMIN_CLIENT, username, password, ADMIN_SCOPES).access_token

    def root(self) -> Secret:
        return self.admin_login(self.root_username, self.root_password)

    def operator(self) -> Secret:
        return self.admin_login(self.operator_username, self.operator_password)

    def second_operator(self) -> Secret:
        return self.admin_login(self.second_operator_username, self.second_operator_password)

    def ensure_operators(self) -> None:
        """Creates the tenant_admin provisioning operators once per run (see module docstring)."""
        if self.operator_username:
            return
        self.target.require_writes()
        root = self.root()
        role = self.tenant_role(root, "tenant_admin")
        self.operator_username, self.operator_password = self.workforce_user(root, "operator", role_id=role,
                                                                             as_root=root)
        self.second_operator_username, self.second_operator_password = self.workforce_user(
            root, "operator2", role_id=role, as_root=root)

    def tenant_role(self, root: Secret, name: str) -> str:
        """Finds or creates a tenant role by name (tenant roles are matched by name, e.g. ``tenant_admin``)."""
        for role in self.http.get("/roles", bearer=root).expect(200).json():
            if role["name"] == name:
                return role["id"]
        return self.http.post("/roles", bearer=root, json_body={"name": name, "description": "cookbook " + name,
                                                                "permissions": []}).expect(201).json()["id"]

    def workforce_user(self, bearer: Secret, suffix: str, role_id: str | None = None,
                       as_root: Secret | None = None) -> tuple[str, Secret]:
        user_id = self.name(suffix)
        password = strong_password()
        self.http.post("/users", bearer=bearer, json_body={"id": user_id, "username": user_id,
                                                           "email": f"{user_id}@cookbook.invalid",
                                                           "password": password.reveal(), "attributes": {}}).expect(201)
        self.registry.add("workforce user", user_id,
                          lambda: self.http.delete(f"/users/{user_id}", bearer=self.operator()), "soft delete (disable)")
        if role_id:
            self.http.post(f"/users/{user_id}/roles", bearer=as_root or bearer, json_body={"roleId": role_id}).expect(200)
        return user_id, password

    # ---------------------------------------------------------------------------------------------- applications
    def admin_base(self) -> str:
        return f"/admin/tenants/{self.tenant}"

    def application(self, op: Secret, suffix: str, audience: str | None = None) -> dict[str, Any]:
        key = self.name(suffix)
        app = self.http.post(self.admin_base() + "/applications", bearer=op, json_body={
            "applicationKey": key, "displayName": key, "audience": audience or f"https://{key}.cookbook.invalid"}
        ).expect(201).json()
        self.registry.add("application", key, lambda: self.http.delete(
            f"{self.admin_base()}/applications/{app['id']}", bearer=self.operator()), "disable")
        return app

    def public_client(self, op: Secret, app: dict, suffix: str, scopes: list[str],
                      redirect_uri: str = "http://127.0.0.1:9/app/callback") -> tuple[Client, dict]:
        client_id = self.name(suffix)
        created = self.http.post(f"{self.admin_base()}/applications/{app['id']}/clients", bearer=op, json_body={
            "clientId": client_id, "clientType": "PUBLIC_BROWSER", "redirectUris": [redirect_uri],
            "postLogoutRedirectUris": [], "scopes": ["openid", *scopes]}).expect(201).json()
        self._own_client(app, created["client"])
        return Client(client_id, None, redirect_uri), created["client"]

    def service_client(self, op: Secret, app: dict, suffix: str, scopes: list[str]) -> tuple[Client, dict]:
        """A confidential client. Axiom generates the secret and returns it exactly once; it is held as a Secret."""
        client_id = self.name(suffix)
        created = self.http.post(f"{self.admin_base()}/applications/{app['id']}/clients", bearer=op, json_body={
            "clientId": client_id, "clientType": "CONFIDENTIAL_SERVICE", "redirectUris": [],
            "postLogoutRedirectUris": [], "scopes": scopes}).expect(201).json()
        self._own_client(app, created["client"])
        return Client(client_id, Secret(created["serviceSecret"], f"{client_id} secret")), created["client"]

    def interactive_client(self, op: Secret, app: dict, suffix: str, scopes: list[str], *,
                           client_type: str = "PUBLIC_BROWSER", population: str = "WORKFORCE",
                           require_consent: bool | None = None, access_ttl: int | None = None,
                           refresh_ttl: int | None = None,
                           redirect_uri: str = "http://127.0.0.1:9/app/callback",
                           post_logout_redirect_uri: str | None = None) -> tuple[Client, dict]:
        """A sign-in client (setup adapter, Axiom management API). ``PUBLIC_BROWSER``: no secret, PKCE.
        ``CONFIDENTIAL_WEB``: a server-side web client with a one-time secret, PKCE and, if granted ``offline_access``,
        rotating refresh tokens. ``population`` selects who signs in: ``WORKFORCE`` or ``CUSTOMER``."""
        client_id = self.name(suffix)
        body: dict[str, Any] = {"clientId": client_id, "clientType": client_type, "population": population,
                                "redirectUris": [redirect_uri],
                                "postLogoutRedirectUris": [post_logout_redirect_uri] if post_logout_redirect_uri else [],
                                "scopes": ["openid", *[s for s in scopes if s != "openid"]]}
        if require_consent is not None:
            body["requireConsent"] = require_consent
        if access_ttl is not None:
            body["accessTokenTtlSeconds"] = access_ttl
        if refresh_ttl is not None:
            body["refreshTokenTtlSeconds"] = refresh_ttl
        created = self.http.post(f"{self.admin_base()}/applications/{app['id']}/clients", bearer=op,
                                 json_body=body).expect(201).json()
        self._own_client(app, created["client"])
        secret = Secret(created["serviceSecret"], f"{client_id} secret") if created.get("serviceSecret") else None
        return Client(client_id, secret, redirect_uri), created["client"]

    def key_client(self, op: Secret, app: dict, suffix: str, scopes: list[str], public_jwks: dict) -> tuple[str, dict]:
        """A confidential service client that authenticates with ``private_key_jwt``; only public keys are sent."""
        client_id = self.name(suffix)
        created = self.http.post(f"{self.admin_base()}/applications/{app['id']}/clients", bearer=op, json_body={
            "clientId": client_id, "clientType": "CONFIDENTIAL_SERVICE", "redirectUris": [],
            "postLogoutRedirectUris": [], "scopes": scopes, "tokenEndpointAuthMethod": "private_key_jwt",
            "jwks": public_jwks}).expect(201).json()
        self._own_client(app, created["client"])
        return client_id, created

    def _own_client(self, app: dict, client: dict) -> None:
        self.registry.add("client", client["clientId"], lambda: self.http.delete(
            f"{self.admin_base()}/applications/{app['id']}/clients/{client['id']}", bearer=self.operator()), "disable")

    def app_role(self, op: Secret, app: dict, suffix: str, effects: dict[str, str]) -> dict:
        return self.http.post(f"{self.admin_base()}/applications/{app['id']}/access/roles", bearer=op, json_body={
            "roleKey": self.name(suffix), "displayName": suffix, "permissions": list(effects),
            "permissionEffects": effects}).expect(201).json()

    def membership(self, op: Secret, app: dict, principal: str, *role_ids: str) -> dict:
        access = f"{self.admin_base()}/applications/{app['id']}/access"
        member = self.http.post(access + "/memberships", bearer=op, json_body={
            "principalId": principal, "assignmentSource": "cookbook"}).expect(201).json()
        self.registry.add("membership", member["id"], lambda: self.http.delete(
            f"{access}/memberships/{member['id']}", bearer=self.operator()), "disable")
        for role_id in role_ids:
            self.http.post(f"{access}/memberships/{member['id']}/roles", bearer=op, json_body={
                "roleId": role_id, "assignmentSource": "cookbook"}).expect(200)
        return member

    # ---------------------------------------------------------------------------------------- workload identities
    def workload(self, op: Secret, client: Client, suffix: str) -> dict:
        """Registers a confidential client as a workload identity (Axiom's existing path name is historical:
        ``/ciam/agent-workloads``; Axiom treats the record as a generic workload)."""
        w = self.http.post(f"{self.admin_base()}/ciam/agent-workloads", bearer=op, json_body={
            "workloadRef": f"workload:{self.name(suffix)}", "name": self.name(suffix),
            "oauthClientId": client.client_id}).expect(201).json()
        self.registry.add("workload", w["id"], lambda: self.http.post(
            f"{self.admin_base()}/ciam/agent-workloads/{w['id']}/retire", bearer=self.operator(),
            json_body={"reason": "cookbook cleanup"}), "retire (terminal)")
        return w

    def broker(self, op: Secret, client: Client, audience: str, scopes: list[str]) -> dict:
        b = self.http.post(f"{self.admin_base()}/agent-exchange/brokers", bearer=op, json_body={
            "oauthClientId": client.client_id, "gatewayAudience": audience, "scopes": scopes}).expect(201).json()
        self.registry.add("exchange intermediary", b["id"], lambda: self.http.post(
            f"{self.admin_base()}/agent-exchange/brokers/{b['id']}/revoke", bearer=self.operator()), "revoke")
        return b

    def route(self, op: Secret, source_workload: str, destination_type: str, audience: str, scopes: list[str],
              destination_workload: str | None = None, ttl_seconds: int = 3600) -> dict:
        import datetime as dt
        body = {"sourceWorkloadId": source_workload, "destinationType": destination_type, "audience": audience,
                "scopes": scopes, "purpose": "cookbook exchange edge",
                "expiresAt": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ttl_seconds)).isoformat()}
        if destination_workload:
            body["destinationWorkloadId"] = destination_workload
        r = self.http.post(f"{self.admin_base()}/agent-exchange/routes", bearer=op, json_body=body).expect(201).json()
        self.registry.add("exchange edge", r["id"], lambda: self.http.post(
            f"{self.admin_base()}/agent-exchange/routes/{r['id']}/revoke", bearer=self.operator()), "revoke")
        return r

    def team(self, op: Secret, suffix: str) -> dict:
        t = self.http.post("/teams", bearer=op, json_body={"name": self.name(suffix)}).expect(201).json()
        self.registry.add("team", t["id"], lambda: self.http.delete(f"/teams/{t['id']}", bearer=self.operator()),
                          "delete")
        return t
