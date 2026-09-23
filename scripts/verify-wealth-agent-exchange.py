#!/usr/bin/env python3
"""Functional proof for the Meridian Wealth workforce and Agent exchange graph."""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import importlib.util
import json
import os
import pathlib
import secrets
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "axiom_argus_exchange_harness", HERE / "verify-argus-agent-exchange.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the shared Argus exchange harness")
COMMON = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMMON
SPEC.loader.exec_module(COMMON)

SCOPE = "wealth:review.invoke"
TOKEN_EXCHANGE = COMMON.TOKEN_EXCHANGE
ACCESS_TOKEN = COMMON.ACCESS_TOKEN


class WealthCallbackRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if newurl.startswith("http://localhost:9970/callback"):
            raise COMMON.RedirectCaptured(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class WealthVerifier(COMMON.Verifier):
    def __init__(self) -> None:
        self.base_url = os.environ.get("AXIOM_BASE_URL", "http://127.0.0.1:8180").rstrip("/")
        self.issuer = os.environ.get(
            "AXIOM_ISSUER", "https://identity.meridian.com:8443"
        ).rstrip("/")
        self.tenant = os.environ.get("AXIOM_TENANT_ID", "meridian")
        self.username = os.environ.get("AXIOM_WEALTH_USERNAME", "rm_jane")
        self.password = COMMON.required("AXIOM_SEED_USER_PASSWORD")
        self.admin_password = COMMON.required("AXIOM_ADMIN_PASSWORD")
        self.public_client = "wealth-review-web"
        self.gateway_client = "argus-gateway-broker"
        self.gateway_audience = "argus-gateway"
        self.entry = "wealth-entry-agent"
        self.orchestrator = "wealth-orchestrator"
        self.holdings = "wealth-holdings-agent"
        self.market = "wealth-market-agent"
        self.suitability = "wealth-suitability-agent"
        self.drafting = "wealth-drafting-agent"
        self.decision = "wealth-decision-agent"
        self.reports = "wealth-reports-agent"
        self.refs = {
            name: f"agent:{name}:development"
            for name in (
                self.entry, self.orchestrator, self.holdings, self.market,
                self.suitability, self.drafting, self.decision, self.reports,
            )
        }
        self.audiences = {
            name: f"agent:meridian:{name}"
            for name in self.refs
        }
        self.holdings_tool = "tool:meridian:wealth-holdings-tool"
        self.model = "model:meridian:wealth-review-model"
        self.secrets = self.load_wealth_secrets()
        self.tokens: list[str] = []
        self.failures: list[str] = []
        self.admin_token = ""
        self.workforce_token = ""
        self.entry_subject = ""
        self.entry_gateway = ""
        self.orchestrator_subject = ""
        self.orchestrator_gateway = ""
        self.holdings_subject = ""
        self.holdings_gateway = ""

    def load_wealth_secrets(self) -> dict[str, str]:
        names = {
            self.entry: "wealth-entry-agent-axiom-oauth-client",
            self.orchestrator: "wealth-orchestrator-workload-oauth-client",
            self.holdings: "wealth-holdings-agent-workload-oauth-client",
            self.market: "wealth-market-agent-workload-oauth-client",
            self.suitability: "wealth-suitability-agent-workload-oauth-client",
            self.drafting: "wealth-drafting-agent-workload-oauth-client",
            self.decision: "wealth-decision-agent-workload-oauth-client",
            self.reports: "wealth-reports-agent-workload-oauth-client",
        }
        values = {
            client: COMMON.kubernetes_secret_value("wealth", name, "client_secret")
            for client, name in names.items()
        }
        values[self.gateway_client] = COMMON.kubernetes_secret_value(
            "argus-system", "argus-gateway-agent-exchange-oauth-client", "client_secret"
        )
        return values

    def run(self) -> int:
        self.act("health-and-protocol-discovery", self.health)
        self.act("reviewed-wealth-authority-inventory", self.authority_inventory)
        self.act("wealth-workforce-pkce-authentication", self.workforce_authentication)
        self.act("workforce-to-entry-agent", self.workforce_to_entry)
        self.act("entry-agent-to-gateway", self.entry_to_gateway)
        self.act("gateway-to-orchestrator", self.gateway_to_orchestrator)
        self.act("orchestrator-to-gateway", self.orchestrator_to_gateway)
        self.act("orchestrator-reviewed-fanout", self.orchestrator_fanout)
        self.act("holdings-agent-to-resource", self.holdings_to_resource)
        self.act("negative-authority", self.negative_authority)
        if os.environ.get("AXIOM_WEALTH_VERIFY_REVOCATION") == "1":
            self.act("route-revocation", self.route_revocation)
        self.act("audit-and-secrecy", self.audit_and_secrecy)
        if self.failures:
            print(f"RESULT FAIL ({len(self.failures)} Wealth functional act(s))")
            return 1
        print("RESULT PASS (workforce -> Wealth Entry Agent -> Argus Gateway -> Wealth Orchestrator -> specialist -> resource)")
        return 0

    def authority_inventory(self) -> str:
        login = COMMON.request(
            self.base_url + "/auth/login", method="POST",
            json_body={"username": "admin", "password": self.admin_password},
        )
        COMMON.expect(login.status == 200, f"administrator login HTTP {login.status}")
        self.admin_token = str(login.json()["accessToken"])
        brokers = self.admin_get(f"/admin/tenants/{self.tenant}/agent-exchange/brokers")
        workloads = self.admin_get(f"/admin/tenants/{self.tenant}/ciam/agent-workloads")
        routes = self.admin_get(f"/admin/tenants/{self.tenant}/agent-exchange/routes")
        active_brokers = [item for item in brokers if item.get("status") == "ACTIVE"]
        COMMON.expect(len(active_brokers) == 1, "expected one active physical Gateway broker")
        broker = active_brokers[0]
        COMMON.expect(broker.get("oauthClientId") == self.gateway_client, "unexpected Gateway broker")
        COMMON.expect(SCOPE in set(broker.get("scopes", [])), "Gateway broker lacks Wealth scope")

        wealth_workloads = {
            item["id"]: item["workloadRef"]
            for item in workloads
            if str(item.get("workloadRef", "")).startswith("agent:wealth-")
        }
        COMMON.expect(set(wealth_workloads.values()) == set(self.refs.values()),
                      "Wealth workload inventory differs from the reviewed eight-workload contract")
        wealth_routes = [
            item for item in routes
            if item.get("status") == "ACTIVE" and SCOPE in set(item.get("scopes", []))
        ]
        actual = {
            (
                wealth_workloads.get(item.get("sourceWorkloadId")),
                str(item.get("destinationType")),
                str(item.get("audience")),
                wealth_workloads.get(item.get("destinationWorkloadId")),
            )
            for item in wealth_routes
        }
        expected = self.expected_routes()
        COMMON.expect(len(wealth_routes) == len(expected) == 20 and actual == expected,
                      "Wealth route inventory differs from the reviewed twenty-route contract")
        return "one physical Gateway broker, eight workloads, and twenty least-authority routes match"

    def expected_routes(self) -> set[tuple[str | None, str, str, str | None]]:
        result: set[tuple[str | None, str, str, str | None]] = set()
        for name in self.refs:
            result.add((self.refs[name], "GATEWAY", self.gateway_audience, None))
        for source, destination in (
            (self.entry, self.orchestrator),
            (self.orchestrator, self.holdings),
            (self.orchestrator, self.market),
            (self.orchestrator, self.suitability),
            (self.orchestrator, self.drafting),
        ):
            result.add((self.refs[source], "AGENT", self.audiences[destination], self.refs[destination]))
        for source, audience in (
            (self.holdings, self.holdings_tool),
            (self.holdings, self.model),
            (self.market, "tool:meridian:wealth-market-tool"),
            (self.market, self.model),
            (self.suitability, self.model),
            (self.drafting, self.model),
            (self.decision, self.model),
        ):
            result.add((self.refs[source], "RESOURCE", audience, None))
        return result

    def workforce_authentication(self) -> str:
        verifier = secrets.token_urlsafe(48)
        challenge = COMMON.b64url(hashlib.sha256(verifier.encode()).digest())
        state = secrets.token_urlsafe(24)
        redirect_uri = "http://localhost:9970/callback"
        params = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": self.public_client,
            "redirect_uri": redirect_uri,
            "scope": f"openid profile email {SCOPE}",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            WealthCallbackRedirectHandler(),
        )
        login_page = opener.open(self.base_url + "/oauth/authorize?" + params, timeout=30)
        csrf = COMMON.hidden_input(login_page.read().decode(), "_csrf")
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
        except COMMON.RedirectCaptured as callback:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(callback.location).query)
        COMMON.expect(query.get("state") == [state], "OIDC state mismatch")
        COMMON.expect(len(query.get("code", [])) == 1, "authorization code is absent")
        token = COMMON.request(
            self.base_url + "/oauth/token", method="POST",
            form={
                "grant_type": "authorization_code",
                "client_id": self.public_client,
                "code": query["code"][0],
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        COMMON.expect(token.status == 200, f"authorization-code redemption HTTP {token.status}")
        self.workforce_token = str(token.json()["access_token"])
        self.tokens.append(self.workforce_token)
        claims = self.validate(
            self.workforce_token, audience=self.audiences[self.entry], profile=None,
            token_use=None, actor_ref=None, client_id=self.public_client,
        )
        COMMON.expect(claims.get("identity_kind") == "workforce", "workforce identity kind is absent")
        COMMON.expect(claims.get("sub") == "rm_jane", "unexpected workforce subject")
        COMMON.expect("wealth-review-relationship-manager" in set(claims.get("roles", [])),
                      "Wealth application role is absent")
        return "rm_jane received an application-scoped S256 PKCE token without a confidential secret"

    def workforce_to_entry(self) -> str:
        self.entry_subject = self.exchange(
            self.workforce_token, self.entry, self.audiences[self.entry]
        )
        self.validate(self.entry_subject, audience=self.audiences[self.entry], profile="workforce",
                      token_use="exchange_subject", actor_ref=self.refs[self.entry], client_id=self.entry)
        return "server-side Wealth Entry Agent became the first business actor"

    def entry_to_gateway(self) -> str:
        self.entry_gateway = self.exchange(self.entry_subject, self.entry, self.gateway_audience)
        self.validate(self.entry_gateway, audience=self.gateway_audience,
                      profile="workload_continuation", token_use="gateway_authorization",
                      actor_ref=self.refs[self.entry], client_id=self.entry)
        return "Wealth Entry Agent obtained only its reviewed Gateway authorization"

    def gateway_to_orchestrator(self) -> str:
        self.orchestrator_subject = self.exchange(
            self.entry_gateway, self.gateway_client, self.audiences[self.orchestrator]
        )
        self.validate(self.orchestrator_subject, audience=self.audiences[self.orchestrator],
                      profile="gateway_backend", token_use="exchange_subject",
                      actor_ref=self.refs[self.entry], client_id=self.gateway_client)
        return "Gateway continued the original workforce subject to the exact Orchestrator"

    def orchestrator_to_gateway(self) -> str:
        self.orchestrator_gateway = self.exchange(
            self.orchestrator_subject, self.orchestrator, self.gateway_audience
        )
        self.validate(self.orchestrator_gateway, audience=self.gateway_audience,
                      profile="workload_continuation", token_use="gateway_authorization",
                      actor_ref=self.refs[self.orchestrator], client_id=self.orchestrator)
        return "Orchestrator became the current actor without changing rm_jane"

    def orchestrator_fanout(self) -> str:
        subjects: dict[str, str] = {}
        for destination in (self.holdings, self.market, self.suitability, self.drafting):
            token = self.exchange(
                self.orchestrator_gateway, self.gateway_client, self.audiences[destination]
            )
            self.validate(token, audience=self.audiences[destination], profile="gateway_backend",
                          token_use="exchange_subject", actor_ref=self.refs[self.orchestrator],
                          client_id=self.gateway_client)
            subjects[destination] = token
        self.holdings_subject = subjects[self.holdings]
        return "only Holdings, Market, Suitability, and Drafting receive delegated Orchestrator work"

    def holdings_to_resource(self) -> str:
        self.holdings_gateway = self.exchange(
            self.holdings_subject, self.holdings, self.gateway_audience
        )
        self.validate(self.holdings_gateway, audience=self.gateway_audience,
                      profile="workload_continuation", token_use="gateway_authorization",
                      actor_ref=self.refs[self.holdings], client_id=self.holdings)
        resource = self.exchange(self.holdings_gateway, self.gateway_client, self.holdings_tool)
        self.validate(resource, audience=self.holdings_tool, profile="gateway_backend",
                      token_use="delegated_access", actor_ref=self.refs[self.holdings],
                      client_id=self.gateway_client)
        return "Holdings Agent reached only its approved holdings resource with the preserved subject"

    def negative_authority(self) -> str:
        wrong_entry_route = self.exchange_response(
            self.entry_gateway, self.gateway_client, self.audiences[self.holdings]
        )
        COMMON.expect(wrong_entry_route.status == 400, "Entry Agent reached an unapproved specialist")
        self_route = self.exchange_response(
            self.orchestrator_gateway, self.gateway_client, self.audiences[self.orchestrator]
        )
        COMMON.expect(self_route.status == 400, "artificial Orchestrator self-route was accepted")
        false_decision = self.exchange_response(
            self.orchestrator_gateway, self.gateway_client, self.audiences[self.decision]
        )
        COMMON.expect(false_decision.status == 400, "unreviewed Decision Agent edge was accepted")
        sibling = self.exchange_response(
            self.holdings_subject, self.market, self.gateway_audience
        )
        COMMON.expect(sibling.status == 400, "sibling workload replay was accepted")
        excessive = self.exchange_response(
            self.holdings_gateway, self.gateway_client, self.holdings_tool,
            scope="axiom.application.read",
        )
        COMMON.expect(excessive.status == 400, "administrative scope escalation was accepted")
        supplied = self.exchange_response(
            self.holdings_gateway, self.gateway_client, self.holdings_tool,
            extra={"actor_token": self.workforce_token},
        )
        COMMON.expect(supplied.status == 400, "caller-supplied actor authority was accepted")
        return "wrong route, self-route, false edge, sibling replay, scope escalation, and actor injection fail closed"

    def route_revocation(self) -> str:
        gateway = self.exchange(self.holdings_subject, self.holdings, self.gateway_audience)
        routes = self.admin_get(f"/admin/tenants/{self.tenant}/agent-exchange/routes")
        workloads = self.admin_get(f"/admin/tenants/{self.tenant}/ciam/agent-workloads")
        holdings_id = next(item["id"] for item in workloads if item.get("workloadRef") == self.refs[self.holdings])
        matches = [
            item for item in routes
            if item.get("status") == "ACTIVE"
            and item.get("sourceWorkloadId") == holdings_id
            and item.get("destinationType") == "GATEWAY"
            and item.get("audience") == self.gateway_audience
        ]
        COMMON.expect(len(matches) == 1, "Holdings Agent Gateway route is not unique")
        revoked = COMMON.request(
            self.base_url + f"/admin/tenants/{self.tenant}/agent-exchange/routes/{matches[0]['id']}/revoke",
            method="POST", headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        COMMON.expect(revoked.status == 200, f"route revocation HTTP {revoked.status}")
        denied = self.exchange_response(self.holdings_subject, self.holdings, self.gateway_audience)
        COMMON.expect(denied.status == 400, "revoked route still minted Gateway authority")
        COMMON.expect(bool(gateway), "pre-revocation exchange proof is absent")
        return "route revocation immediately prevents a new exchange; republish to restore reviewed state"

    def client_credentials(self, client_id: str) -> str:
        response = COMMON.request(
            self.base_url + "/oauth/token", method="POST",
            form={"grant_type": "client_credentials", "scope": SCOPE},
            basic=(client_id, self.secrets[client_id]),
        )
        COMMON.expect(response.status == 200, f"client credentials HTTP {response.status}")
        token = str(response.json()["access_token"])
        self.tokens.append(token)
        return token

    def exchange_response(self, subject: str, client_id: str, audience: str, *,
                          scope: str = SCOPE, extra: dict[str, str] | None = None) -> Any:
        form = {
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": subject,
            "subject_token_type": ACCESS_TOKEN,
            "requested_token_type": ACCESS_TOKEN,
            "audience": audience,
            "scope": scope,
        }
        form.update(extra or {})
        return COMMON.request(
            self.base_url + "/oauth/token", method="POST", form=form,
            basic=(client_id, self.secrets[client_id]),
        )

    def validate(self, token: str, *, audience: str, profile: str | None,
                 token_use: str | None, actor_ref: str | None, client_id: str) -> dict[str, Any]:
        COMMON.verify_signature(self.base_url, token)
        claims = COMMON.jwt_claims(token)
        COMMON.expect(claims.get("iss") == self.issuer, "token issuer mismatch")
        COMMON.expect(claims.get("tenant_id") == self.tenant, "token tenant mismatch")
        COMMON.expect(COMMON.audiences(claims) == {audience}, "token audience is not exact")
        COMMON.expect(SCOPE in COMMON.scopes(claims), "Wealth business scope is absent")
        COMMON.expect(claims.get("client_id") == client_id, "requesting client claim mismatch")
        COMMON.expect(claims.get("sub") == "rm_jane", "original workforce subject changed")
        COMMON.expect(int(claims.get("exp", 0)) > int(time.time()), "token is expired")
        if profile is None:
            COMMON.expect("act" not in claims, "initial workforce token contains an actor")
            return claims
        COMMON.expect(claims.get("authority_profile") == profile, "authority profile mismatch")
        COMMON.expect(claims.get("token_use") == token_use, "token use mismatch")
        COMMON.expect(bool(claims.get("authority_id")), "authority id is absent")
        actor = claims.get("act")
        COMMON.expect(isinstance(actor, dict), "structured actor is absent")
        COMMON.expect(actor.get("sub") == actor_ref, "actor workload reference mismatch")
        COMMON.expect(bool(actor.get("client_id")), "actor OAuth client is absent")
        COMMON.expect(bool(actor.get("workload_id")), "actor workload id is absent")
        COMMON.expect(int(claims["exp"]) - int(claims["iat"]) <= 300,
                      "exchange token lifetime exceeds five minutes")
        return claims


if __name__ == "__main__":
    raise SystemExit(WealthVerifier().run())
