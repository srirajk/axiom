#!/usr/bin/env python3
"""Verify the reviewed Argus quickstart identity graph against a running Axiom."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import time
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("axiom_exchange_common", ROOT / "verify-argus-agent-exchange.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Axiom exchange verification helpers")
COMMON = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMMON
SPEC.loader.exec_module(COMMON)

SCOPE = "quickstart:invoke"
AUDIENCES = {
    "entry": "agent:meridian:quickstart-entry",
    "agent": "agent:meridian:quickstart-agent",
    "tool": "tool:meridian:quickstart-tool",
    "mcp": "tool:meridian:quickstart-mcp",
    "gateway": "argus-gateway",
    "wrong": "agent:meridian:quickstart-wrong-audience",
    "service": "agent:meridian:quickstart-service",
    "worker": "agent:meridian:quickstart-worker-agent",
    "task": "agent:meridian:quickstart-task-agent",
}
REFERENCES = {
    "entry": "agent:quickstart-entry:development",
    "agent": "agent:quickstart-agent:development",
    "service": "agent:quickstart-service:development",
    "worker": "agent:quickstart-worker-agent:development",
    "task": "agent:quickstart-task-agent:development",
}
SECRETS = {
    "quickstart-entry": ("quickstart", "quickstart-entry-workload-oauth-client"),
    "quickstart-agent": ("quickstart", "quickstart-agent-workload-oauth-client"),
    "quickstart-wrong-audience": ("quickstart", "quickstart-wrong-audience-oauth-client"),
    "quickstart-service": ("quickstart", "quickstart-service-workload-oauth-client"),
    "quickstart-worker-agent": ("quickstart", "quickstart-worker-agent-workload-oauth-client"),
    "quickstart-task-agent": ("quickstart", "quickstart-task-agent-workload-oauth-client"),
    "argus-gateway-broker": ("argus-system", "argus-gateway-agent-exchange-oauth-client"),
}


def main() -> int:
    base = os.environ.get("AXIOM_BASE_URL", "http://127.0.0.1:8180").rstrip("/")
    issuer = os.environ.get("AXIOM_ISSUER", "https://identity.meridian.com:8443").rstrip("/")
    credentials = {
        client: COMMON.kubernetes_secret_value(namespace, name, "client_secret")
        for client, (namespace, name) in SECRETS.items()
    }

    def mint(client: str) -> str:
        response = COMMON.request(
            base + "/oauth/token", method="POST",
            form={"grant_type": "client_credentials", "scope": SCOPE},
            basic=(client, credentials[client]),
        )
        COMMON.expect(response.status == 200,
                      f"{client} client_credentials HTTP {response.status}: {COMMON.oauth_error(response)}")
        return str(response.json()["access_token"])

    def exchange(subject: str, client: str, audience: str, expected_status: int = 200) -> str:
        response = COMMON.request(
            base + "/oauth/token", method="POST",
            form={
                "grant_type": COMMON.TOKEN_EXCHANGE,
                "subject_token": subject,
                "subject_token_type": COMMON.ACCESS_TOKEN,
                "requested_token_type": COMMON.ACCESS_TOKEN,
                "audience": audience,
                "scope": SCOPE,
            },
            basic=(client, credentials[client]),
        )
        COMMON.expect(response.status == expected_status,
                      f"{client} exchange to {audience} HTTP {response.status}: {COMMON.oauth_error(response)}")
        return str(response.json()["access_token"]) if expected_status == 200 else COMMON.oauth_error(response)

    def check(label: str, token: str, audience: str, requester: str,
              token_use: str | None, actor: str | None, subject: str = "quickstart-entry") -> dict[str, Any]:
        COMMON.verify_signature(base, token)
        claims = COMMON.jwt_claims(token)
        COMMON.expect(claims.get("iss") == issuer, f"{label} issuer mismatch")
        COMMON.expect(claims.get("tenant_id") == "meridian", f"{label} tenant mismatch")
        COMMON.expect(COMMON.audiences(claims) == {audience}, f"{label} audience mismatch")
        COMMON.expect(SCOPE in COMMON.scopes(claims), f"{label} scope mismatch")
        COMMON.expect(claims.get("sub") == subject, f"{label} subject mismatch")
        COMMON.expect(claims.get("client_id") == requester, f"{label} requester mismatch")
        COMMON.expect(int(claims.get("exp", 0)) > time.time(), f"{label} expired")
        if token_use is None:
            COMMON.expect(claims.get("identity_kind") == "workload" and "act" not in claims,
                          f"{label} is not an original workload token")
        else:
            COMMON.expect(claims.get("token_use") == token_use, f"{label} token use mismatch")
            COMMON.expect(isinstance(claims.get("act"), dict)
                          and claims["act"].get("sub") == actor, f"{label} actor mismatch")
            COMMON.expect(bool(claims.get("authority_id")), f"{label} authority is absent")
            COMMON.expect(int(claims["exp"]) - int(claims["iat"]) <= 300,
                          f"{label} exchange lifetime exceeds five minutes")
        print(f"PASS {label}: aud={audience}, subject={subject}, actor={actor or 'none'}")
        return claims

    admin_password = COMMON.required("AXIOM_ADMIN_PASSWORD")
    login = COMMON.request(base + "/auth/login", method="POST",
                           json_body={"username": "admin", "password": admin_password})
    COMMON.expect(login.status == 200, f"administrator login HTTP {login.status}")
    broker_response = COMMON.request(base + "/admin/tenants/meridian/agent-exchange/brokers",
                                     headers={"Authorization": "Bearer " + login.json()["accessToken"]})
    COMMON.expect(broker_response.status == 200, f"broker inventory HTTP {broker_response.status}")
    brokers = [item for item in broker_response.json() if item.get("status") == "ACTIVE"]
    COMMON.expect(len(brokers) == 1 and brokers[0].get("oauthClientId") == "argus-gateway-broker"
                  and SCOPE in set(brokers[0].get("scopes", [])), "Gateway broker lacks reviewed quickstart scope")
    print("PASS broker inventory: one active broker with quickstart scope")

    entry = mint("quickstart-entry")
    check("entry client credentials", entry, AUDIENCES["entry"], "quickstart-entry", None, None)
    gateway = exchange(entry, "quickstart-entry", AUDIENCES["gateway"])
    check("entry to Gateway", gateway, AUDIENCES["gateway"], "quickstart-entry",
          "gateway_authorization", REFERENCES["entry"])
    agent = exchange(gateway, "argus-gateway-broker", AUDIENCES["agent"])
    check("Gateway to Agent", agent, AUDIENCES["agent"], "argus-gateway-broker",
          "exchange_subject", REFERENCES["entry"])
    agent_gateway = exchange(agent, "quickstart-agent", AUDIENCES["gateway"])
    check("Agent to Gateway", agent_gateway, AUDIENCES["gateway"], "quickstart-agent",
          "gateway_authorization", REFERENCES["agent"])
    tool = exchange(agent_gateway, "argus-gateway-broker", AUDIENCES["tool"])
    check("Gateway to tool", tool, AUDIENCES["tool"], "argus-gateway-broker",
          "delegated_access", REFERENCES["agent"])
    mcp = exchange(agent_gateway, "argus-gateway-broker", AUDIENCES["mcp"])
    check("Gateway to MCP Server", mcp, AUDIENCES["mcp"], "argus-gateway-broker",
          "delegated_access", REFERENCES["agent"])
    direct_tool = exchange(gateway, "argus-gateway-broker", AUDIENCES["tool"])
    check("entry to tool", direct_tool, AUDIENCES["tool"], "argus-gateway-broker",
          "delegated_access", REFERENCES["entry"])
    direct_mcp_denial = exchange(gateway, "argus-gateway-broker", AUDIENCES["mcp"], 400)
    COMMON.expect(direct_mcp_denial in {"invalid_target", "invalid_grant"},
                  "entry workload bypassed the Agent for MCP access")
    print("PASS entry workload cannot bypass the Agent for MCP access")
    wrong = mint("quickstart-wrong-audience")
    check("wrong-audience client", wrong, AUDIENCES["wrong"], "quickstart-wrong-audience",
          None, None, subject="quickstart-wrong-audience")
    denial = exchange(gateway, "argus-gateway-broker", "agent:meridian:wealth-orchestrator", 400)
    COMMON.expect(denial in {"invalid_target", "invalid_grant"}, "unreviewed route did not fail closed")
    print("PASS unreviewed cross-use-case route denied")

    service = mint("quickstart-service")
    check("service client credentials", service, AUDIENCES["service"], "quickstart-service",
          None, None, subject="quickstart-service")
    service_gateway = exchange(service, "quickstart-service", AUDIENCES["gateway"])
    check("service to Gateway", service_gateway, AUDIENCES["gateway"], "quickstart-service",
          "gateway_authorization", REFERENCES["service"], subject="quickstart-service")
    service_agent = exchange(service_gateway, "argus-gateway-broker", AUDIENCES["agent"])
    check("Gateway to existing quickstart Agent", service_agent, AUDIENCES["agent"], "argus-gateway-broker",
          "exchange_subject", REFERENCES["service"], subject="quickstart-service")
    service_agent_gateway = exchange(service_agent, "quickstart-agent", AUDIENCES["gateway"])
    check("existing quickstart Agent to Gateway", service_agent_gateway, AUDIENCES["gateway"], "quickstart-agent",
          "gateway_authorization", REFERENCES["agent"], subject="quickstart-service")
    service_direct_tool = exchange(service_agent_gateway, "argus-gateway-broker", AUDIENCES["tool"])
    check("Gateway to tool from existing quickstart Agent", service_direct_tool, AUDIENCES["tool"],
          "argus-gateway-broker", "delegated_access", REFERENCES["agent"], subject="quickstart-service")

    worker = mint("quickstart-worker-agent")
    check("Worker Agent client credentials", worker, AUDIENCES["worker"], "quickstart-worker-agent",
          None, None, subject="quickstart-worker-agent")
    worker_gateway = exchange(worker, "quickstart-worker-agent", AUDIENCES["gateway"])
    check("Worker Agent to Gateway", worker_gateway, AUDIENCES["gateway"], "quickstart-worker-agent",
          "gateway_authorization", REFERENCES["worker"], subject="quickstart-worker-agent")
    task = exchange(worker_gateway, "argus-gateway-broker", AUDIENCES["task"])
    check("Gateway to Task Agent", task, AUDIENCES["task"], "argus-gateway-broker",
          "exchange_subject", REFERENCES["worker"], subject="quickstart-worker-agent")
    task_gateway = exchange(task, "quickstart-task-agent", AUDIENCES["gateway"])
    check("Task Agent to Gateway", task_gateway, AUDIENCES["gateway"], "quickstart-task-agent",
          "gateway_authorization", REFERENCES["task"], subject="quickstart-worker-agent")
    service_tool = exchange(task_gateway, "argus-gateway-broker", AUDIENCES["tool"])
    check("Gateway to tool from Task Agent", service_tool, AUDIENCES["tool"], "argus-gateway-broker",
          "delegated_access", REFERENCES["task"], subject="quickstart-worker-agent")
    skipped_agent = exchange(service_gateway, "argus-gateway-broker", AUDIENCES["task"], 400)
    COMMON.expect(skipped_agent in {"invalid_target", "invalid_grant"},
                  "service bypassed the approved quickstart Agent")
    print("PASS service cannot jump directly to the Task Agent")
    print("AXIOM QUICKSTART EXCHANGE PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print("AXIOM QUICKSTART EXCHANGE FAIL: " + COMMON.safe_error(error), file=sys.stderr)
        raise SystemExit(1) from None
