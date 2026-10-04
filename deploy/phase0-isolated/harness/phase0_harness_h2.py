#!/opt/homebrew/bin/python3.13
"""Phase 0.2 H-2 isolated human PKCE login and BFF -> Gateway -> Agent -> resource exchange harness.

Implements package H-2 of docs/operations/phase-0.2-test-harness-design.md §8 on top of the reviewed H-1 module
``phase0_harness.py``, which is imported unchanged (constants, command builder, redaction, JWT helpers, URL guard,
port selection, V-1..V-10, port-forward lifecycle, cleanup re-login and exit-code semantics).

Usage:
    /opt/homebrew/bin/python3.13 -I -B phase0_harness_h2.py --package h2            # plan only (no subprocess/network)
    /opt/homebrew/bin/python3.13 -I -B phase0_harness_h2.py --package h2 --execute  # actually run

Output is JSON Lines on stdout only; every event name carries the ``h2_`` prefix and ``"package": "H-2"``.
Exit code: 0 all fifteen cases passed and nothing needs attention; 1 any case failed; 2 abort, redaction
violation, incomplete cleanup or a leaked port-forward.

All expected values live in ``H2_EXPECTATIONS`` (one data-driven table); evaluators are generic.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import importlib.util
import json
import os
import re
import secrets
import signal
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

# ---------------------------------------------------------------------------------------------------------------------
# H-1 import. Under ``-I`` the script directory is not on sys.path, so the sibling file is loaded by its fixed path.
# A module of the same name from any other location is refused.
# ---------------------------------------------------------------------------------------------------------------------

_H1_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase0_harness.py")
# SHA-256 of the reviewed and executed H-1 harness. H-2 refuses to load any other version of it.
H1_SHA256 = "10ffb18b65e09ffc66439583ae299ee0ac10a7aa724d398e4aedee342aa3eebc"


def _load_h1() -> Any:
    existing = sys.modules.get("phase0_harness")
    if existing is not None:
        if os.path.realpath(getattr(existing, "__file__", "") or "") != os.path.realpath(_H1_PATH):
            raise ImportError("phase0_harness already imported from an unexpected location")
        return existing
    with open(_H1_PATH, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != H1_SHA256:
            raise ImportError("phase0_harness.py does not match the reviewed H-1 digest")
    spec = importlib.util.spec_from_file_location("phase0_harness", _H1_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load phase0_harness.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["phase0_harness"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("phase0_harness", None)
        raise
    return module


h1 = _load_h1()

AbortRun = h1.AbortRun
HarnessError = h1.HarnessError
SensitiveValue = h1.SensitiveValue
Redactor = h1.Redactor
CONTEXT = h1.CONTEXT
NAMESPACE = h1.NAMESPACE
TENANT = h1.TENANT
SCOPE = h1.SCOPE
EXTRA_SCOPE = h1.EXTRA_SCOPE
EXPECTED_ISSUER = h1.EXPECTED_ISSUER
TOKEN_EXCHANGE_GRANT = h1.TOKEN_EXCHANGE_GRANT
ACCESS_TOKEN_TYPE = h1.ACCESS_TOKEN_TYPE
HTTP_TIMEOUT = h1.HTTP_TIMEOUT
SAFE_ID = h1.SAFE_ID
EXCHANGE_MAX_LIFETIME = h1.EXCHANGE_MAX_LIFETIME
CLOCK_SKEW = h1.CLOCK_SKEW

# ---------------------------------------------------------------------------------------------------------------------
# H-2 constants
# ---------------------------------------------------------------------------------------------------------------------

PACKAGE = "H-2"
EVENT_PREFIX = "h2_"
DESCRIPTION = "phase0 H-2 isolated test"
ROUTE_PURPOSE = "phase0 H-2 isolated test"
ASSIGNMENT_SOURCE = "phase0-h2-test"
REDIRECT_URI = "http://127.0.0.1:9/callback"
HUMAN_SCOPES = ("openid", "profile", SCOPE)
HUMAN_SCOPE = " ".join(HUMAN_SCOPES)
EMAIL_DOMAIN = "phase0.invalid"
# Whether the tool application also needs a confidential client (decided by the contract check).
TOOL_NEEDS_CLIENT = False
MAX_REDIRECT_HOPS = 5
REDIRECT_STATUSES = (301, 302, 303, 307, 308)
EXPECTED_ENTITLEMENT_REVISION = 2
# Only these Axiom paths may be rewritten onto the forwarded base when a Location names another host.
KNOWN_REWRITE_PATHS = ("/oauth/authorize", "/login")
H2_ALLOWED_CLAIMS = tuple(h1.ALLOWED_CLAIMS) + ("roles", "workload_id")

APP_ROLES = ("bff", "gateway", "agent", "tool", "sibling")
WORKLOAD_ROLES = ("bff", "agent", "sibling")
ROUTE_KEYS = ("R1", "R2", "R3", "R4")
USER_ROLES = ("user", "nomember")

# ---------------------------------------------------------------------------------------------------------------------
# Expectation table (single source of truth; placeholders ``{name}`` are resolved from the run's variables)
# ---------------------------------------------------------------------------------------------------------------------
# Check kinds:
#   ("status", int)                       HTTP status
#   ("token_type", str)                   response token_type, case-insensitive
#   ("issued_token_type", str)            response issued_token_type
#   ("header", name, value)               JWT header field equality
#   ("claim", name, value)                claim equality
#   ("claim_startswith", name, prefix)    claim is a string with this prefix
#   ("claim_present", name)               claim present and non-empty
#   ("aud", [values])                     normalised aud list equality
#   ("act", name, value)                  act.<name> equality
#   ("act_ne", name, value)               act.<name> must differ
#   ("act_not_contains", name, text)      act.<name> must not contain text
#   ("roles_contains", value)             roles claim contains value
#   ("scope_eq", [values]) / ("scope_superset", [values])
#   ("exp_bound", previous_case_id)       exp <= min(previous exp, request_time + 300 + 5)
#   ("claim_absent", name)                claim must not be present
#   ("roles_eq", [values])                roles claim equals exactly this set
#   ("sid_new", [case_ids])               sid present and different from the sid of every listed case
#   ("lifetime_max", seconds)             0 < exp - iat <= seconds
#   ("response_authority_eq_claim",)      response authority_id equals the token's authority_id claim

EXCHANGE_COMMON = [
    ("issued_token_type", ACCESS_TOKEN_TYPE),
    ("claim", "iss", "{issuer}"),
    ("claim", "tenant_id", "{tenant}"),
    ("claim", "identity_kind", "workforce"),
    ("claim_absent", "roles"),
    ("scope_eq", [SCOPE]),
    ("lifetime_max", EXCHANGE_MAX_LIFETIME),
    ("response_authority_eq_claim",),
]

H2_EXPECTATIONS: dict = {
    "order": ["H2-P1", "H2-N1", "H2-N2", "H2-N3", "H2-P2", "H2-N4", "H2-N5", "H2-N6", "H2-N7", "H2-P3",
              "H2-N8", "H2-P4", "H2-P5", "H2-N9", "H2-P6"],
    "cases": {
        "H2-P1": {
            "class": "positive", "kind": "pkce_login", "user": "user", "depends": [],
            "description": "<p>-user PKCE login + code redemption: 200 Bearer; typ at+jwt; iss; sub=<p>-user; "
                           "aud=[bff aud]; client_id=<p>-human-web; identity_kind=workforce; tenant_id; sid; "
                           "roles contains <p>-operator; scope contains quickstart:invoke",
            "checks": [
                ("status", 200), ("token_type", "Bearer"), ("header", "typ", "at+jwt"),
                ("claim", "iss", "{issuer}"), ("claim", "sub", "{user}"), ("aud", ["{bff_aud}"]),
                ("claim", "client_id", "{human_client}"), ("claim", "identity_kind", "workforce"),
                ("claim", "tenant_id", "{tenant}"), ("claim_present", "sid"),
                ("roles_eq", ["{operator_role}"]), ("scope_superset", [SCOPE]),
                ("claim_absent", "azp"), ("claim_absent", "act"), ("claim_absent", "token_use"),
                ("claim_absent", "subject_sid"),
            ],
        },
        "H2-N1": {
            "class": "wrong_verifier", "kind": "wrong_verifier", "user": "user", "depends": ["H2-P1"],
            "description": "fresh code (same logged-in session) redeemed with a wrong code_verifier: "
                           "400 invalid_grant; no access_token",
            "denial": {"status": 400, "error": "invalid_grant"},
        },
        "H2-N2": {
            "class": "code_replay", "kind": "code_replay", "user": "user", "depends": ["H2-P1"],
            "description": "fresh code (same logged-in session) redeemed once with the correct verifier (200), "
                           "then replayed with the same verifier: 400 invalid_grant; no access_token. "
                           "The H2-P1 code is never replayed (a replay invalidates that authorization's tokens)",
            "first_redemption_status": 200,
            "denial": {"status": 400, "error": "invalid_grant"},
        },
        "H2-N3": {
            "class": "non_member", "kind": "login_denial", "user": "nomember", "depends": [],
            "description": "<p>-nomember logs in; authorize refused: 403 and no code in any Location",
            "denial": {"status": 403, "no_code": True, "login_accepted": True},
        },
        "H2-P2": {
            "class": "positive", "kind": "exchange", "requester": "bff", "subject": "H2-P1",
            "audience": "{bff_aud}", "scope": SCOPE, "depends": ["H2-P1"],
            "description": "workforce -> BFF: <p>-bff exchanges P1 to bff aud",
            "checks": [
                ("status", 200), ("claim", "sub", "{user}"), ("aud", ["{bff_aud}"]),
                ("act", "sub", "{bff_wl_ref}"), ("act", "client_id", "{bff_client}"),
                ("act", "workload_id", "{bff_wl_id}"),
                ("claim", "client_id", "{bff_client}"), ("claim", "azp", "{bff_client}"),
                ("claim", "identity_kind", "workforce"), ("claim", "authority_profile", "workforce"),
                ("claim", "token_use", "exchange_subject"),
                ("claim", "authority_id", "workforce:{bff_app_id}:{user}:{entitlement_revision}"),
                ("claim", "subject_sid", "{p1_sid}"), ("sid_new", ["H2-P1"]), ("exp_bound", "H2-P1"),
            ] + EXCHANGE_COMMON,
        },
        "H2-N4": {
            "class": "raw_human_to_broker", "kind": "exchange", "requester": "broker", "subject": "H2-P1",
            "audience": "{agent_aud}", "scope": SCOPE, "depends": ["H2-P1"],
            "description": "broker exchanges the raw P1 human token to agent aud: 400 invalid_grant",
            "denial": {"status": 400, "error": "invalid_grant"},
        },
        "H2-N5": {
            "class": "wrong_redeemer", "kind": "exchange", "requester": "sibling", "subject": "H2-P2",
            "audience": "{gateway_aud}", "scope": SCOPE, "depends": ["H2-P2"],
            "description": "<p>-sibling exchanges P2 to gateway: 400 invalid_grant",
            "denial": {"status": 400, "error": "invalid_grant"},
        },
        "H2-N6": {
            "class": "skip_gateway", "kind": "exchange", "requester": "bff", "subject": "H2-P2",
            "audience": "{agent_aud}", "scope": SCOPE, "depends": ["H2-P2"],
            "description": "<p>-bff exchanges P2 straight to agent aud: 400 invalid_target",
            "denial": {"status": 400, "error": "invalid_target"},
        },
        "H2-N7": {
            "class": "over_broad_scope", "kind": "exchange", "requester": "bff", "subject": "H2-P2",
            "audience": "{gateway_aud}", "scope": f"{SCOPE} {EXTRA_SCOPE}", "depends": ["H2-P2"],
            "description": "<p>-bff exchanges P2 to gateway with an extra scope: 400 invalid_scope",
            "denial": {"status": 400, "error": "invalid_scope"},
        },
        "H2-P3": {
            "class": "positive", "kind": "exchange", "requester": "bff", "subject": "H2-P2",
            "audience": "{gateway_aud}", "scope": SCOPE, "depends": ["H2-P2"],
            "description": "BFF -> Gateway: <p>-bff exchanges P2 to gateway (R1)",
            "checks": [
                ("status", 200), ("claim", "sub", "{user}"), ("aud", ["{gateway_aud}"]),
                ("act", "sub", "{bff_wl_ref}"), ("act", "client_id", "{bff_client}"),
                ("act", "workload_id", "{bff_wl_id}"), ("claim", "client_id", "{bff_client}"),
                ("claim", "azp", "{bff_client}"), ("claim", "authority_profile", "workload_continuation"),
                ("claim", "token_use", "gateway_authorization"), ("claim", "authority_id", "{R1}"),
                ("claim", "subject_sid", "{p1_sid}"), ("sid_new", ["H2-P1", "H2-P2"]), ("exp_bound", "H2-P2"),
            ] + EXCHANGE_COMMON,
        },
        "H2-N8": {
            "class": "wrong_redeemer", "kind": "exchange", "requester": "agent", "subject": "H2-P3",
            "audience": "{gateway_aud}", "scope": SCOPE, "depends": ["H2-P3"],
            "description": "<p>-agent exchanges P3 (addressed to the broker) to gateway: 400 invalid_grant",
            "denial": {"status": 400, "error": "invalid_grant"},
        },
        "H2-P4": {
            "class": "positive", "kind": "exchange", "requester": "broker", "subject": "H2-P3",
            "audience": "{agent_aud}", "scope": SCOPE, "depends": ["H2-P3"],
            "description": "broker -> Agent (R2): actor preserved as the BFF; broker is never the actor",
            "checks": [
                ("status", 200), ("claim", "sub", "{user}"), ("aud", ["{agent_aud}"]),
                ("act", "sub", "{bff_wl_ref}"), ("act", "client_id", "{bff_client}"),
                ("act", "workload_id", "{bff_wl_id}"), ("act_ne", "client_id", "{broker_client}"),
                ("act_not_contains", "sub", "gateway-broker"),
                ("claim", "client_id", "{broker_client}"), ("claim", "azp", "{broker_client}"),
                ("claim", "authority_profile", "gateway_backend"), ("claim", "token_use", "exchange_subject"),
                ("claim", "authority_id", "{R2}"), ("claim", "subject_sid", "{p1_sid}"),
                ("sid_new", ["H2-P1", "H2-P2", "H2-P3"]), ("exp_bound", "H2-P3"),
            ] + EXCHANGE_COMMON,
        },
        "H2-P5": {
            "class": "positive", "kind": "exchange", "requester": "agent", "subject": "H2-P4",
            "audience": "{gateway_aud}", "scope": SCOPE, "depends": ["H2-P4"],
            "description": "Agent -> Gateway (R3): <p>-agent exchanges P4 to gateway",
            "checks": [
                ("status", 200), ("claim", "sub", "{user}"), ("aud", ["{gateway_aud}"]),
                ("act", "sub", "{agent_wl_ref}"), ("act", "client_id", "{agent_client}"),
                ("act", "workload_id", "{agent_wl_id}"),
                ("claim", "client_id", "{agent_client}"), ("claim", "azp", "{agent_client}"),
                ("claim", "authority_profile", "workload_continuation"),
                ("claim", "token_use", "gateway_authorization"), ("claim", "authority_id", "{R3}"),
                ("claim", "subject_sid", "{p1_sid}"), ("sid_new", ["H2-P1", "H2-P2", "H2-P3", "H2-P4"]),
                ("exp_bound", "H2-P4"),
            ] + EXCHANGE_COMMON,
        },
        "H2-N9": {
            "class": "no_route", "kind": "exchange", "requester": "broker", "subject": "H2-P5",
            "audience": "{bff_aud}", "scope": SCOPE, "depends": ["H2-P5"],
            "description": "broker exchanges P5 to bff aud (no agent->AGENT bff route): 400 invalid_target",
            "denial": {"status": 400, "error": "invalid_target"},
        },
        "H2-P6": {
            "class": "positive", "kind": "exchange", "requester": "broker", "subject": "H2-P5",
            "audience": "{tool_aud}", "scope": SCOPE, "depends": ["H2-P5"],
            "description": "broker -> resource (R4): delegated access to the tool audience",
            "checks": [
                ("status", 200), ("claim", "sub", "{user}"), ("aud", ["{tool_aud}"]),
                ("act", "sub", "{agent_wl_ref}"), ("act", "client_id", "{agent_client}"),
                ("act", "workload_id", "{agent_wl_id}"), ("act_ne", "client_id", "{broker_client}"),
                ("claim", "client_id", "{broker_client}"),
                ("claim", "azp", "{broker_client}"), ("claim", "authority_profile", "gateway_backend"),
                ("claim", "token_use", "delegated_access"), ("claim", "authority_id", "{R4}"),
                ("claim", "subject_sid", "{p1_sid}"),
                ("sid_new", ["H2-P1", "H2-P2", "H2-P3", "H2-P4", "H2-P5"]), ("exp_bound", "H2-P5"),
            ] + EXCHANGE_COMMON,
        },
    },
}


def validate_expectations(table: dict) -> None:
    order, cases = table.get("order"), table.get("cases")
    if not isinstance(order, list) or not isinstance(cases, dict) or sorted(order) != sorted(cases) \
            or len(set(order)) != len(order):
        raise HarnessError("expectation table order/cases mismatch")
    for cid in order:
        spec = cases[cid]
        for dep in spec.get("depends", []):
            if dep not in cases or order.index(dep) >= order.index(cid):
                raise HarnessError(f"{cid}: dependency {dep} must run earlier")
        if spec["kind"] == "exchange" and spec.get("subject") not in cases:
            raise HarnessError(f"{cid}: unknown subject case")
        if ("checks" in spec) == ("denial" in spec):
            raise HarnessError(f"{cid}: exactly one of checks/denial is required")


validate_expectations(H2_EXPECTATIONS)
CASE_IDS = tuple(H2_EXPECTATIONS["order"])


# ---------------------------------------------------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------------------------------------------------

def identity_names_h2(p: str, tool_needs_client: bool = TOOL_NEEDS_CLIENT) -> dict:
    apps = {
        "bff": {"applicationKey": f"{p}-bff", "audience": f"agent:{TENANT}:{p}-bff"},
        "gateway": {"applicationKey": f"{p}-gateway", "audience": f"{p}-gateway"},
        "agent": {"applicationKey": f"{p}-agent", "audience": f"agent:{TENANT}:{p}-agent"},
        "tool": {"applicationKey": f"{p}-tool", "audience": f"tool:{TENANT}:{p}-tool"},
        "sibling": {"applicationKey": f"{p}-sibling", "audience": f"agent:{TENANT}:{p}-sibling"},
    }
    clients = {
        "human_web": {"clientId": f"{p}-human-web", "app": "bff", "clientType": "PUBLIC_BROWSER",
                      "redirectUris": [REDIRECT_URI], "scopes": list(HUMAN_SCOPES)},
        "bff": {"clientId": f"{p}-bff", "app": "bff", "clientType": "CONFIDENTIAL_SERVICE",
                "redirectUris": [], "scopes": [SCOPE]},
        "broker": {"clientId": f"{p}-gateway-broker", "app": "gateway", "clientType": "CONFIDENTIAL_SERVICE",
                   "redirectUris": [], "scopes": [SCOPE]},
        "agent": {"clientId": f"{p}-agent", "app": "agent", "clientType": "CONFIDENTIAL_SERVICE",
                  "redirectUris": [], "scopes": [SCOPE]},
        "sibling": {"clientId": f"{p}-sibling", "app": "sibling", "clientType": "CONFIDENTIAL_SERVICE",
                    "redirectUris": [], "scopes": [SCOPE]},
    }
    if tool_needs_client:
        clients["tool"] = {"clientId": f"{p}-tool", "app": "tool", "clientType": "CONFIDENTIAL_SERVICE",
                           "redirectUris": [], "scopes": [SCOPE]}
    return {
        "applications": apps,
        "clients": clients,
        "workloads": {"bff": {"workloadRef": f"agent:{p}-bff:test", "client": "bff"},
                      "agent": {"workloadRef": f"agent:{p}-agent:test", "client": "agent"},
                      "sibling": {"workloadRef": f"agent:{p}-sibling:test", "client": "sibling"}},
        "broker": {"client": "broker", "gatewayAudience": apps["gateway"]["audience"], "scopes": [SCOPE]},
        "routes": {
            "R1": {"source": "bff", "destinationType": "GATEWAY", "destination": None, "audience_app": "gateway"},
            "R2": {"source": "bff", "destinationType": "AGENT", "destination": "agent", "audience_app": "agent"},
            "R3": {"source": "agent", "destinationType": "GATEWAY", "destination": None, "audience_app": "gateway"},
            "R4": {"source": "agent", "destinationType": "RESOURCE", "destination": None, "audience_app": "tool"},
        },
        "role": {"roleKey": f"{p}-operator", "app": "bff", "permissions": [SCOPE]},
        "users": {"user": f"{p}-user", "nomember": f"{p}-nomember"},
        "membership": {"user": "user", "app": "bff"},
    }


def base_vars(p: str, names: dict | None = None) -> dict:
    n = names or identity_names_h2(p)
    apps, clients, wl = n["applications"], n["clients"], n["workloads"]
    return {
        "p": p, "issuer": EXPECTED_ISSUER, "tenant": TENANT,
        "user": n["users"]["user"], "nomember": n["users"]["nomember"], "operator_role": n["role"]["roleKey"],
        "bff_aud": apps["bff"]["audience"], "gateway_aud": apps["gateway"]["audience"],
        "agent_aud": apps["agent"]["audience"], "tool_aud": apps["tool"]["audience"],
        "sibling_aud": apps["sibling"]["audience"],
        "human_client": clients["human_web"]["clientId"], "bff_client": clients["bff"]["clientId"],
        "broker_client": clients["broker"]["clientId"], "agent_client": clients["agent"]["clientId"],
        "sibling_client": clients["sibling"]["clientId"],
        "bff_wl_ref": wl["bff"]["workloadRef"], "agent_wl_ref": wl["agent"]["workloadRef"],
        "sibling_wl_ref": wl["sibling"]["workloadRef"],
        "bff_wl_id": None, "agent_wl_id": None, "R1": None, "R2": None, "R3": None, "R4": None, "p1_sid": None,
        "bff_app_id": None,
        # Membership create sets revision 1; the single role assignment bumps it to 2 (source contract).
        "entitlement_revision": EXPECTED_ENTITLEMENT_REVISION,
    }


# ---------------------------------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------------------------------

def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pkce_pair(token_urlsafe: Callable[[int], str] = secrets.token_urlsafe) -> tuple[str, str]:
    """(code_verifier, S256 code_challenge)."""
    verifier = token_urlsafe(64)[:96]
    challenge = b64url_nopad(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


_INPUT_TAG = re.compile(r"<input\b([^>]*)>", re.IGNORECASE | re.DOTALL)
_ATTR = re.compile(r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""", re.DOTALL)


def extract_csrf(body: Any, field_name: str = "_csrf") -> str | None:
    """Value of the hidden input named ``_csrf``, independent of attribute order and quoting."""
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", errors="replace")
    if not isinstance(body, str):
        return None
    for tag in _INPUT_TAG.finditer(body):
        attrs: dict[str, str] = {}
        for m in _ATTR.finditer(tag.group(1)):
            value = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
            attrs.setdefault(m.group(1).lower(), html.unescape(value))
        if attrs.get("name") == field_name and attrs.get("value"):
            return attrs["value"]
    return None


def normalize_headers(headers: Any) -> list[tuple[str, str]]:
    if headers is None:
        return []
    items = headers.items() if hasattr(headers, "items") else headers
    out = []
    for item in items:
        if isinstance(item, (tuple, list)) and len(item) == 2 and isinstance(item[0], str) \
                and isinstance(item[1], str):
            out.append((item[0], item[1]))
    return out


def header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    lname = name.lower()
    return [v for k, v in headers if k.lower() == lname]


def first_header(headers: list[tuple[str, str]], name: str) -> str | None:
    values = header_values(headers, name)
    return values[0] if values else None


def location_path(location: Any) -> str | None:
    """Path only (never the query, which may carry a code)."""
    if not isinstance(location, str):
        return None
    try:
        return urllib.parse.urlsplit(location).path
    except ValueError:
        return None


def location_query(location: Any) -> dict:
    if not isinstance(location, str):
        return {}
    try:
        return urllib.parse.parse_qs(urllib.parse.urlsplit(location).query, keep_blank_values=True)
    except ValueError:
        return {}


def location_has_code(location: Any) -> bool:
    return "code" in location_query(location)


def filter_claims_h2(claims: Any) -> dict:
    if not isinstance(claims, dict):
        return {}
    out = {}
    for k in H2_ALLOWED_CLAIMS:
        if k in claims:
            v = claims[k]
            out[k] = filter_claims_h2(v) if isinstance(v, dict) else v
    return out


# ---------------------------------------------------------------------------------------------------------------------
# HTTP layer with headers, Location guard and cookie jar
# ---------------------------------------------------------------------------------------------------------------------

def default_http_h2(method: str, url: str, headers: dict, body: bytes | None, timeout: float = HTTP_TIMEOUT,
                    _opener: Any = None) -> tuple[int, list[tuple[str, str]], bytes]:
    """Like H-1 default_http (no env proxies, redirects never followed) but also returns response headers."""
    opener = _opener or h1.build_opener()
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, normalize_headers(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        try:
            data = exc.read()
        except Exception:  # noqa: BLE001
            data = b""
        hdrs = normalize_headers(getattr(exc, "headers", None))
        try:
            exc.close()
        except Exception:  # noqa: BLE001
            pass
        return exc.code, hdrs, data


@dataclass
class LocationTarget:
    kind: str                       # "local" or "callback"
    path: str | None                # path+query on the forwarded base (local only)
    display_path: str               # path only, safe to print
    code_present: bool
    rewritten: bool = False
    original_host: str | None = None
    code: str | None = None
    state: str | None = None
    error: str | None = None


def _local_target(parts: urllib.parse.SplitResult, port: int, code_present: bool, **kw: Any) -> LocationTarget:
    path_qs = parts.path + (("?" + parts.query) if parts.query else "")
    h1.make_url(port, path_qs)   # raises HarnessError for anything that is not a fixed relative path
    return LocationTarget("local", path_qs, parts.path, code_present, **kw)


def classify_location(location: Any, port: int, redirect_uri: str = REDIRECT_URI) -> LocationTarget:
    """Decide what a redirect Location means. Raises HarnessError for anything not allowed.

    - relative absolute-path (``/x``) or ``http://127.0.0.1:<port>/x``: follow on the forwarded base;
    - the client redirect_uri (scheme, host, port, path): extract code/state only, never requested;
    - the configured issuer host (scheme, host, port) with a known Axiom path: rewritten onto the forwarded base
      and counted in the summary;
    - everything else is rejected.
    """
    if not isinstance(location, str) or not location:
        raise HarnessError("Location rejected: empty")
    if any(ch in location for ch in ("\\", " ", "\r", "\n", "\t")):
        raise HarnessError("Location rejected: forbidden characters")
    try:
        parts = urllib.parse.urlsplit(location)
        lport = parts.port
    except ValueError:
        raise HarnessError("Location rejected: unparsable") from None
    if parts.fragment:
        raise HarnessError("Location rejected: fragment")
    qs = location_query(location)
    code_present = "code" in qs
    if not parts.scheme and not parts.netloc:
        if not location.startswith("/") or location.startswith("//"):
            raise HarnessError("Location rejected: relative reference is not an absolute path")
        return _local_target(parts, port, code_present)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HarnessError("Location rejected: scheme")
    if parts.username is not None or parts.password is not None:
        raise HarnessError("Location rejected: userinfo")
    cb = urllib.parse.urlsplit(redirect_uri)
    if (parts.scheme, parts.hostname, lport, parts.path) == (cb.scheme, cb.hostname, cb.port, cb.path):
        codes, states, errors = qs.get("code", []), qs.get("state", []), qs.get("error", [])
        return LocationTarget("callback", None, parts.path, code_present,
                              code=codes[0] if len(codes) == 1 and codes[0] else None,
                              state=states[0] if len(states) == 1 else None,
                              error=errors[0] if len(errors) == 1 else None)
    if parts.scheme == "http" and parts.hostname == "127.0.0.1" and lport == port:
        return _local_target(parts, port, code_present)
    issuer = urllib.parse.urlsplit(EXPECTED_ISSUER)
    if (parts.scheme, parts.hostname, lport) == (issuer.scheme, issuer.hostname, issuer.port) \
            and parts.path in KNOWN_REWRITE_PATHS:
        # Only the configured issuer's own host may be mapped onto the forward, and only for known paths.
        return _local_target(parts, port, code_present, rewritten=True, original_host=parts.hostname)
    raise HarnessError("Location rejected: host not allowed")


_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def parse_set_cookie(raw: Any) -> tuple[str, str, dict] | None:
    if not isinstance(raw, str):
        return None
    pieces = raw.split(";")
    if "=" not in pieces[0]:
        return None
    name, value = pieces[0].split("=", 1)
    name, value = name.strip(), value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    if not _COOKIE_NAME.match(name):
        return None
    attrs: dict[str, str] = {}
    for piece in pieces[1:]:
        k, _, v = piece.partition("=")
        if k.strip():
            attrs[k.strip().lower()] = v.strip()
    return name, value, attrs


class CookieJar:
    """In-memory, per browser session. Stores only cookies from server responses; sends them only to the
    forwarded base ``http://127.0.0.1:<port>``. Every value is registered with the redactor."""

    def __init__(self, port: int, redactor: Redactor):
        self.port = port
        self.redactor = redactor
        self._cookies: dict[str, str] = {}

    def absorb(self, headers: list[tuple[str, str]]) -> None:
        for raw in header_values(headers, "Set-Cookie"):
            parsed = parse_set_cookie(raw)
            if parsed is None:
                continue
            name, value, attrs = parsed
            self.redactor.register(value)
            max_age = attrs.get("max-age")
            expired = max_age is not None and max_age.lstrip("-").isdigit() and int(max_age) <= 0
            if not value or expired:
                self._cookies.pop(name, None)
            else:
                self._cookies[name] = value

    def header_for(self, url: str) -> str | None:
        try:
            parts = urllib.parse.urlsplit(url)
            port = parts.port
        except ValueError:
            return None
        if parts.scheme != "http" or parts.hostname != "127.0.0.1" or port != self.port or not self._cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    def names(self) -> list[str]:
        return sorted(self._cookies)


# ---------------------------------------------------------------------------------------------------------------------
# Generic evaluators
# ---------------------------------------------------------------------------------------------------------------------

class UnknownValue(Exception):
    pass


_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")


def resolve(value: Any, variables: dict) -> Any:
    if isinstance(value, str):
        def sub(m: re.Match) -> str:
            v = variables.get(m.group(1))
            if v is None:
                raise UnknownValue(m.group(1))
            return str(v)
        return _PLACEHOLDER.sub(sub, value)
    if isinstance(value, (list, tuple)):
        return [resolve(v, variables) for v in value]
    return value


def resolve_for_display(value: Any, variables: dict) -> Any:
    try:
        return resolve(value, variables)
    except UnknownValue as u:
        if isinstance(value, str):
            return _PLACEHOLDER.sub(lambda m: str(variables.get(m.group(1)) or f"<{m.group(1)}>"), value)
        return [resolve_for_display(v, variables) for v in value] if isinstance(value, (list, tuple)) \
            else f"<{u}>"


@dataclass
class EvalEnv:
    variables: dict
    exps: dict = field(default_factory=dict)        # case_id -> exp of its access token
    sids: dict = field(default_factory=dict)        # case_id -> sid of its access token
    request_time: float | None = None


def case_result(case_id: str, spec: dict, observed: dict, mismatches: list[str]) -> dict:
    return {"event": "case", "package": PACKAGE, "case_id": case_id, "class": spec["class"],
            "expected": spec["description"], "observed": observed, "mismatches": mismatches,
            "result": "pass" if not mismatches else "fail"}


def skipped_case(case_id: str, spec: dict, reason: str) -> dict:
    return {"event": "case", "package": PACKAGE, "case_id": case_id, "class": spec["class"],
            "expected": spec["description"], "observed": {"skipped_reason": reason}, "mismatches": [],
            "result": "skipped"}


def _apply_check(check: tuple, parsed: dict, header: dict, claims: dict, env: EvalEnv, observed: dict,
                 m: list[str]) -> None:
    kind = check[0]
    v = env.variables
    if kind == "status":
        return  # evaluated first
    if kind == "token_type":
        tt = parsed.get("token_type")
        if not isinstance(tt, str) or tt.lower() != str(check[1]).lower():
            m.append(f"token_type != {check[1]}")
    elif kind == "issued_token_type":
        if parsed.get("issued_token_type") != check[1]:
            m.append("issued_token_type mismatch")
    elif kind == "header":
        if header.get(check[1]) != resolve(check[2], v):
            m.append(f"header {check[1]} mismatch")
    elif kind == "claim":
        want = resolve(check[2], v)
        got = claims.get(check[1])
        if got is None or str(got) != str(want):
            m.append(f"{check[1]} mismatch")
    elif kind == "claim_startswith":
        got = claims.get(check[1])
        if not isinstance(got, str) or not got.startswith(resolve(check[2], v)):
            m.append(f"{check[1]} does not start with {check[2]}")
    elif kind == "claim_present":
        if claims.get(check[1]) in (None, "", [], {}):
            m.append(f"{check[1]} missing")
    elif kind == "aud":
        if h1.normalize_aud(claims.get("aud")) != resolve(check[1], v):
            m.append("aud mismatch")
    elif kind in ("act", "act_ne", "act_not_contains"):
        act = claims.get("act")
        if not isinstance(act, dict):
            m.append("act missing")
            return
        got = act.get(check[1])
        want = resolve(check[2], v)
        if kind == "act" and (got is None or str(got) != str(want)):
            m.append(f"act.{check[1]} mismatch")
        elif kind == "act_ne" and got is not None and str(got) == str(want):
            m.append(f"act.{check[1]} must not be {check[2]}")
        elif kind == "act_not_contains" and isinstance(got, str) and want in got:
            m.append(f"act.{check[1]} contains {check[2]}")
    elif kind == "roles_contains":
        if resolve(check[1], v) not in h1.normalize_roles(claims.get("roles")):
            m.append("roles missing expected role")
    elif kind in ("scope_eq", "scope_superset"):
        got = h1.normalize_scope(claims.get("scope"))
        want = set(resolve(check[1], v))
        if got is None or (kind == "scope_eq" and got != want) or (kind == "scope_superset" and not want <= got):
            m.append(f"scope {'!=' if kind == 'scope_eq' else 'does not contain'} {sorted(want)}")
    elif kind == "claim_absent":
        if check[1] in claims:
            m.append(f"{check[1]} must be absent")
    elif kind == "roles_eq":
        if h1.normalize_roles(claims.get("roles")) != set(resolve(check[1], v)):
            m.append("roles != expected set")
    elif kind == "sid_new":
        sid = claims.get("sid")
        if not isinstance(sid, str) or not sid:
            m.append("sid missing")
        else:
            reused = [cid for cid in check[1] if env.sids.get(cid) == sid]
            if reused:
                m.append(f"sid reused from {reused}")
            if any(env.sids.get(cid) is None for cid in check[1]):
                m.append("previous sid unknown")
    elif kind == "lifetime_max":
        exp, iat = _int(claims.get("exp")), _int(claims.get("iat"))
        if exp is None or iat is None or not (0 < exp - iat <= int(check[1])):
            m.append(f"exp-iat not in (0, {check[1]}]")
    elif kind == "response_authority_eq_claim":
        resp, claim = parsed.get("authority_id"), claims.get("authority_id")
        if resp is None or claim is None or str(resp) != str(claim):
            m.append("response authority_id != claim authority_id")
    elif kind == "exp_bound":
        exp = _int(claims.get("exp"))
        prev = _int(env.exps.get(check[1]))
        if exp is None:
            m.append("exp missing or not integer")
        elif prev is None:
            m.append(f"{check[1]} exp unknown")
        elif env.request_time is None:
            m.append("request time unknown")
        else:
            bound = min(prev, int(env.request_time) + EXCHANGE_MAX_LIFETIME + CLOCK_SKEW)
            observed["exp_bound"] = bound
            if exp > bound:
                m.append(f"exp {exp} > bound {bound}")
    else:
        raise HarnessError(f"unknown check kind {kind!r}")


def evaluate_token_response(case_id: str, spec: dict, status: Any, body: Any, env: EvalEnv) -> dict:
    parsed = parse_json(body)
    observed: dict = {"status": status, **h1.error_fields(parsed)}
    m: list[str] = []
    want_status = next((c[1] for c in spec["checks"] if c[0] == "status"), 200)
    if status != want_status:
        m.append(f"status {status} != {want_status}")
    if not isinstance(parsed, dict):
        m.append("body is not a JSON object")
        return case_result(case_id, spec, observed, m)
    for k in ("token_type", "issued_token_type"):
        if k in parsed:
            observed[k] = parsed.get(k)
    if "authority_id" in parsed:
        observed["response_authority_id"] = parsed.get("authority_id")
    token = parsed.get("access_token")
    if not isinstance(token, str) or not token:
        m.append("access_token missing")
        return case_result(case_id, spec, observed, m)
    observed["token_sha256_12"] = h1.token_hash(token)
    try:
        header, claims = h1.decode_jwt(token)
    except ValueError as exc:
        m.append(f"access_token not decodable: {exc}")
        return case_result(case_id, spec, observed, m)
    observed["header"] = filter_claims_h2(header)
    observed["claims"] = filter_claims_h2(claims)
    for check in spec["checks"]:
        try:
            _apply_check(check, parsed, header, claims, env, observed, m)
        except UnknownValue as u:
            m.append(f"{check[0]} {check[1] if len(check) > 1 else ''}: expected value unknown ({u})")
    return case_result(case_id, spec, observed, m)


def evaluate_denial(case_id: str, spec: dict, status: Any, body: Any) -> dict:
    denial = spec["denial"]
    parsed = parse_json(body)
    observed: dict = {"status": status, **h1.error_fields(parsed)}
    m: list[str] = []
    if status != denial["status"]:
        m.append(f"status {status} != {denial['status']}")
    if not isinstance(parsed, dict):
        m.append("body is not a JSON object")
        observed["access_token_present"] = None
        return case_result(case_id, spec, observed, m)
    present = "access_token" in parsed
    observed["access_token_present"] = present
    if present:
        observed["token_sha256_12"] = h1.token_hash(parsed.get("access_token"))
        m.append("access_token present in denial body")
    if "error" in denial and parsed.get("error") != denial["error"]:
        m.append(f"error != {denial['error']}")
    return case_result(case_id, spec, observed, m)


def evaluate_login_denial(case_id: str, spec: dict, login: dict) -> dict:
    """Hard requirement: no authorization code in any Location. Status and login acceptance from the table."""
    denial = spec["denial"]
    observed = {"login_accepted": login.get("login_accepted"), "final_status": login.get("final_status"),
                "code_issued": login.get("code_issued"), "trace": login.get("trace"),
                "failure": login.get("failure")}
    m: list[str] = []
    if denial.get("no_code", True) and login.get("code_issued"):
        m.append("authorization code issued")
    if denial.get("login_accepted") and not login.get("login_accepted"):
        m.append("login was not accepted (authorization refusal not exercised)")
    if "status" in denial and login.get("final_status") != denial["status"]:
        m.append(f"status {login.get('final_status')} != {denial['status']}")
    return case_result(case_id, spec, observed, m)


parse_json = h1.parse_json


# ---------------------------------------------------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------------------------------------------------

@dataclass
class H2Created:
    apps: dict = field(default_factory=dict)        # role -> appId
    clients: dict = field(default_factory=dict)     # role -> (appId, clientUuid)
    workloads: dict = field(default_factory=dict)   # role -> workloadId
    broker: Any = None
    routes: dict = field(default_factory=dict)      # R1..R4 -> routeId
    role: Any = None
    users: dict = field(default_factory=dict)       # user role -> user id
    membership: Any = None


def _safe_id(value: Any) -> bool:
    return isinstance(value, (str, int)) and not isinstance(value, bool) and bool(SAFE_ID.match(str(value)))


class H2Runner(h1.Runner):
    def __init__(self, *, http: Callable | None = None, token_urlsafe: Callable[[int], str] = secrets.token_urlsafe,
                 expectations: dict | None = None, tool_needs_client: bool = TOOL_NEEDS_CLIENT, **kw: Any):
        super().__init__(http=http or default_http_h2, **kw)
        self.token_urlsafe = token_urlsafe
        self.expectations = expectations or H2_EXPECTATIONS
        validate_expectations(self.expectations)
        self.case_ids = tuple(self.expectations["order"])
        self.tool_needs_client = tool_needs_client
        self.names = identity_names_h2(self.prefix, tool_needs_client)
        self.h2 = H2Created()
        self.passwords: dict[str, SensitiveValue] = {}
        self.tokens: dict[str, SensitiveValue] = {}
        self.env = EvalEnv(variables=base_vars(self.prefix, self.names))
        self.location_rewrites = 0
        self.logins: dict[str, dict] = {}
        self.jars: dict[str, CookieJar] = {}
        self._relogged = False

    # -- output -------------------------------------------------------------------------------------------------------
    def emit(self, event: dict) -> None:
        ev = dict(event)
        name = str(ev.get("event", ""))
        ev["event"] = name if name.startswith(EVENT_PREFIX) else EVENT_PREFIX + name
        ev.setdefault("package", PACKAGE)
        super().emit(ev)

    # -- HTTP ---------------------------------------------------------------------------------------------------------
    def request(self, method: str, path: str, **kw: Any) -> tuple[int, Any]:
        status, _headers, raw = self.request_full(method, path, **kw)
        return status, raw

    def request_full(self, method: str, path: str, *, json_body: Any = None, form: dict | None = None,
                     bearer: SensitiveValue | None = None, basic: tuple[str, SensitiveValue] | None = None,
                     accept: str = "application/json", jar: CookieJar | None = None,
                     abort_on_5xx: bool = True) -> tuple[int, list[tuple[str, str]], Any]:
        safe_path = location_path(path) or "?"
        if not self._pf_alive():
            raise AbortRun("port-forward lost")
        url = h1.make_url(self.port, path)
        h1.check_url(url, self.port)
        headers = {"Accept": accept}
        data = None
        if json_body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(json_body).encode("utf-8")
        elif form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(form).encode("ascii")
        if bearer is not None:
            headers["Authorization"] = "Bearer " + bearer.reveal()
        elif basic is not None:
            hdr = h1.basic_auth(basic[0], basic[1].reveal())
            self.redactor.register(hdr)
            self.redactor.register(hdr[len("Basic "):])
            headers["Authorization"] = hdr
        if jar is not None:
            cookie = jar.header_for(url)
            if cookie:
                headers["Cookie"] = cookie
        try:
            status, resp_headers, raw = self.http(method, url, headers, data, HTTP_TIMEOUT)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            if not self._pf_alive():
                raise AbortRun("port-forward lost") from None
            raise AbortRun(f"transport error {type(exc).__name__} on {method} {safe_path}") from None
        finally:
            headers.clear()
            del data
        resp_headers = normalize_headers(resp_headers)
        for raw_cookie in header_values(resp_headers, "Set-Cookie"):
            parsed = parse_set_cookie(raw_cookie)
            if parsed is not None:
                self.redactor.register(parsed[1])
        for loc in header_values(resp_headers, "Location"):
            for code in location_query(loc).get("code", []):
                self.redactor.register(code)
        if jar is not None:
            jar.absorb(resp_headers)
        if abort_on_5xx and isinstance(status, int) and status >= 500:
            self.emit({"event": "http_5xx", "method": method, "path": safe_path, "status": status,
                       **h1.error_fields(raw)})
            raise AbortRun(f"5xx on {method} {safe_path}")
        return status, resp_headers, raw

    # -- setup --------------------------------------------------------------------------------------------------------
    def _admin_call(self, step: str, method: str, path: str, body: dict, expect: int = 201) -> dict:
        status, raw = self.request(method, path, json_body=body, bearer=self.admin_token)
        doc = parse_json(raw)
        if status != expect or not isinstance(doc, dict):
            self.emit({"event": "setup", "step": step, "ok": False, "status": status, **h1.error_fields(doc)})
            raise AbortRun(f"setup {step} failed")
        return doc

    def _require_id(self, step: str, value: Any) -> Any:
        if value is None or not _safe_id(value):
            self.emit({"event": "setup", "step": step, "ok": False, "reason": "id missing or unsafe"})
            raise AbortRun(f"setup {step}: id missing or unsafe")
        return value

    def setup(self) -> None:
        base = f"/admin/tenants/{TENANT}"
        n = self.names
        for role in APP_ROLES:
            spec = n["applications"][role]
            doc = self._admin_call(f"application:{role}", "POST", f"{base}/applications", {
                "applicationKey": spec["applicationKey"], "displayName": spec["applicationKey"],
                "description": DESCRIPTION, "audience": spec["audience"]})
            self.h2.apps[role] = self._require_id(f"application:{role}", doc.get("id"))
            if role == "bff":
                self.env.variables["bff_app_id"] = str(doc.get("id"))
            self.emit({"event": "setup", "step": f"application:{role}", "ok": True, "id": doc.get("id"),
                       "applicationKey": spec["applicationKey"], "audience": spec["audience"]})
        for role, spec in n["clients"].items():
            app_id = self.h2.apps[spec["app"]]
            doc = self._admin_call(f"client:{role}", "POST", f"{base}/applications/{app_id}/clients", {
                "clientId": spec["clientId"], "clientType": spec["clientType"],
                "redirectUris": list(spec["redirectUris"]), "postLogoutRedirectUris": [],
                "scopes": list(spec["scopes"])})
            client = doc.get("client") if isinstance(doc.get("client"), dict) else {}
            secret = doc.get("serviceSecret")
            confidential = spec["clientType"] == "CONFIDENTIAL_SERVICE"
            if isinstance(secret, str) and secret:
                self.client_secrets[role] = self._sensitive(secret)
            if client.get("id") is not None and _safe_id(client.get("id")):
                self.h2.clients[role] = (app_id, client.get("id"))
            if client.get("id") is None or not _safe_id(client.get("id")) \
                    or client.get("clientId") != spec["clientId"] or (confidential and role not in self.client_secrets):
                self.emit({"event": "setup", "step": f"client:{role}", "ok": False,
                           "reason": "client id/clientId/serviceSecret missing or mismatched"})
                raise AbortRun("client response incomplete")
            self.emit({"event": "setup", "step": f"client:{role}", "ok": True, "id": client.get("id"),
                       "clientId": spec["clientId"], "clientType": spec["clientType"]})
        for role in WORKLOAD_ROLES:
            spec = n["workloads"][role]
            doc = self._admin_call(f"workload:{role}", "POST", f"{base}/ciam/agent-workloads", {
                "workloadRef": spec["workloadRef"], "name": spec["workloadRef"],
                "oauthClientId": n["clients"][spec["client"]]["clientId"]})
            self.h2.workloads[role] = self._require_id(f"workload:{role}", doc.get("id"))
            self.emit({"event": "setup", "step": f"workload:{role}", "ok": True, "id": doc.get("id"),
                       "workloadRef": spec["workloadRef"]})
        self.env.variables["bff_wl_id"] = str(self.h2.workloads["bff"])
        self.env.variables["agent_wl_id"] = str(self.h2.workloads["agent"])
        b = n["broker"]
        doc = self._admin_call("broker", "POST", f"{base}/agent-exchange/brokers", {
            "oauthClientId": n["clients"][b["client"]]["clientId"], "gatewayAudience": b["gatewayAudience"],
            "scopes": list(b["scopes"])})
        self.h2.broker = self._require_id("broker", doc.get("id"))
        self.emit({"event": "setup", "step": "broker", "ok": True, "id": doc.get("id")})
        for key in ROUTE_KEYS:
            r = n["routes"][key]
            doc = self._admin_call(f"route:{key}", "POST", f"{base}/agent-exchange/routes", {
                "sourceWorkloadId": self.h2.workloads[r["source"]], "destinationType": r["destinationType"],
                "destinationWorkloadId": None if r["destination"] is None else self.h2.workloads[r["destination"]],
                "audience": n["applications"][r["audience_app"]]["audience"], "scopes": [SCOPE],
                "purpose": ROUTE_PURPOSE, "expiresAt": h1.iso_utc(self.now() + 3600)})
            self.h2.routes[key] = self._require_id(f"route:{key}", doc.get("id"))
            self.env.variables[key] = str(doc.get("id"))
            self.emit({"event": "setup", "step": f"route:{key}", "ok": True, "id": doc.get("id"),
                       "destinationType": r["destinationType"]})
        bff_app = self.h2.apps[n["role"]["app"]]
        role_key = n["role"]["roleKey"]
        doc = self._admin_call("role", "POST", f"{base}/applications/{bff_app}/access/roles", {
            "roleKey": role_key, "displayName": role_key, "description": DESCRIPTION,
            "permissions": list(n["role"]["permissions"]),
            "permissionEffects": {p: "allow" for p in n["role"]["permissions"]}})
        self.h2.role = self._require_id("role", doc.get("id"))
        self.emit({"event": "setup", "step": "role", "ok": True, "id": doc.get("id"), "roleKey": role_key})
        for role in USER_ROLES:
            uid = n["users"][role]
            # The server merges POST /users onto an existing principal with the same id; refuse to proceed
            # unless the id is provably unused.
            pre_status, _pre = self.request("GET", f"/users/{uid}", bearer=self.admin_token)
            if pre_status != 404:
                self.emit({"event": "setup", "step": f"user_precheck:{role}", "ok": False, "status": pre_status})
                raise AbortRun(f"user id for {role} is not provably unused (precheck status {pre_status})")
            password = self._sensitive(self.token_urlsafe(24) + "Aa1!")
            self.passwords[role] = password
            doc = self._admin_call(f"user:{role}", "POST", "/users", {
                "id": uid, "username": uid, "email": f"{uid}@{EMAIL_DOMAIN}", "password": password.reveal(),
                "attributes": {}})
            got = doc.get("id")
            if got != uid:
                self.emit({"event": "setup", "step": f"user:{role}", "ok": False, "reason": "returned id differs"})
                if got is not None and _safe_id(got):
                    # The server created an account under the returned id; record it so cleanup removes it.
                    self.h2.users[role] = got
                else:
                    self.cleanup_incomplete = True
                raise AbortRun(f"setup user:{role}: returned id differs from requested id")
            self.h2.users[role] = self._require_id(f"user:{role}", got)
            self.emit({"event": "setup", "step": f"user:{role}", "ok": True, "id": got})
        m = n["membership"]
        mapp = self.h2.apps[m["app"]]
        doc = self._admin_call("membership", "POST", f"{base}/applications/{mapp}/access/memberships", {
            "principalId": self.h2.users[m["user"]], "assignmentSource": ASSIGNMENT_SOURCE})
        self.h2.membership = self._require_id("membership", doc.get("id"))
        self.emit({"event": "setup", "step": "membership", "ok": True, "id": doc.get("id")})
        doc = self._admin_call("membership_role", "POST",
                               f"{base}/applications/{mapp}/access/memberships/{self.h2.membership}/roles",
                               {"roleId": self.h2.role, "assignmentSource": ASSIGNMENT_SOURCE}, expect=200)
        # The workforce authority_id embeds the membership's entitlement revision. Use the value the server
        # reports after the role assignment; the source contract says 2 (create=1, role assignment +1).
        revision = doc.get("entitlementRevision")
        if isinstance(revision, int) and not isinstance(revision, bool):
            self.env.variables["entitlement_revision"] = revision
        self.emit({"event": "setup", "step": "membership_role", "ok": True,
                   "entitlementRevision": self.env.variables["entitlement_revision"]})

    # -- browser flow -------------------------------------------------------------------------------------------------
    def _jar(self, user_role: str) -> CookieJar:
        if user_role not in self.jars:
            self.jars[user_role] = CookieJar(self.port, self.redactor)
        return self.jars[user_role]

    def _authorize_path(self, state: str, nonce: str, challenge: str) -> str:
        return "/oauth/authorize?" + urllib.parse.urlencode({
            "response_type": "code", "client_id": self.env.variables["human_client"], "redirect_uri": REDIRECT_URI,
            "scope": HUMAN_SCOPE, "state": state, "nonce": nonce, "code_challenge": challenge,
            "code_challenge_method": "S256"})

    def _walk(self, jar: CookieJar, method: str, path: str, *, trace: list, budget: dict,
              form: dict | None = None) -> dict:
        """One request plus manual, guarded redirect following. The redirect_uri is never requested."""
        current = path
        status, headers, raw = self.request_full(method, path, form=form, accept="text/html", jar=jar)
        while True:
            loc = first_header(headers, "Location")
            hop: dict = {"method": method, "path": location_path(current), "status": status}
            if loc is not None:
                hop["location_path"] = location_path(loc)
                hop["code_present"] = location_has_code(loc)
            trace.append(hop)
            if not (status in REDIRECT_STATUSES and loc):
                return {"kind": "final", "status": status, "raw": raw, "path": location_path(current)}
            try:
                target = classify_location(loc, self.port)
            except HarnessError as exc:
                hop["guard"] = "rejected"
                return {"kind": "guard_rejected", "status": status, "reason": str(exc)}
            if target.kind == "callback":
                hop["callback"] = True
                return {"kind": "callback", "status": status, "code": target.code, "state": target.state,
                        "error": target.error}
            if target.rewritten:
                hop["rewritten"] = True
                self.location_rewrites += 1
                self.emit({"event": "location_rewrite", "from_host": target.original_host,
                           "path": target.display_path})
            if budget["remaining"] <= 0:
                return {"kind": "hop_limit", "status": status}
            budget["remaining"] -= 1
            method, current = "GET", target.path
            status, headers, raw = self.request_full("GET", target.path, accept="text/html", jar=jar)

    def _new_authorization(self) -> tuple[str, str, str, str]:
        verifier, challenge = pkce_pair(self.token_urlsafe)
        self.redactor.register(verifier)
        state, nonce = self.token_urlsafe(24), self.token_urlsafe(24)
        self.redactor.register(state)
        self.redactor.register(nonce)
        return verifier, challenge, state, nonce

    @staticmethod
    def _finish(res: dict, r: dict, state: str, verifier: str) -> None:
        res["final_status"] = r.get("status")
        res["code_issued"] = any(h.get("code_present") for h in res["trace"])
        if r["kind"] == "callback":
            res["callback_error"] = r.get("error")
            res["state_ok"] = r.get("state") == state
            if r.get("code"):
                res["code"] = SensitiveValue(r["code"])
                res["verifier"] = SensitiveValue(verifier)
            else:
                res["failure"] = res["failure"] or "callback without code"
        else:
            res["failure"] = res["failure"] or f"authorize ended with {r['kind']} (status {r.get('status')})"
            if r["kind"] == "guard_rejected":
                res["guard_reason"] = r.get("reason")

    def pkce_login(self, user_role: str, jar: CookieJar) -> dict:
        res: dict = {"login_accepted": False, "code": None, "verifier": None, "state_ok": False,
                     "code_issued": False, "trace": [], "failure": None, "final_status": None}
        verifier, challenge, state, nonce = self._new_authorization()
        budget = {"remaining": MAX_REDIRECT_HOPS}
        r = self._walk(jar, "GET", self._authorize_path(state, nonce, challenge), trace=res["trace"], budget=budget)
        first = res["trace"][0] if res["trace"] else {}
        if r["kind"] != "final" or r.get("path") != "/login" or r.get("status") != 200 \
                or first.get("status") not in REDIRECT_STATUSES:
            res["failure"] = "authorize did not redirect to the login page"
            self._finish(res, r if r["kind"] != "final" else {"kind": "no_login_page", "status": r.get("status")},
                         state, verifier)
            return res
        csrf = extract_csrf(r.get("raw"))
        if not csrf:
            res["failure"] = "login page has no _csrf field"
            res["final_status"] = r.get("status")
            return res
        self.redactor.register(csrf)
        username = self.names["users"][user_role]
        start = len(res["trace"])
        r = self._walk(jar, "POST", "/login", trace=res["trace"], budget=budget,
                       form={"username": username, "password": self.passwords[user_role].reveal(), "_csrf": csrf})
        post = res["trace"][start] if len(res["trace"]) > start else {}
        res["login_accepted"] = post.get("status") in REDIRECT_STATUSES \
            and post.get("location_path") not in (None, "/login")
        self._finish(res, r, state, verifier)
        return res

    def authorize_in_session(self, jar: CookieJar) -> dict:
        res: dict = {"code": None, "verifier": None, "state_ok": False, "code_issued": False, "trace": [],
                     "failure": None, "final_status": None}
        verifier, challenge, state, nonce = self._new_authorization()
        r = self._walk(jar, "GET", self._authorize_path(state, nonce, challenge), trace=res["trace"],
                       budget={"remaining": MAX_REDIRECT_HOPS})
        self._finish(res, r, state, verifier)
        return res

    @staticmethod
    def login_summary(login: dict) -> dict:
        return {k: login.get(k) for k in ("login_accepted", "state_ok", "code_issued", "final_status", "failure",
                                          "guard_reason", "callback_error", "trace") if k in login}

    def redeem(self, code: SensitiveValue, verifier: SensitiveValue) -> tuple[int, Any]:
        form = {"grant_type": "authorization_code", "client_id": self.env.variables["human_client"],
                "code": code.reveal(), "redirect_uri": REDIRECT_URI, "code_verifier": verifier.reveal()}
        self.env.request_time = self.now()
        status, _h, raw = self.request_full("POST", "/oauth/token", form=form, abort_on_5xx=False)
        self._register_body_tokens(raw)
        return status, raw

    # -- cases --------------------------------------------------------------------------------------------------------
    def _store_token(self, case_id: str, raw: Any) -> None:
        doc = parse_json(raw)
        token = doc.get("access_token") if isinstance(doc, dict) else None
        self.tokens[case_id] = SensitiveValue(token)
        _h, claims = h1.decode_jwt(token)
        self.env.exps[case_id] = _int(claims.get("exp"))
        self.env.sids[case_id] = claims.get("sid")
        if case_id == "H2-P1":
            self.env.variables["p1_sid"] = claims.get("sid")

    @staticmethod
    def _check_5xx(case_id: str, status: Any) -> None:
        if isinstance(status, int) and status >= 500:
            raise AbortRun(f"5xx in {case_id}")

    def case_pkce_login(self, cid: str, spec: dict) -> None:
        login = self.pkce_login(spec["user"], self._jar(spec["user"]))
        self.logins[spec["user"]] = login
        summary = self.login_summary(login)
        if login["failure"] or login["code"] is None or not login["state_ok"]:
            reason = login["failure"] or ("state mismatch" if login["code"] is not None else "no code")
            self._record(case_result(cid, spec, {"login": summary}, [f"login: {reason}"]))
            return
        status, raw = self.redeem(login["code"], login["verifier"])
        result = evaluate_token_response(cid, spec, status, raw, self.env)
        result["observed"]["login"] = summary
        if result["result"] == "pass":
            self._store_token(cid, raw)
        self._record(result)
        self._check_5xx(cid, status)

    def case_wrong_verifier(self, cid: str, spec: dict) -> None:
        fresh = self.authorize_in_session(self._jar(spec["user"]))
        obs = {"fresh_authorize": self.login_summary(fresh)}
        if fresh["code"] is None or not fresh["state_ok"]:
            self._record(case_result(cid, spec, obs, [f"fresh code not issued: {fresh['failure'] or 'state'}"]))
            return
        wrong, _challenge = pkce_pair(self.token_urlsafe)
        self.redactor.register(wrong)
        status, raw = self.redeem(fresh["code"], SensitiveValue(wrong))
        result = evaluate_denial(cid, spec, status, raw)
        result["observed"].update(obs)
        self._record(result)
        self._check_5xx(cid, status)

    def case_code_replay(self, cid: str, spec: dict) -> None:
        fresh = self.authorize_in_session(self._jar(spec["user"]))
        obs: dict = {"fresh_authorize": self.login_summary(fresh)}
        if fresh["code"] is None or not fresh["state_ok"]:
            self._record(case_result(cid, spec, obs, [f"fresh code not issued: {fresh['failure'] or 'state'}"]))
            return
        status, raw = self.redeem(fresh["code"], fresh["verifier"])   # tokens registered, never used further
        obs["first_redemption_status"] = status
        obs["first_redemption_error"] = h1.error_fields(raw)["error"]
        want = spec.get("first_redemption_status", 200)
        if status != want:
            self._record(case_result(cid, spec, obs, [f"first redemption status {status} != {want}"]))
            self._check_5xx(cid, status)
            return
        status, raw = self.redeem(fresh["code"], fresh["verifier"])
        result = evaluate_denial(cid, spec, status, raw)
        result["observed"].update(obs)
        self._record(result)
        self._check_5xx(cid, status)

    def case_login_denial(self, cid: str, spec: dict) -> None:
        login = self.pkce_login(spec["user"], self._jar(spec["user"]))
        self.logins[spec["user"]] = login
        self._record(evaluate_login_denial(cid, spec, login))

    def case_exchange(self, cid: str, spec: dict) -> None:
        subject = self.tokens.get(spec["subject"])
        if subject is None:
            self._record(skipped_case(cid, spec, f"no {spec['subject']} token"))
            return
        role = spec["requester"]
        client_id = self.names["clients"][role]["clientId"]
        secret = self.client_secrets.get(role)
        if secret is None:
            self._record(case_result(cid, spec, {}, [f"no secret for requester {role}"]))
            return
        try:
            audience = resolve(spec["audience"], self.env.variables)
        except UnknownValue as u:
            self._record(case_result(cid, spec, {}, [f"audience unknown ({u})"]))
            return
        form = {"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": subject.reveal(),
                "subject_token_type": ACCESS_TOKEN_TYPE, "requested_token_type": ACCESS_TOKEN_TYPE,
                "audience": audience, "scope": spec["scope"]}
        self.env.request_time = self.now()
        status, raw = self.request("POST", "/oauth/token", form=form, basic=(client_id, secret),
                                   abort_on_5xx=False)
        self._register_body_tokens(raw)
        if "denial" in spec:
            result = evaluate_denial(cid, spec, status, raw)
        else:
            result = evaluate_token_response(cid, spec, status, raw, self.env)
            if result["result"] == "pass":
                self._store_token(cid, raw)
        result["observed"]["requester"] = client_id
        result["observed"]["audience"] = audience
        self._record(result)
        self._check_5xx(cid, status)

    def run_cases(self) -> None:
        handlers = {"pkce_login": self.case_pkce_login, "wrong_verifier": self.case_wrong_verifier,
                    "code_replay": self.case_code_replay, "login_denial": self.case_login_denial,
                    "exchange": self.case_exchange}
        cases = self.expectations["cases"]
        for cid in self.case_ids:
            spec = cases[cid]
            blocked = [d for d in spec.get("depends", []) if self.results.get(d, {}).get("result") != "pass"]
            if blocked:
                self._record(skipped_case(cid, spec, f"prerequisite {', '.join(blocked)} did not pass"))
                continue
            try:
                handlers[spec["kind"]](cid, spec)
            except AbortRun as exc:
                if cid not in self.results:
                    self._record(skipped_case(cid, spec, str(exc)))
                raise

    # -- cleanup ------------------------------------------------------------------------------------------------------
    @staticmethod
    def _path_ids_h2(path: str) -> list[str]:
        parts = path.split("?", 1)[0].strip("/").split("/")
        collections = {"routes", "brokers", "agent-workloads", "clients", "applications", "memberships",
                       "sessions", "users", "roles"}
        return [parts[i + 1] for i, seg in enumerate(parts[:-1]) if seg in collections]

    def _cleanup_fail(self, step: str, reason: str) -> None:
        self.cleanup_incomplete = True
        self.emit({"event": "cleanup", "step": step, "ok": False, "reason": reason})

    def _cleanup_call(self, step: str, method: str, path: str, body: Any = None,
                      emit_ok: bool = True) -> tuple[bool, Any, Any]:
        if self.admin_token is None:
            self._cleanup_fail(step, "no admin token")
            return False, None, None
        if not all(SAFE_ID.match(seg) for seg in self._path_ids_h2(path)):
            self._cleanup_fail(step, "unsafe server id")
            return False, None, None
        status, raw = self.request(method, path, json_body=body, bearer=self.admin_token, abort_on_5xx=False)
        if status == 401 and not self._relogged:
            self._relogged = True
            if self._relogin():
                status, raw = self.request(method, path, json_body=body, bearer=self.admin_token,
                                           abort_on_5xx=False)
        ok = isinstance(status, int) and 200 <= status < 300
        if not ok:
            self.cleanup_incomplete = True
        if emit_ok or not ok:
            self.emit({"event": "cleanup", "step": step, "ok": ok, "status": status,
                       **({} if ok else h1.error_fields(raw))})
        return ok, status, raw

    def _cleanup_sessions(self, step: str, user_role: str) -> None:
        pid = self.h2.users[user_role]
        if not _safe_id(pid):
            self._cleanup_fail(step, "unsafe server id")
            return
        query = urllib.parse.urlencode({"principalId": str(pid), "status": "ACTIVE", "size": 100})
        base = f"/admin/tenants/{TENANT}/sessions"
        ok, status, raw = self._cleanup_call(f"{step}:list", "GET", f"{base}?{query}", emit_ok=False)
        if not ok:
            return
        doc = parse_json(raw)
        items = doc if isinstance(doc, list) else (doc.get("content") if isinstance(doc, dict) else None)
        if not isinstance(items, list):
            self._cleanup_fail(f"{step}:list", "unrecognised session list")
            return
        total = doc.get("totalElements") if isinstance(doc, dict) else None
        truncated = isinstance(total, int) and total > len(items)
        active = [it for it in items if isinstance(it, dict) and it.get("status", "ACTIVE") == "ACTIVE"]
        if truncated:
            self.cleanup_incomplete = True
        self.emit({"event": "cleanup", "step": f"{step}:list", "ok": not truncated, "status": status,
                   "active_sessions": len(active), "truncated": truncated})
        for it in active:
            sid, rev = it.get("id"), it.get("revision")
            if not _safe_id(sid) or _int(rev) is None:
                self._cleanup_fail(f"{step}:session", "unsafe session id or revision")
                continue
            self._cleanup_call(f"{step}:{sid}", "POST", f"{base}/{sid}/revoke", {"expectedRevision": rev})

    def cleanup_steps(self) -> list[tuple[str, Callable[[str], None]]]:
        base = f"/admin/tenants/{TENANT}"
        c = self.h2
        steps: list[tuple[str, Callable[[str], None]]] = []

        def call(method: str, path_fn: Callable[[], str], *ids: Any) -> Callable[[str], None]:
            def run(step: str) -> None:
                if not all(_safe_id(i) for i in ids):
                    self._cleanup_fail(step, "unsafe server id")
                    return
                self._cleanup_call(step, method, path_fn())
            return run

        for role in USER_ROLES:
            if role in c.users:
                steps.append((f"revoke_sessions:{role}", lambda step, role=role: self._cleanup_sessions(step, role)))
        for key in reversed(ROUTE_KEYS):
            if key in c.routes:
                rid = c.routes[key]
                steps.append((f"revoke_route:{key}",
                              call("POST", lambda rid=rid: f"{base}/agent-exchange/routes/{rid}/revoke", rid)))
        if c.broker is not None:
            bid = c.broker
            steps.append(("revoke_broker", call("POST", lambda: f"{base}/agent-exchange/brokers/{bid}/revoke", bid)))
        for role in WORKLOAD_ROLES:
            if role in c.workloads:
                wid = c.workloads[role]
                steps.append((f"revoke_workload:{role}",
                              call("POST", lambda wid=wid: f"{base}/ciam/agent-workloads/{wid}/revoke", wid)))
        for role in self.names["clients"]:
            if role in c.clients:
                app_id, cuuid = c.clients[role]
                steps.append((f"disable_client:{role}", call(
                    "DELETE", lambda a=app_id, u=cuuid: f"{base}/applications/{a}/clients/{u}", app_id, cuuid)))
        if c.membership is not None:
            mapp = c.apps.get(self.names["membership"]["app"])
            mid = c.membership
            steps.append(("remove_membership", call(
                "DELETE", lambda: f"{base}/applications/{mapp}/access/memberships/{mid}", mapp, mid)))
        for role in USER_ROLES:
            if role in c.users:
                uid = c.users[role]
                steps.append((f"delete_user:{role}", call("DELETE", lambda uid=uid: f"/users/{uid}", uid)))
        for role in APP_ROLES:
            if role in c.apps:
                aid = c.apps[role]
                steps.append((f"disable_application:{role}",
                              call("DELETE", lambda aid=aid: f"{base}/applications/{aid}", aid)))
        return steps

    def cleanup(self) -> None:
        steps = self.cleanup_steps()
        if not steps:
            return
        if not self._pf_alive() and self.pf is not None:
            if not self._restart_port_forward_for_cleanup():
                for step, _fn in steps:
                    self.emit({"event": "cleanup", "step": step, "ok": False, "reason": "no port-forward"})
                self.cleanup_incomplete = True
                return
        self._relogged = False
        for step, fn in steps:
            try:
                fn(step)
            except (AbortRun, HarnessError) as exc:
                self._cleanup_fail(step, str(exc))
            except Exception as exc:  # noqa: BLE001 - never stop the remaining steps; type only (may carry data)
                self._cleanup_fail(step, f"unexpected {type(exc).__name__}")

    # -- orchestration ------------------------------------------------------------------------------------------------
    def run(self) -> int:
        self.emit({"event": "run_start", "prefix": self.prefix, "context": CONTEXT, "namespace": NAMESPACE,
                   "tool_needs_client": self.tool_needs_client})
        try:
            self.v1_context()
            self.v2_namespace()
            self.v3_release()
            self.v4_pod()
            self.v5_secret()
            self.v6_port()
            try:
                self.start_port_forward()
                self.v7_discovery()
                self.v8_readiness()
                self.v9_login()
                self.v10_no_collision()
                self.setup()
                self.run_cases()
            except (AbortRun, HarnessError) as exc:
                self._abort(f"{type(exc).__name__}: {exc}")
            except KeyboardInterrupt:
                self._abort("interrupted")
            except Exception as exc:  # noqa: BLE001 - fail closed; message omitted (may carry data)
                self._abort(f"unexpected {type(exc).__name__}")
            finally:
                try:
                    self.cleanup()
                finally:
                    self.stop_port_forward()
        except (AbortRun, HarnessError) as exc:
            self._abort(f"{type(exc).__name__}: {exc}")
        except KeyboardInterrupt:
            self._abort("interrupted")
        except Exception as exc:  # noqa: BLE001
            self._abort(f"unexpected {type(exc).__name__}")
        cases = self.expectations["cases"]
        for cid in self.case_ids:
            if cid not in self.results:
                self._record(skipped_case(cid, cases[cid], "aborted" if self.aborted else "not run"))
        counts = {k: sum(1 for cid in self.case_ids if self.results[cid]["result"] == k)
                  for k in ("pass", "fail", "skipped")}
        summary = {"event": "summary", "package": PACKAGE, "prefix": self.prefix, "cases": len(self.case_ids),
                   "passed": counts["pass"], "failed": counts["fail"], "skipped": counts["skipped"],
                   "aborted": self.aborted, "abort_reason": self.abort_reason,
                   "redaction_violation": self.redactor.violation, "cleanup_complete": not self.cleanup_incomplete,
                   "port_forward_leaked": self.pf_leaked, "location_rewrites": self.location_rewrites}
        self.emit(summary)
        if self.aborted or self.redactor.violation or self.cleanup_incomplete or self.pf_leaked:
            return 2
        if counts["pass"] == len(self.case_ids):
            return 0
        return 1


# ---------------------------------------------------------------------------------------------------------------------
# Plan mode and CLI
# ---------------------------------------------------------------------------------------------------------------------

CLEANUP_ORDER = ["revoke ACTIVE sessions of <p>-user and <p>-nomember", "revoke routes R4, R3, R2, R1",
                 "revoke broker", "revoke workloads", "disable clients", "remove membership",
                 "soft-delete users", "disable applications", "stop port-forward"]


def plan_events(expectations: dict | None = None, tool_needs_client: bool = TOOL_NEEDS_CLIENT) -> list[dict]:
    table = expectations or H2_EXPECTATIONS
    names = identity_names_h2("<p>", tool_needs_client)
    variables = base_vars("<p>", names)
    events: list[dict] = [{"event": "h2_plan", "package": PACKAGE, "mode": "dry",
                           "note": "no subprocess or network calls; pass --execute to run",
                           "context": CONTEXT, "namespace": NAMESPACE, "expected_issuer": EXPECTED_ISSUER,
                           "prefix_template": "p0h + secrets.token_hex(5)", "redirect_uri": REDIRECT_URI,
                           "tool_needs_client": tool_needs_client}]
    for ev in h1.plan_events():
        if ev.get("event") == "plan_verify":
            events.append({**ev, "event": "h2_plan_verify", "package": PACKAGE})
    events.append({"event": "h2_plan_identities", "package": PACKAGE, **names})
    for cid in table["order"]:
        spec = table["cases"][cid]
        ev = {"event": "h2_plan_case", "package": PACKAGE, "case_id": cid, "class": spec["class"],
              "kind": spec["kind"], "depends": list(spec.get("depends", [])), "expected": spec["description"]}
        if spec["kind"] == "exchange":
            ev["requester"] = names["clients"][spec["requester"]]["clientId"]
            ev["subject"] = spec["subject"]
            ev["audience"] = resolve_for_display(spec["audience"], variables)
            ev["scope"] = spec["scope"]
        if "checks" in spec:
            ev["checks"] = [[c[0], *[resolve_for_display(x, variables) for x in c[1:]]] for c in spec["checks"]]
        else:
            ev["denial"] = spec["denial"]
        events.append(ev)
    events.append({"event": "h2_plan_cleanup", "package": PACKAGE, "order": CLEANUP_ORDER,
                   "persists": "application role and audit rows have no delete API"})
    return events


def main(argv: list[str] | None = None, *, out: Any = None, runner_factory: Callable[..., H2Runner] = H2Runner) -> int:
    out = out if out is not None else sys.stdout
    if sys.version_info < (3, 13):
        sys.stderr.write("phase0_harness_h2 requires Python 3.13+\n")
        return 2
    parser = argparse.ArgumentParser(description="Phase 0.2 isolated harness, package H-2 "
                                                 "(H-1 stays in phase0_harness.py)")
    parser.add_argument("--package", required=True, choices=("h2",), help="test package to run (h2 only)")
    parser.add_argument("--execute", action="store_true", help="actually run against the isolated release")
    args = parser.parse_args(argv)
    if not args.execute:
        for ev in plan_events():
            out.write(json.dumps(ev) + "\n")
        return 0

    def _interrupt(signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _interrupt)
    return runner_factory(out=out).run()


if __name__ == "__main__":
    sys.exit(main())
