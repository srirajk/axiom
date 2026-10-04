#!/opt/homebrew/bin/python3.13
"""Phase 0.2 H-1 isolated OAuth issuance and exchange harness.

Implements package H-1 of docs/operations/phase-0.2-test-harness-design.md (revision 2).

Black-box functional test of the ISOLATED release in namespace ``axiom-phase0-test`` on kube context
``docker-desktop``, reached host-side through ``kubectl port-forward``. Standard library only.

Usage:
    /opt/homebrew/bin/python3.13 -I -B phase0_harness.py            # print the plan only (no subprocess, no network)
    /opt/homebrew/bin/python3.13 -I -B phase0_harness.py --execute  # actually run

Output is JSON Lines on stdout only. No file is written. Exit code: 0 all five cases passed and no abort;
1 any case failed; 2 abort (verification, setup, 5xx, port-forward loss) or refusal.
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import queue
import re
import signal
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# ---------------------------------------------------------------------------------------------------------------------
# Constants (design §2)
# ---------------------------------------------------------------------------------------------------------------------

CONTEXT = "docker-desktop"
NAMESPACE = "axiom-phase0-test"
RELEASE = "axiom"
CHART = "axiom-0.1.3"
EXPECTED_DIGEST = "sha256:42e702bffa8ebf863f976587297a32914eb76bd1382df78fcd90c5630740903f"
EXPECTED_ISSUER = "http://axiom.axiom-phase0-test.svc.cluster.local:8084"
TENANT = "meridian"
SCOPE = "quickstart:invoke"
EXTRA_SCOPE = "cards:incident.read"
SECRET_NAME = "axiom-runtime"
SECRET_KEY = "axiom.bootstrap.admin-password"
ADMIN_USERNAME = "admin"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

SERVICE_PORT = 8084
SERVER_LABEL_SELECTOR = "app.kubernetes.io/instance=axiom,app.kubernetes.io/component=server"
SERVER_CONTAINER = "server"
ADMIN_AUDIENCE = "axiom-api"
ADMIN_ROLE = "platform_admin"
ROUTE_PURPOSE = "phase0 H-1 isolated test"

PORT_BASE = 41000
PORT_SPAN = 8000
PORT_ATTEMPTS = 5
PORT_FORWARD_READY_TIMEOUT = 20.0
PORT_FORWARD_STOP_TIMEOUT = 5.0
CMD_TIMEOUT = 30.0
HTTP_TIMEOUT = 15.0
EXCHANGE_MAX_LIFETIME = 300
CLOCK_SKEW = 5
MAX_WORKLOAD_LIFETIME = 3600

ALLOWED_CLAIMS = (
    "typ", "kid", "iss", "sub", "aud", "scope", "exp", "iat", "tenant_id", "identity_kind", "client_id",
    "azp", "act", "token_use", "authority_profile", "authority_id", "sid", "subject_sid",
)

FORBIDDEN_ARGS = frozenset({"-A", "--all-namespaces", "axiom", "-n", "--namespace", "--context", "--kube-context",
                            "-s", "--server", "--cluster", "--user", "--token", "--as", "--as-group", "--as-uid",
                            "--insecure-skip-tls-verify"})
FORBIDDEN_ARG_PREFIXES = ("--namespace=", "--context=", "--kube-context=", "-n=", "--all-namespaces=", "--kubeconfig",
                          "--server=", "--cluster=", "--user=", "--token=", "--as=", "--as-group=", "--as-uid=",
                          "--insecure-skip-tls-verify=")
# Server-issued identifiers are interpolated into cleanup paths only if they match this shape.
SAFE_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
# Proxy variables are removed from child-process environments so kubectl/helm talk to the cluster directly.
PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy",
                  "no_proxy")

CASE_IDS = ("H1-P1", "H1-P2", "H1-N1", "H1-N2", "H1-N3")
REDACTED = "<redacted>"


class HarnessError(Exception):
    """Programming or safety-rule violation (never caught silently)."""


class AbortRun(Exception):
    """Abort condition (design §7): verification failure, setup failure, 5xx, port-forward loss."""


# ---------------------------------------------------------------------------------------------------------------------
# Command builder (design §3)
# ---------------------------------------------------------------------------------------------------------------------

def _check_args(args: Iterable[str]) -> list[str]:
    out = []
    for a in args:
        if not isinstance(a, str):
            raise HarnessError("command arguments must be strings")
        if a in FORBIDDEN_ARGS:
            raise HarnessError(f"forbidden argument: {a!r}")
        if a.startswith(FORBIDDEN_ARG_PREFIXES):
            raise HarnessError(f"forbidden argument: {a!r}")
        out.append(a)
    return out


def build_command(tool: str, verb: str, *args: str, namespace: str = NAMESPACE, context: str = CONTEXT) -> list[str]:
    """Build a kubectl/helm argv from the fixed template.

    kubectl --context docker-desktop <verb> -n axiom-phase0-test <args...>
    helm --kube-context docker-desktop <verb> -n axiom-phase0-test <args...>
    """
    if namespace != NAMESPACE:
        raise HarnessError(f"refusing namespace {namespace!r}; only {NAMESPACE!r} is allowed")
    if context != CONTEXT:
        raise HarnessError(f"refusing context {context!r}; only {CONTEXT!r} is allowed")
    if verb in ("config",):
        raise HarnessError("use build_context_check_command for kubectl config")
    checked = _check_args([verb, *args])
    if tool == "kubectl":
        return ["kubectl", "--context", CONTEXT, checked[0], "-n", NAMESPACE, *checked[1:]]
    if tool == "helm":
        return ["helm", "--kube-context", CONTEXT, checked[0], "-n", NAMESPACE, *checked[1:]]
    raise HarnessError(f"unsupported tool {tool!r}")


def build_context_check_command(context: str = CONTEXT) -> list[str]:
    """V-1 special case: a kubeconfig read that takes no namespace and only the literal context name."""
    if context != CONTEXT:
        raise HarnessError(f"refusing context {context!r}; only {CONTEXT!r} is allowed")
    return ["kubectl", "config", "get-contexts", CONTEXT]


def child_env() -> dict:
    """Environment for kubectl/helm: inherited, minus proxy variables."""
    return {k: v for k, v in os.environ.items() if k not in PROXY_ENV_VARS}


def default_run_cmd(argv: list[str], timeout: float = CMD_TIMEOUT) -> subprocess.CompletedProcess:
    if not isinstance(argv, list) or not argv or argv[0] not in ("kubectl", "helm"):
        raise HarnessError("run_cmd only executes kubectl/helm argv lists")
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False, check=False,
                          env=child_env())


def default_popen(argv: list[str]) -> subprocess.Popen:
    if not isinstance(argv, list) or not argv or argv[0] != "kubectl":
        raise HarnessError("popen only starts kubectl argv lists")
    # start_new_session: a terminal Ctrl-C must not kill the forward before cleanup has used it.
    return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            text=True, shell=False, bufsize=1, env=child_env(), start_new_session=True)


# ---------------------------------------------------------------------------------------------------------------------
# Sensitive values and redaction (design §3)
# ---------------------------------------------------------------------------------------------------------------------

class SensitiveValue:
    """In-memory holder for a secret; never renders its content."""

    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return REDACTED

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return REDACTED


class Redactor:
    """Final output guard: no registered sensitive string may reach stdout."""

    def __init__(self) -> None:
        self._values: set[str] = set()
        self.violation = False

    def register(self, value: Any) -> None:
        if isinstance(value, SensitiveValue):
            value = value.reveal()
        if not isinstance(value, str) or not value:
            return
        self._values.add(value)
        for form in (json.dumps(value)[1:-1], urllib.parse.quote_plus(value), urllib.parse.quote(value, safe="")):
            if form:
                self._values.add(form)

    def guard(self, line: str) -> str:
        # Longest first so a value containing another is replaced whole.
        for value in sorted(self._values, key=len, reverse=True):
            if value in line:
                line = line.replace(value, REDACTED)
                self.violation = True
        return line


def token_hash(token: Any) -> str | None:
    if not isinstance(token, str) or not token:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------------------------------------------------
# JWT and claim helpers (display only; no signature verification)
# ---------------------------------------------------------------------------------------------------------------------

def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment:
        raise ValueError("empty segment")
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def decode_jwt(token: Any) -> tuple[dict, dict]:
    """Return (header, payload). Raises ValueError for anything that is not a 3-part JWS with JSON objects."""
    if not isinstance(token, str):
        raise ValueError("token is not a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token is not a three-part JWS")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"undecodable JWT segment: {type(exc).__name__}") from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header/payload is not an object")
    return header, payload


def normalize_aud(aud: Any) -> list | None:
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list) and all(isinstance(a, str) for a in aud):
        return list(aud)
    return None


def normalize_scope(scope: Any) -> set | None:
    if isinstance(scope, str):
        return set(scope.split())
    if isinstance(scope, list) and all(isinstance(s, str) for s in scope):
        out: set[str] = set()
        for s in scope:
            out.update(s.split())
        return out
    return None


def normalize_roles(roles: Any) -> set:
    if isinstance(roles, str):
        return set(roles.replace(",", " ").split())
    if isinstance(roles, list):
        return {r for r in roles if isinstance(r, str)}
    return set()


def filter_claims(claims: Any) -> dict:
    if not isinstance(claims, dict):
        return {}
    out = {}
    for k in ALLOWED_CLAIMS:
        if k in claims:
            v = claims[k]
            out[k] = filter_claims(v) if isinstance(v, dict) else v
    return out


def parse_json(body: Any) -> Any:
    if isinstance(body, (dict, list)):
        return body
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray)):
        try:
            body = bytes(body).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(body, str) or not body.strip():
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def error_fields(body: Any) -> dict:
    parsed = parse_json(body)
    if not isinstance(parsed, dict):
        return {"error": None, "error_description": None}
    return {"error": parsed.get("error"), "error_description": parsed.get("error_description")}


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


# ---------------------------------------------------------------------------------------------------------------------
# Per-run identities (design §5)
# ---------------------------------------------------------------------------------------------------------------------

def new_prefix(token_hex: Callable[[int], str] = secrets.token_hex) -> str:
    return "p0h" + token_hex(5)


def identity_names(p: str) -> dict:
    return {
        "applications": {
            "entry": {"applicationKey": f"{p}-entry", "audience": f"agent:{TENANT}:{p}-entry"},
            "gateway": {"applicationKey": f"{p}-gateway", "audience": f"{p}-gateway"},
            "sibling": {"applicationKey": f"{p}-sibling", "audience": f"agent:{TENANT}:{p}-sibling"},
        },
        "clients": {"entry": f"{p}-entry", "gateway": f"{p}-gateway-broker", "sibling": f"{p}-sibling"},
        "workloads": {"entry": f"agent:{p}-entry:test", "sibling": f"agent:{p}-sibling:test"},
        "gateway_audience": f"{p}-gateway",
        "sibling_audience": f"agent:{TENANT}:{p}-sibling",
    }


# ---------------------------------------------------------------------------------------------------------------------
# Case evaluators (design §6) — pure functions
# ---------------------------------------------------------------------------------------------------------------------

@dataclass
class CaseContext:
    prefix: str
    route_id: Any = None
    p1_exp: int | None = None
    now: Callable[[], float] = time.time
    entry_workload_id: Any = None
    request_time: float | None = None


CASE_META = {
    "H1-P1": ("positive", "200 Bearer; typ at+jwt; iss; sub=client_id=<p>-entry; aud=[agent:meridian:<p>-entry]; "
                          "identity_kind=workload; tenant_id=meridian; scope=quickstart:invoke; no sid; exp-iat<=3600"),
    "H1-P2": ("positive", "200; issued_token_type=access_token urn; authority_id=R1; sub=<p>-entry; aud=[<p>-gateway]; "
                          "act.sub=agent:<p>-entry:test; act.client_id=<p>-entry; act.workload_id=<entry workload>; "
                          "client_id=azp=<p>-entry; identity_kind=workload; authority_profile=workload_continuation; "
                          "token_use=gateway_authorization; scope=quickstart:invoke; exp<=min(P1.exp, now+305)"),
    "H1-N1": ("wrong_audience", "400 invalid_target; no access_token"),
    "H1-N2": ("wrong_redeemer", "400 invalid_grant; no access_token"),
    "H1-N3": ("over_broad_scope", "400 invalid_scope; no access_token"),
}


def _case_result(case_id: str, observed: dict, mismatches: list[str]) -> dict:
    cls, expected = CASE_META[case_id]
    return {"event": "case", "case_id": case_id, "class": cls, "expected": expected, "observed": observed,
            "mismatches": mismatches, "result": "pass" if not mismatches else "fail"}


def skipped_case(case_id: str, reason: str) -> dict:
    cls, expected = CASE_META[case_id]
    return {"event": "case", "case_id": case_id, "class": cls, "expected": expected,
            "observed": {"skipped_reason": reason}, "mismatches": [], "result": "skipped"}


def _decode_access_token(body: dict, observed: dict, mismatches: list[str]) -> tuple[dict, dict] | None:
    token = body.get("access_token")
    if not isinstance(token, str) or not token:
        mismatches.append("access_token missing")
        return None
    observed["token_sha256_12"] = token_hash(token)
    try:
        header, claims = decode_jwt(token)
    except ValueError as exc:
        mismatches.append(f"access_token not decodable: {exc}")
        return None
    observed["header"] = filter_claims(header)
    observed["claims"] = filter_claims(claims)
    return header, claims


def evaluate_p1(status: int, body: Any, ctx: CaseContext) -> dict:
    parsed = parse_json(body)
    observed: dict = {"status": status, **error_fields(parsed)}
    m: list[str] = []
    entry = f"{ctx.prefix}-entry"
    if status != 200:
        m.append(f"status {status} != 200")
    if not isinstance(parsed, dict):
        m.append("body is not a JSON object")
        return _case_result("H1-P1", observed, m)
    tt = parsed.get("token_type")
    observed["token_type"] = tt
    if not isinstance(tt, str) or tt.lower() != "bearer":
        m.append("token_type != Bearer")
    decoded = _decode_access_token(parsed, observed, m)
    if decoded is None:
        return _case_result("H1-P1", observed, m)
    header, c = decoded
    if header.get("typ") != "at+jwt":
        m.append("header typ != at+jwt")
    if c.get("iss") != EXPECTED_ISSUER:
        m.append("iss mismatch")
    if c.get("sub") != entry:
        m.append("sub mismatch")
    if c.get("client_id") != entry:
        m.append("client_id mismatch")
    if normalize_aud(c.get("aud")) != [f"agent:{TENANT}:{entry}"]:
        m.append("aud mismatch")
    if c.get("identity_kind") != "workload":
        m.append("identity_kind != workload")
    if c.get("tenant_id") != TENANT:
        m.append("tenant_id mismatch")
    if normalize_scope(c.get("scope")) != {SCOPE}:
        m.append("scope != {quickstart:invoke}")
    if "sid" in c:
        m.append("sid present")
    exp, iat = _int(c.get("exp")), _int(c.get("iat"))
    if exp is None or iat is None:
        m.append("exp/iat missing or not integer")
    elif not (0 < exp - iat <= MAX_WORKLOAD_LIFETIME):
        m.append(f"exp-iat {exp - iat} not in (0, {MAX_WORKLOAD_LIFETIME}]")
    return _case_result("H1-P1", observed, m)


def evaluate_p2(status: int, body: Any, ctx: CaseContext) -> dict:
    parsed = parse_json(body)
    observed: dict = {"status": status, **error_fields(parsed)}
    m: list[str] = []
    entry = f"{ctx.prefix}-entry"
    if status != 200:
        m.append(f"status {status} != 200")
    if not isinstance(parsed, dict):
        m.append("body is not a JSON object")
        return _case_result("H1-P2", observed, m)
    observed["issued_token_type"] = parsed.get("issued_token_type")
    observed["response_authority_id"] = parsed.get("authority_id")
    if parsed.get("issued_token_type") != ACCESS_TOKEN_TYPE:
        m.append("issued_token_type mismatch")
    route = None if ctx.route_id is None else str(ctx.route_id)
    if route is None:
        m.append("route id unknown")
    elif parsed.get("authority_id") is None or str(parsed.get("authority_id")) != route:
        m.append("response authority_id != route id")
    decoded = _decode_access_token(parsed, observed, m)
    if decoded is None:
        return _case_result("H1-P2", observed, m)
    _header, c = decoded
    if c.get("sub") != entry:
        m.append("sub mismatch")
    if normalize_aud(c.get("aud")) != [f"{ctx.prefix}-gateway"]:
        m.append("aud mismatch")
    act = c.get("act")
    if not isinstance(act, dict):
        m.append("act missing")
    else:
        if act.get("sub") != f"agent:{entry}:test":
            m.append("act.sub mismatch")
        if act.get("client_id") != entry:
            m.append("act.client_id mismatch")
        if ctx.entry_workload_id is not None and str(act.get("workload_id")) != str(ctx.entry_workload_id):
            m.append("act.workload_id mismatch")
    if c.get("client_id") != entry:
        m.append("client_id mismatch")
    if c.get("azp") != entry:
        m.append("azp mismatch")
    if c.get("identity_kind") != "workload":
        m.append("identity_kind != workload")
    # Exchanged tokens carry a durable session (sid); record it, do not assert on it.
    observed["sid_present"] = "sid" in c
    if c.get("authority_profile") != "workload_continuation":
        m.append("authority_profile mismatch")
    if c.get("token_use") != "gateway_authorization":
        m.append("token_use mismatch")
    if route is None or c.get("authority_id") is None or str(c.get("authority_id")) != route:
        m.append("claim authority_id != route id")
    if normalize_scope(c.get("scope")) != {SCOPE}:
        m.append("scope != {quickstart:invoke}")
    exp = _int(c.get("exp"))
    if exp is None:
        m.append("exp missing or not integer")
    elif ctx.p1_exp is None:
        m.append("P1 exp unknown")
    else:
        issued_no_later_than = ctx.request_time if ctx.request_time is not None else ctx.now()
        bound = min(ctx.p1_exp, int(issued_no_later_than) + EXCHANGE_MAX_LIFETIME + CLOCK_SKEW)
        observed["exp_bound"] = bound
        if exp > bound:
            m.append(f"exp {exp} > bound {bound}")
    return _case_result("H1-P2", observed, m)


def _evaluate_denial(case_id: str, expected_error: str, status: int, body: Any) -> dict:
    parsed = parse_json(body)
    observed: dict = {"status": status, **error_fields(parsed)}
    m: list[str] = []
    if status != 400:
        m.append(f"status {status} != 400")
    if not isinstance(parsed, dict):
        m.append("body is not a JSON object")
        observed["access_token_present"] = None
        return _case_result(case_id, observed, m)
    present = "access_token" in parsed
    observed["access_token_present"] = present
    if present:
        observed["token_sha256_12"] = token_hash(parsed.get("access_token"))
        m.append("access_token present in denial body")
    if parsed.get("error") != expected_error:
        m.append(f"error != {expected_error}")
    return _case_result(case_id, observed, m)


def evaluate_n1(status: int, body: Any, ctx: CaseContext) -> dict:
    return _evaluate_denial("H1-N1", "invalid_target", status, body)


def evaluate_n2(status: int, body: Any, ctx: CaseContext) -> dict:
    return _evaluate_denial("H1-N2", "invalid_grant", status, body)


def evaluate_n3(status: int, body: Any, ctx: CaseContext) -> dict:
    return _evaluate_denial("H1-N3", "invalid_scope", status, body)


# ---------------------------------------------------------------------------------------------------------------------
# Port selection (V-6) and URL guard
# ---------------------------------------------------------------------------------------------------------------------

def choose_port(rng: Callable[[int], int] = secrets.randbelow,
                socket_factory: Callable[..., Any] = socket.socket,
                attempts: int = PORT_ATTEMPTS) -> int | None:
    for _ in range(attempts):
        port = PORT_BASE + rng(PORT_SPAN)
        if not (PORT_BASE <= port < PORT_BASE + PORT_SPAN):
            continue
        s = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            s.close()
        return port
    return None


def base_url(port: int) -> str:
    if not isinstance(port, int) or not (PORT_BASE <= port < PORT_BASE + PORT_SPAN):
        raise HarnessError("port outside the harness range")
    return f"http://127.0.0.1:{port}/"


def check_url(url: str, port: int) -> str:
    prefix = base_url(port)
    if not isinstance(url, str) or not url.startswith(prefix):
        raise HarnessError("URL is not on the forwarded base")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.port != port or parts.username \
            or parts.password or parts.fragment:
        raise HarnessError("URL is not on the forwarded base")
    if any(ch in url for ch in ("\\", " ", "\r", "\n", "\t")):
        raise HarnessError("URL contains forbidden characters")
    return url


def make_url(port: int, path: str) -> str:
    """Fixed paths only: absolute URLs (e.g. from discovery metadata) are rejected."""
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "://" in path \
            or ".." in path.split("?")[0]:
        raise HarnessError("only fixed relative paths are allowed")
    return check_url(base_url(port)[:-1] + path, port)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def build_opener() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) disables environment proxies; redirects are never followed.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def default_http(method: str, url: str, headers: dict, body: bytes | None,
                 timeout: float = HTTP_TIMEOUT, _opener: Any = None) -> tuple[int, bytes]:
    opener = _opener or build_opener()
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        try:
            data = exc.read()
        except Exception:  # noqa: BLE001
            data = b""
        finally:
            exc.close()
        return exc.code, data


def basic_auth(client_id: str, secret: str) -> str:
    raw = urllib.parse.quote_plus(client_id) + ":" + urllib.parse.quote_plus(secret)
    return "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")


def parse_k8s_time(value: Any) -> _dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        t = _dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if t.tzinfo is None:
        return None
    return t


def iso_utc(epoch: float) -> str:
    return _dt.datetime.fromtimestamp(int(epoch), tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tail(text: Any, n: int = 300) -> str:
    if not isinstance(text, str):
        return ""
    return text.strip()[-n:]


# ---------------------------------------------------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------------------------------------------------

@dataclass
class Created:
    apps: dict = field(default_factory=dict)        # role -> appId
    clients: dict = field(default_factory=dict)     # role -> (appId, clientUuid)
    workloads: dict = field(default_factory=dict)   # role -> workloadId
    broker: Any = None
    route: Any = None


SECRET_KEYS_TEMPLATE = ('{{.metadata.namespace}}{{"\\n"}}{{.metadata.creationTimestamp}}{{"\\n"}}'
                        '{{range $k, $v := .data}}{{$k}}{{"\\n"}}{{end}}')
SECRET_VALUE_JSONPATH = r"jsonpath={.data.axiom\.bootstrap\.admin-password}"


class Runner:
    def __init__(self, *, run_cmd: Callable = default_run_cmd, popen: Callable = default_popen,
                 http: Callable = default_http, out: Any = None, now: Callable[[], float] = time.time,
                 prefix: str | None = None, port_chooser: Callable[[], int | None] = choose_port,
                 monotonic: Callable[[], float] = time.monotonic,
                 pf_ready_timeout: float = PORT_FORWARD_READY_TIMEOUT):
        self.run_cmd = run_cmd
        self.popen = popen
        self.http = http
        self.out = out if out is not None else sys.stdout
        self.now = now
        self.monotonic = monotonic
        self.port_chooser = port_chooser
        self.pf_ready_timeout = pf_ready_timeout
        self.redactor = Redactor()
        self.prefix = prefix or new_prefix()
        self.names = identity_names(self.prefix)
        self.port: int | None = None
        self.pf = None
        self._pf_lines: queue.Queue = queue.Queue()
        self.ns_created: _dt.datetime | None = None
        self.admin_password: SensitiveValue | None = None
        self.admin_token: SensitiveValue | None = None
        self.client_secrets: dict[str, SensitiveValue] = {}
        self.created = Created()
        self.results: dict[str, dict] = {}
        self.aborted = False
        self.cleanup_incomplete = False
        self.pf_leaked = False
        self.abort_reason: str | None = None

    # -- output -------------------------------------------------------------------------------------------------------
    def emit(self, event: dict) -> None:
        line = json.dumps(event, default=str)
        line = self.redactor.guard(line)
        self.out.write(line + "\n")
        try:
            self.out.flush()
        except Exception:  # noqa: BLE001
            pass

    def _sensitive(self, value: str) -> SensitiveValue:
        self.redactor.register(value)
        return SensitiveValue(value)

    def _verify(self, step: str, ok: bool, **detail: Any) -> None:
        self.emit({"event": "verify", "step": step, "ok": bool(ok), **detail})
        if not ok:
            raise AbortRun(f"{step} failed")

    # -- kubectl / helm -----------------------------------------------------------------------------------------------
    def _cmd(self, argv: list[str]) -> tuple[int, str, str]:
        """Run a kubectl/helm argv. Never logs; callers decide what (if anything) to emit."""
        try:
            cp = self.run_cmd(argv, CMD_TIMEOUT)
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except OSError as exc:
            return -1, "", f"{type(exc).__name__}"
        rc = getattr(cp, "returncode", -1)
        return rc, getattr(cp, "stdout", "") or "", getattr(cp, "stderr", "") or ""

    def v1_context(self) -> None:
        argv = build_context_check_command()
        rc, out, err = self._cmd(argv)
        found = rc == 0 and any(CONTEXT in line.split() for line in out.splitlines())
        self._verify("V-1", found, argv=argv, returncode=rc, stderr=_tail(err) if rc else "")

    def v2_namespace(self) -> None:
        argv = build_command("kubectl", "get", "ns", NAMESPACE, "-o", "json")
        rc, out, err = self._cmd(argv)
        doc = parse_json(out) if rc == 0 else None
        meta = doc.get("metadata") if isinstance(doc, dict) else None
        meta = meta if isinstance(meta, dict) else {}
        labels = meta.get("labels") if isinstance(meta.get("labels"), dict) else {}
        created = parse_k8s_time(meta.get("creationTimestamp"))
        ok = (rc == 0 and meta.get("name") == NAMESPACE
              and labels.get("pod-security.kubernetes.io/enforce") == "restricted" and created is not None)
        if ok:
            self.ns_created = created
        self._verify("V-2", ok, argv=argv, returncode=rc, name=meta.get("name"),
                     enforce=labels.get("pod-security.kubernetes.io/enforce"),
                     creationTimestamp=meta.get("creationTimestamp"), stderr=_tail(err) if rc else "")

    def v3_release(self) -> None:
        argv = build_command("helm", "list", "-o", "json")
        rc, out, err = self._cmd(argv)
        doc = parse_json(out) if rc == 0 else None
        releases = doc if isinstance(doc, list) else None
        ok = False
        detail: dict = {}
        if releases is not None and len(releases) == 1 and isinstance(releases[0], dict):
            r = releases[0]
            detail = {"name": r.get("name"), "chart": r.get("chart"), "status": r.get("status"),
                      "namespace": r.get("namespace")}
            ok = (r.get("name") == RELEASE and r.get("chart") == CHART and r.get("status") == "deployed"
                  and r.get("namespace") == NAMESPACE)
        self._verify("V-3", ok and rc == 0, argv=argv, returncode=rc,
                     release_count=None if releases is None else len(releases), **detail,
                     stderr=_tail(err) if rc else "")

    def v4_pod(self) -> None:
        argv = build_command("kubectl", "get", "pods", "-l", SERVER_LABEL_SELECTOR, "-o", "json")
        rc, out, err = self._cmd(argv)
        doc = parse_json(out) if rc == 0 else None
        items = doc.get("items") if isinstance(doc, dict) else None
        ok = False
        detail: dict = {"pod_count": None if not isinstance(items, list) else len(items)}
        if isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict):
            pod = items[0]
            status = pod.get("status") if isinstance(pod.get("status"), dict) else {}
            meta = pod.get("metadata") if isinstance(pod.get("metadata"), dict) else {}
            conds = status.get("conditions") if isinstance(status.get("conditions"), list) else []
            ready = any(isinstance(c, dict) and c.get("type") == "Ready" and c.get("status") == "True"
                        for c in conds)
            css = status.get("containerStatuses") if isinstance(status.get("containerStatuses"), list) else []
            server = [c for c in css if isinstance(c, dict) and c.get("name") == SERVER_CONTAINER]
            image_id = server[0].get("imageID") if len(server) == 1 else None
            c_ready = len(server) == 1 and server[0].get("ready") is True
            digest_ok = isinstance(image_id, str) and image_id.endswith(EXPECTED_DIGEST)
            ok = ready and c_ready and digest_ok and meta.get("namespace") == NAMESPACE
            detail.update({"pod": meta.get("name"), "ready": ready, "container_ready": c_ready,
                           "imageID": image_id, "digest_ok": digest_ok})
        self._verify("V-4", ok and rc == 0, argv=argv, returncode=rc, **detail, stderr=_tail(err) if rc else "")

    def v5_secret(self) -> None:
        argv = build_command("kubectl", "get", "secret", SECRET_NAME, "-o", "go-template=" + SECRET_KEYS_TEMPLATE)
        rc, out, err = self._cmd(argv)
        lines = out.splitlines() if rc == 0 else []
        ns = lines[0].strip() if len(lines) > 0 else None
        created_raw = lines[1].strip() if len(lines) > 1 else None
        keys = [l.strip() for l in lines[2:] if l.strip()]
        created = parse_k8s_time(created_raw)
        ok = (rc == 0 and ns == NAMESPACE and created is not None and self.ns_created is not None
              and created >= self.ns_created and SECRET_KEY in keys)
        self._verify("V-5", ok, argv=argv, returncode=rc, namespace=ns, creationTimestamp=created_raw,
                     namespaceCreationTimestamp=None if self.ns_created is None else self.ns_created.isoformat(),
                     key_present=SECRET_KEY in keys, key_count=len(keys), stderr=_tail(err) if rc else "")
        # Separate read of the one key. argv and output are never logged.
        vargv = build_command("kubectl", "get", "secret", SECRET_NAME, "-o", SECRET_VALUE_JSONPATH)
        rc, out, _err = self._cmd(vargv)
        raw = (out or "").strip()
        self.redactor.register(raw)
        value = None
        if rc == 0 and raw:
            try:
                value = base64.b64decode(raw, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                value = None
        del out, raw
        if value:
            self.admin_password = self._sensitive(value)
        self._verify("V-5-value", bool(value), returncode=rc, decoded=bool(value))

    # -- port-forward -------------------------------------------------------------------------------------------------
    def v6_port(self) -> None:
        port = self.port_chooser()
        if port is not None:
            self.port = port
        self._verify("V-6", port is not None, port=port)

    def start_port_forward(self) -> None:
        argv = build_command("kubectl", "port-forward", "svc/axiom", f"{self.port}:{SERVICE_PORT}",
                             "--address", "127.0.0.1")
        try:
            self.pf = self.popen(argv)
        except OSError as exc:
            self.emit({"event": "port_forward_start", "ok": False, "argv": argv, "error": type(exc).__name__})
            raise AbortRun("port-forward could not start") from None
        stream = getattr(self.pf, "stdout", None)
        if stream is not None:
            t = threading.Thread(target=self._drain, args=(stream,), daemon=True)
            t.start()
        want = f"Forwarding from 127.0.0.1:{self.port}"
        deadline = self.monotonic() + self.pf_ready_timeout
        ready = False
        while self.monotonic() < deadline:
            try:
                line = self._pf_lines.get(timeout=0.2)
            except queue.Empty:
                line = None
            if line is None:
                if self.pf.poll() is not None and self._pf_lines.empty():
                    break
                continue
            if want in line:
                ready = True
                break
        self.emit({"event": "port_forward_start", "ok": ready, "argv": argv, "port": self.port})
        if not ready:
            raise AbortRun("port-forward not ready")

    def _drain(self, stream: Any) -> None:
        try:
            for line in stream:
                self._pf_lines.put(line)
        except Exception:  # noqa: BLE001
            pass
        self._pf_lines.put(None)

    def stop_port_forward(self) -> None:
        if self.pf is None:
            return
        killed = False
        try:
            self.pf.terminate()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.pf.wait(timeout=PORT_FORWARD_STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            killed = True
            try:
                self.pf.kill()
                self.pf.wait(timeout=PORT_FORWARD_STOP_TIMEOUT)
            except Exception:  # noqa: BLE001
                pass
        exited = self.pf.poll() is not None
        if not exited:
            self.pf_leaked = True
        self.emit({"event": "port_forward_stop", "exited": exited, "killed": killed,
                   "returncode": self.pf.poll()})

    def _pf_alive(self) -> bool:
        return self.pf is not None and self.pf.poll() is None

    # -- HTTP ---------------------------------------------------------------------------------------------------------
    def request(self, method: str, path: str, *, json_body: Any = None, form: dict | None = None,
                bearer: SensitiveValue | None = None, basic: tuple[str, SensitiveValue] | None = None,
                abort_on_5xx: bool = True) -> tuple[int, Any]:
        if not self._pf_alive():
            raise AbortRun("port-forward lost")
        url = make_url(self.port, path)
        check_url(url, self.port)
        headers = {"Accept": "application/json"}
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
            hdr = basic_auth(basic[0], basic[1].reveal())
            self.redactor.register(hdr)
            self.redactor.register(hdr[len("Basic "):])
            headers["Authorization"] = hdr
        try:
            status, raw = self.http(method, url, headers, data, HTTP_TIMEOUT)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            if not self._pf_alive():
                raise AbortRun("port-forward lost") from None
            raise AbortRun(f"transport error {type(exc).__name__} on {method} {path}") from None
        finally:
            headers.clear()
        if abort_on_5xx and isinstance(status, int) and status >= 500:
            self.emit({"event": "http_5xx", "method": method, "path": path, "status": status,
                       **error_fields(raw)})
            raise AbortRun(f"5xx on {method} {path}")
        return status, raw

    def v7_discovery(self) -> None:
        # Issuer comes from the OIDC document. The token-exchange grant is asserted on the RFC 8414
        # metadata endpoint, because the server's own metadata customizer is attached there
        # (SecurityConfig authorizationServerMetadataEndpoint); its presence in openid-configuration
        # is framework-default behaviour and is not relied on.
        status, raw = self.request("GET", "/.well-known/openid-configuration")
        doc = parse_json(raw)
        doc = doc if isinstance(doc, dict) else {}
        m_status, m_raw = self.request("GET", "/.well-known/oauth-authorization-server")
        meta = parse_json(m_raw)
        meta = meta if isinstance(meta, dict) else {}
        grants = meta.get("grant_types_supported")
        exchange_ok = isinstance(grants, list) and TOKEN_EXCHANGE_GRANT in grants
        ok = (status == 200 and doc.get("issuer") == EXPECTED_ISSUER
              and m_status == 200 and meta.get("issuer") == EXPECTED_ISSUER and exchange_ok)
        self._verify("V-7", ok, status=status, issuer=doc.get("issuer"), metadata_status=m_status,
                     metadata_issuer=meta.get("issuer"), token_exchange_supported=exchange_ok)

    def v8_readiness(self) -> None:
        status, raw = self.request("GET", "/actuator/health/readiness")
        doc = parse_json(raw)
        st = doc.get("status") if isinstance(doc, dict) else None
        self._verify("V-8", status == 200 and st == "UP", status=status, readiness=st)

    def v9_login(self) -> None:
        if self.admin_password is None:
            self._verify("V-9", False, reason="no admin password")
        status, raw = self.request("POST", "/auth/login",
                                   json_body={"username": ADMIN_USERNAME, "password": self.admin_password.reveal()})
        doc = parse_json(raw)
        doc = doc if isinstance(doc, dict) else {}
        token = doc.get("accessToken")
        claims: dict = {}
        detail: dict = {"status": status}
        if isinstance(token, str) and token:
            self.redactor.register(token)
            detail["token_sha256_12"] = token_hash(token)
            try:
                _h, claims = decode_jwt(token)
            except ValueError:
                claims = {}
        for k in ("refreshToken", "refresh_token", "sessionToken"):
            if isinstance(doc.get(k), str):
                self.redactor.register(doc[k])
        roles = normalize_roles(claims.get("roles"))
        ok = (status == 200 and bool(claims) and claims.get("iss") == EXPECTED_ISSUER
              and claims.get("tenant_id") == TENANT and normalize_aud(claims.get("aud")) == [ADMIN_AUDIENCE]
              and ADMIN_ROLE in roles)
        detail.update({"iss": claims.get("iss"), "tenant_id": claims.get("tenant_id"), "aud": claims.get("aud"),
                       "platform_admin": ADMIN_ROLE in roles})
        if ok:
            self.admin_token = SensitiveValue(token)
        self._verify("V-9", ok, **detail)

    def v10_no_collision(self) -> None:
        status, raw = self.request("GET", f"/admin/tenants/{TENANT}/applications", bearer=self.admin_token)
        doc = parse_json(raw)
        items = doc if isinstance(doc, list) else (doc.get("content") if isinstance(doc, dict) else None)
        ok = status == 200 and isinstance(items, list)
        collisions = 0
        if ok:
            for it in items:
                key = it.get("applicationKey") if isinstance(it, dict) else None
                if isinstance(key, str) and key.startswith(self.prefix):
                    collisions += 1
        self._verify("V-10", ok and collisions == 0, status=status,
                     application_count=len(items) if isinstance(items, list) else None, collisions=collisions)

    # -- setup (design §5) --------------------------------------------------------------------------------------------
    def _admin_create(self, step: str, path: str, body: dict) -> dict:
        status, raw = self.request("POST", path, json_body=body, bearer=self.admin_token)
        doc = parse_json(raw)
        if status != 201 or not isinstance(doc, dict):
            self.emit({"event": "setup", "step": step, "ok": False, "status": status, **error_fields(doc)})
            raise AbortRun(f"setup {step} failed")
        return doc

    def setup(self) -> None:
        base = f"/admin/tenants/{TENANT}"
        apps = self.names["applications"]
        for role in ("entry", "gateway", "sibling"):
            spec = apps[role]
            doc = self._admin_create(f"application:{role}", f"{base}/applications", {
                "applicationKey": spec["applicationKey"], "displayName": spec["applicationKey"],
                "description": "phase0 H-1 isolated test", "audience": spec["audience"]})
            app_id = doc.get("id")
            if app_id is None:
                self.emit({"event": "setup", "step": f"application:{role}", "ok": False, "reason": "no id"})
                raise AbortRun("application id missing")
            self.created.apps[role] = app_id
            self.emit({"event": "setup", "step": f"application:{role}", "ok": True, "id": app_id,
                       "applicationKey": spec["applicationKey"], "audience": spec["audience"]})
        for role in ("entry", "gateway", "sibling"):
            app_id = self.created.apps[role]
            client_id = self.names["clients"][role]
            doc = self._admin_create(f"client:{role}", f"{base}/applications/{app_id}/clients", {
                "clientId": client_id, "clientType": "CONFIDENTIAL_SERVICE", "redirectUris": [],
                "postLogoutRedirectUris": [], "scopes": [SCOPE]})
            client = doc.get("client") if isinstance(doc.get("client"), dict) else {}
            secret = doc.get("serviceSecret")
            if isinstance(secret, str) and secret:
                self.client_secrets[role] = self._sensitive(secret)
            if client.get("id") is not None:
                self.created.clients[role] = (app_id, client.get("id"))
            if client.get("id") is None or client.get("clientId") != client_id or not (isinstance(secret, str)
                                                                                       and secret):
                self.emit({"event": "setup", "step": f"client:{role}", "ok": False,
                           "reason": "client id/clientId/serviceSecret missing or mismatched"})
                raise AbortRun("client response incomplete")
            self.emit({"event": "setup", "step": f"client:{role}", "ok": True, "id": client.get("id"),
                       "clientId": client_id})
        for role in ("entry", "sibling"):
            ref = self.names["workloads"][role]
            doc = self._admin_create(f"workload:{role}", f"{base}/ciam/agent-workloads", {
                "workloadRef": ref, "name": ref, "oauthClientId": self.names["clients"][role]})
            if doc.get("id") is None:
                self.emit({"event": "setup", "step": f"workload:{role}", "ok": False, "reason": "no id"})
                raise AbortRun("workload id missing")
            self.created.workloads[role] = doc.get("id")
            self.emit({"event": "setup", "step": f"workload:{role}", "ok": True, "id": doc.get("id"),
                       "workloadRef": ref})
        doc = self._admin_create("broker", f"{base}/agent-exchange/brokers", {
            "oauthClientId": self.names["clients"]["gateway"], "gatewayAudience": self.names["gateway_audience"],
            "scopes": [SCOPE]})
        if doc.get("id") is None:
            raise AbortRun("broker id missing")
        self.created.broker = doc.get("id")
        self.emit({"event": "setup", "step": "broker", "ok": True, "id": doc.get("id")})
        doc = self._admin_create("route", f"{base}/agent-exchange/routes", {
            "sourceWorkloadId": self.created.workloads["entry"], "destinationType": "GATEWAY",
            "destinationWorkloadId": None, "audience": self.names["gateway_audience"], "scopes": [SCOPE],
            "purpose": ROUTE_PURPOSE, "expiresAt": iso_utc(self.now() + 3600)})
        if doc.get("id") is None:
            raise AbortRun("route id missing")
        self.created.route = doc.get("id")
        self.emit({"event": "setup", "step": "route", "ok": True, "id": doc.get("id")})

    # -- cases (design §6) --------------------------------------------------------------------------------------------
    def _record(self, result: dict) -> dict:
        self.results[result["case_id"]] = result
        self.emit(result)
        return result

    def _register_body_tokens(self, raw: Any) -> None:
        doc = parse_json(raw)
        if isinstance(doc, dict):
            for k in ("access_token", "refresh_token", "id_token"):
                if isinstance(doc.get(k), str):
                    self.redactor.register(doc[k])

    def _run_case(self, case_id: str, role: str, form: dict, evaluator: Callable, ctx: CaseContext) -> dict:
        ctx.request_time = self.now()
        try:
            status, raw = self.request("POST", "/oauth/token", form=form,
                                       basic=(self.names["clients"][role], self.client_secrets[role]),
                                       abort_on_5xx=False)
        except AbortRun as exc:
            self._record(skipped_case(case_id, str(exc)))
            raise
        self._register_body_tokens(raw)
        result = self._record(evaluator(status, raw, ctx))
        if isinstance(status, int) and status >= 500:
            raise AbortRun(f"5xx in {case_id}")
        return {"status": status, "raw": raw, "result": result}

    def run_cases(self) -> None:
        p = self.prefix
        ctx = CaseContext(prefix=p, route_id=self.created.route, now=self.now,
                          entry_workload_id=self.created.workloads.get("entry"))
        r1 = self._run_case("H1-P1", "entry", {"grant_type": "client_credentials", "scope": SCOPE},
                            evaluate_p1, ctx)
        if r1["result"]["result"] != "pass":
            for cid in CASE_IDS[1:]:
                self._record(skipped_case(cid, "H1-P1 failed"))
            return
        doc = parse_json(r1["raw"])
        subject = SensitiveValue(doc["access_token"])
        _h, claims = decode_jwt(subject.reveal())
        ctx.p1_exp = _int(claims.get("exp"))

        def xform(audience: str, scope: str) -> dict:
            return {"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": subject.reveal(),
                    "subject_token_type": ACCESS_TOKEN_TYPE, "requested_token_type": ACCESS_TOKEN_TYPE,
                    "audience": audience, "scope": scope}

        gw = self.names["gateway_audience"]
        plan = [
            ("H1-P2", "entry", xform(gw, SCOPE), evaluate_p2),
            ("H1-N1", "entry", xform(self.names["sibling_audience"], SCOPE), evaluate_n1),
            ("H1-N2", "sibling", xform(gw, SCOPE), evaluate_n2),
            ("H1-N3", "entry", xform(gw, f"{SCOPE} {EXTRA_SCOPE}"), evaluate_n3),
        ]
        for case_id, role, form, evaluator in plan:
            self._run_case(case_id, role, form, evaluator, ctx)

    # -- cleanup (design §7) ------------------------------------------------------------------------------------------
    def cleanup(self) -> None:
        base = f"/admin/tenants/{TENANT}"
        steps: list[tuple[str, str, str]] = []
        if self.created.route is not None:
            steps.append(("revoke_route", "POST", f"{base}/agent-exchange/routes/{self.created.route}/revoke"))
        if self.created.broker is not None:
            steps.append(("revoke_broker", "POST", f"{base}/agent-exchange/brokers/{self.created.broker}/revoke"))
        for role in ("entry", "sibling"):
            if role in self.created.workloads:
                steps.append((f"revoke_workload:{role}", "POST",
                              f"{base}/ciam/agent-workloads/{self.created.workloads[role]}/revoke"))
        for role in ("entry", "gateway", "sibling"):
            if role in self.created.clients:
                app_id, cuuid = self.created.clients[role]
                steps.append((f"disable_client:{role}", "DELETE", f"{base}/applications/{app_id}/clients/{cuuid}"))
        for role in ("entry", "gateway", "sibling"):
            if role in self.created.apps:
                steps.append((f"disable_application:{role}", "DELETE",
                              f"{base}/applications/{self.created.apps[role]}"))
        if not steps:
            return
        if not self._pf_alive() and self.pf is not None:
            # The forward died mid-run; cleanup needs one replacement forward on a fresh local port.
            if not self._restart_port_forward_for_cleanup():
                for step, _m, _p in steps:
                    self.emit({"event": "cleanup", "step": step, "ok": False, "reason": "no port-forward"})
                self.cleanup_incomplete = True
                return
        relogged = False
        for step, method, path in steps:
            if self.admin_token is None:
                self.emit({"event": "cleanup", "step": step, "ok": False, "reason": "no admin token"})
                self.cleanup_incomplete = True
                continue
            if not all(SAFE_ID.match(seg) for seg in self._path_ids(path)):
                self.emit({"event": "cleanup", "step": step, "ok": False, "reason": "unsafe server id"})
                self.cleanup_incomplete = True
                continue
            try:
                status, raw = self.request(method, path, bearer=self.admin_token, abort_on_5xx=False)
                if status == 401 and not relogged:
                    # One re-login if the admin session lapsed; the step is then attempted once more.
                    relogged = True
                    if self._relogin():
                        status, raw = self.request(method, path, bearer=self.admin_token, abort_on_5xx=False)
                ok = isinstance(status, int) and 200 <= status < 300
                if not ok:
                    self.cleanup_incomplete = True
                self.emit({"event": "cleanup", "step": step, "ok": ok, "status": status,
                           **({} if ok else error_fields(raw))})
            except (AbortRun, HarnessError) as exc:
                self.cleanup_incomplete = True
                self.emit({"event": "cleanup", "step": step, "ok": False, "reason": str(exc)})
            except Exception as exc:  # noqa: BLE001 - never stop the remaining steps; type only (may carry data)
                self.cleanup_incomplete = True
                self.emit({"event": "cleanup", "step": step, "ok": False, "reason": f"unexpected {type(exc).__name__}"})

    @staticmethod
    def _path_ids(path: str) -> list[str]:
        """Server-issued identifiers in a cleanup path: every segment that follows a collection name."""
        parts = path.strip("/").split("/")
        collections = {"routes", "brokers", "agent-workloads", "clients", "applications"}
        return [parts[i + 1] for i, seg in enumerate(parts[:-1]) if seg in collections]

    def _restart_port_forward_for_cleanup(self) -> bool:
        old = self.pf
        self.stop_port_forward()
        port = self.port_chooser()
        if port is None:
            self.emit({"event": "port_forward_restart", "ok": False, "reason": "no free port"})
            return False
        self.port = port
        self.pf = None
        self._pf_lines = queue.Queue()
        try:
            self.start_port_forward()
        except (AbortRun, HarnessError, OSError):
            self.emit({"event": "port_forward_restart", "ok": False})
            return False
        self.emit({"event": "port_forward_restart", "ok": True, "port": port, "replaced": old is not None})
        return True

    def _relogin(self) -> bool:
        if self.admin_password is None:
            return False
        try:
            status, raw = self.request("POST", "/auth/login",
                                       json_body={"username": ADMIN_USERNAME, "password": self.admin_password.reveal()})
        except Exception:  # noqa: BLE001
            self.emit({"event": "cleanup_relogin", "ok": False})
            return False
        doc = parse_json(raw)
        token = doc.get("accessToken") if isinstance(doc, dict) else None
        ok = status == 200 and isinstance(token, str) and bool(token)
        if ok:
            self.redactor.register(token)
            self.admin_token = self._sensitive(token)
        self.emit({"event": "cleanup_relogin", "ok": ok, "status": status})
        return ok

    # -- orchestration ------------------------------------------------------------------------------------------------
    def _abort(self, reason: str) -> None:
        self.aborted = True
        self.abort_reason = reason
        self.emit({"event": "abort", "reason": reason})

    def run(self) -> int:
        self.emit({"event": "run_start", "prefix": self.prefix, "context": CONTEXT, "namespace": NAMESPACE})
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
        for cid in CASE_IDS:
            if cid not in self.results:
                self._record(skipped_case(cid, "aborted" if self.aborted else "not run"))
        counts = {k: sum(1 for r in self.results.values() if r["result"] == k) for k in ("pass", "fail", "skipped")}
        summary = {"event": "summary", "prefix": self.prefix, "passed": counts["pass"], "failed": counts["fail"],
                   "skipped": counts["skipped"], "aborted": self.aborted, "abort_reason": self.abort_reason,
                   "redaction_violation": False}
        summary["redaction_violation"] = self.redactor.violation
        summary["cleanup_complete"] = not self.cleanup_incomplete
        summary["port_forward_leaked"] = self.pf_leaked
        self.emit(summary)
        # Case results are unchanged by cleanup; the exit code still demands operator attention.
        if self.aborted or self.redactor.violation or self.cleanup_incomplete or self.pf_leaked:
            return 2
        if counts["pass"] == len(CASE_IDS):
            return 0
        return 1


# ---------------------------------------------------------------------------------------------------------------------
# Plan mode and CLI
# ---------------------------------------------------------------------------------------------------------------------

def plan_events() -> list[dict]:
    names = identity_names("<p>")
    events: list[dict] = [{"event": "plan", "mode": "dry", "note": "no subprocess or network calls; pass --execute to run",
                           "context": CONTEXT, "namespace": NAMESPACE, "release": RELEASE, "chart": CHART,
                           "expected_digest": EXPECTED_DIGEST, "expected_issuer": EXPECTED_ISSUER,
                           "prefix_template": "p0h + secrets.token_hex(5)"}]
    steps = [
        ("V-1", build_context_check_command()),
        ("V-2", build_command("kubectl", "get", "ns", NAMESPACE, "-o", "json")),
        ("V-3", build_command("helm", "list", "-o", "json")),
        ("V-4", build_command("kubectl", "get", "pods", "-l", SERVER_LABEL_SELECTOR, "-o", "json")),
        ("V-5", build_command("kubectl", "get", "secret", SECRET_NAME, "-o", "go-template=<namespace,"
                                                                            "creationTimestamp,key names>")),
        ("V-5-value", f"separate read of key {SECRET_KEY} only (argv/output never logged)"),
        ("V-6", f"random port in {PORT_BASE}-{PORT_BASE + PORT_SPAN - 1}, bind-check 127.0.0.1, "
                f"then kubectl port-forward svc/axiom <port>:{SERVICE_PORT} --address 127.0.0.1"),
        ("V-7", "GET /.well-known/openid-configuration (issuer) + /.well-known/oauth-authorization-server (issuer, token-exchange grant)"),
        ("V-8", "GET /actuator/health/readiness"),
        ("V-9", "POST /auth/login as admin"),
        ("V-10", f"GET /admin/tenants/{TENANT}/applications: no applicationKey starts with prefix"),
    ]
    for step, what in steps:
        events.append({"event": "plan_verify", "step": step, "action": what})
    events.append({"event": "plan_identities", **names})
    for cid in CASE_IDS:
        cls, expected = CASE_META[cid]
        events.append({"event": "plan_case", "case_id": cid, "class": cls, "expected": expected})
    events.append({"event": "plan_cleanup", "order": ["revoke route", "revoke broker", "revoke workloads",
                                                      "disable clients", "disable applications",
                                                      "stop port-forward"]})
    return events


def main(argv: list[str] | None = None, *, out: Any = None, runner_factory: Callable[..., Runner] = Runner) -> int:
    out = out if out is not None else sys.stdout
    if sys.version_info < (3, 13):
        sys.stderr.write("phase0_harness requires Python 3.13+\n")
        return 2
    parser = argparse.ArgumentParser(description="Phase 0.2 H-1 isolated harness")
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
