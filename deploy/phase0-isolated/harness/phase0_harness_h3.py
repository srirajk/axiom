#!/opt/homebrew/bin/python3.13
"""Phase 0.2 H-3 isolated introspection and signature-tamper harness.

Implements package H-3 of docs/operations/phase-0.2-test-harness-design.md §8 (introspection of active tokens,
unauthenticated introspection caller, and the corrected tamper method) on top of the reviewed and executed H-2
module ``phase0_harness_h2.py``, which is imported unchanged and itself pins H-1 (``phase0_harness.py``).

Reused from H-2 (and through it H-1): preflight V-1..V-10, port-forward lifecycle, setup of the per-run identities
(with an H-3 prefix), PKCE login, the BFF -> Gateway -> Agent -> resource exchange chain and its evaluators,
request/URL/Location guards, redaction, cleanup and the exit-code semantics.

Usage:
    /opt/homebrew/bin/python3.13 -I -B phase0_harness_h3.py --package h3            # plan only (no subprocess/network)
    /opt/homebrew/bin/python3.13 -I -B phase0_harness_h3.py --package h3 --execute  # actually run

Output is JSON Lines on stdout only; every event name carries the ``h3_`` prefix and ``"package": "H-3"``.
Exit code: 0 all cases passed and nothing needs attention; 1 any case failed; 2 abort, redaction violation,
incomplete cleanup or a leaked port-forward.

All expected values live in ``H3_EXPECTATIONS`` (one data-driven table); evaluators are generic. The tamper cases
are NOT revocation evidence (that is H-4). H3-T2 and H3-T3 each have an untampered positive control and are
expected to exercise an RS256 decoder; H3-T1 only shows that a tampered token is not reported active (its cause is
not distinguishable).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import importlib.util
import json
import os
import re
import secrets
import signal
import sys
from typing import Any, Callable

# ---------------------------------------------------------------------------------------------------------------------
# H-2 import. Under ``-I`` the script directory is not on sys.path, so the sibling file is loaded by its fixed path
# after its SHA-256 has been checked. H-2 in turn pins H-1; H-3 also checks the H-1 file digest itself, because H-2
# accepts an already-imported H-1 module without re-hashing it. A module from any other location is refused.
# ---------------------------------------------------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
_H1_PATH = os.path.join(_HERE, "phase0_harness.py")
_H2_PATH = os.path.join(_HERE, "phase0_harness_h2.py")
# SHA-256 of the reviewed and executed H-1 and H-2 harnesses. H-3 refuses to load any other version.
H1_SHA256 = "10ffb18b65e09ffc66439583ae299ee0ac10a7aa724d398e4aedee342aa3eebc"
H2_SHA256 = "30b949d2aad7ad6400d905666c8fbd68faae67ff824afbbc359936bc3c855f7d"


def _file_digest(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _load_h2() -> Any:
    # Digests are checked BEFORE anything is executed, also when a module is already imported.
    if _file_digest(_H1_PATH) != H1_SHA256:
        raise ImportError("phase0_harness.py does not match the reviewed H-1 digest")
    if _file_digest(_H2_PATH) != H2_SHA256:
        raise ImportError("phase0_harness_h2.py does not match the reviewed H-2 digest")
    existing = sys.modules.get("phase0_harness_h2")
    if existing is not None:
        if os.path.realpath(getattr(existing, "__file__", "") or "") != os.path.realpath(_H2_PATH):
            raise ImportError("phase0_harness_h2 already imported from an unexpected location")
        module = existing
    else:
        spec = importlib.util.spec_from_file_location("phase0_harness_h2", _H2_PATH)
        if spec is None or spec.loader is None:
            raise ImportError("cannot load phase0_harness_h2.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["phase0_harness_h2"] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop("phase0_harness_h2", None)
            raise
    if getattr(module, "H1_SHA256", None) != H1_SHA256:
        raise ImportError("phase0_harness_h2 pins an unexpected H-1 digest")
    h1_mod = getattr(module, "h1", None)
    if os.path.realpath(getattr(h1_mod, "__file__", "") or "") != os.path.realpath(_H1_PATH):
        raise ImportError("phase0_harness_h2 uses an H-1 module from an unexpected location")
    return module


h2 = _load_h2()
h1 = h2.h1

AbortRun = h1.AbortRun
HarnessError = h1.HarnessError
SensitiveValue = h1.SensitiveValue
CONTEXT = h1.CONTEXT
NAMESPACE = h1.NAMESPACE
SCOPE = h1.SCOPE
EXPECTED_ISSUER = h1.EXPECTED_ISSUER
TOKEN_EXCHANGE_GRANT = h1.TOKEN_EXCHANGE_GRANT
ACCESS_TOKEN_TYPE = h1.ACCESS_TOKEN_TYPE
parse_json = h1.parse_json

# ---------------------------------------------------------------------------------------------------------------------
# H-3 constants
# ---------------------------------------------------------------------------------------------------------------------

PACKAGE = "H-3"
EVENT_PREFIX = "h3_"
PREFIX_HEAD = "p3h"
TAMPER_CLAIM = "tampered-signature rejection with an untampered positive control; not revocation evidence"
TAMPER_CLAIM_T1 = ("tampered token not reported active; cause not distinguishable (store miss, signature or "
                   "session); not signature-specific evidence; not revocation evidence")
# Field names that may ever be printed from an introspection response (values only via this allow-list).
INTROSPECTION_FIELD_NAMES = (
    "active", "token_type", "iss", "sub", "aud", "scope", "exp", "iat", "client_id", "azp", "tenant_id",
    "identity_kind", "token_use", "authority_profile", "authority_id", "subject_sid", "sid",
    "act.sub", "act.client_id", "act.workload_id",
)
# Printed only as sha256[:12].
HASHED_FIELDS = ("sid", "subject_sid")
FIELD_MODES = ("eq", "eq_if_present", "absent_ok")
# A third entry form ("<path>", "lit", <value>) requires the response field to equal a literal value.
LITERAL_MODE = "lit"


class TamperError(ValueError):
    """The tamper helper refused (input is not a canonical JWS, or tampering would not change the bytes)."""


def new_prefix_h3(token_hex: Callable[[int], str] = secrets.token_hex) -> str:
    return PREFIX_HEAD + token_hex(5)


# ---------------------------------------------------------------------------------------------------------------------
# Expectation table (single source of truth; placeholders ``{name}`` resolve from the run's variables)
# ---------------------------------------------------------------------------------------------------------------------
# Prerequisite chain: H3-C1..H3-C6 are H-2's positive cases P1..P6, re-labelled; their checks come from
# H2_EXPECTATIONS with every H-2 case id rewritten to its H-3 label. No H-2 denial case is re-run.
#
# Introspection field comparison modes (issued token claim vs. introspection response member):
#   "eq"             both carry the field and the (normalised) values are equal
#   "eq_if_present"  the response may omit the field; if it carries it, it must equal the issued token's claim
#   "absent_ok"      presence must agree (both absent passes); when both carry it, the values must be equal
# Normalisation: aud -> list (a string becomes [string]); scope -> set of space-separated values;
# exp/iat -> integer seconds; act.* and everything else -> string. sid/subject_sid are compared on their values but
# printed only as sha256[:12].

H3_CHAIN = {"H3-C1": "H2-P1", "H3-C2": "H2-P2", "H3-C3": "H2-P3", "H3-C4": "H2-P4", "H3-C5": "H2-P5",
            "H3-C6": "H2-P6"}

INTROSPECTOR_ROLE = "sibling"     # client role (H-2 identity) that authenticates to /oauth/introspect

INTROSPECTION_COMMON = [
    ("sub", "eq"), ("aud", "eq"), ("client_id", "eq"), ("scope", "eq"), ("exp", "eq"), ("iat", "eq"),
    ("iss", "eq"), ("tenant_id", "eq"), ("identity_kind", "eq"),
]
INTROSPECTION_EXCHANGED = [
    ("act.sub", "eq"), ("act.client_id", "eq"), ("act.workload_id", "eq"), ("azp", "eq"), ("token_use", "eq"),
    ("authority_profile", "eq"), ("authority_id", "eq"), ("subject_sid", "eq"), ("sid", "eq"),
    # Local-decode path adds token_type=Bearer for act tokens (SessionAwareIntrospectionAuthenticationProvider).
    ("token_type", LITERAL_MODE, "Bearer"),
]
# The human (authorization-code) token carries none of the exchange claims but does carry sid.
INTROSPECTION_HUMAN = [
    ("act.sub", "absent_ok"), ("act.client_id", "absent_ok"), ("token_use", "absent_ok"),
    ("authority_profile", "absent_ok"), ("authority_id", "absent_ok"), ("subject_sid", "absent_ok"),
    ("sid", "absent_ok"),
]


def _introspect_case(n: int, what: str, fields: list) -> dict:
    return {
        "class": "introspection_active", "kind": "introspect", "token_case": f"H3-C{n}", "depends": [f"H3-C{n}"],
        "description": f"introspect the H3-C{n} {what} token as the introspection client: 200; active == true; "
                       "echoed fields equal the issued token's claims",
        "status": 200, "active": True, "fields": fields,
    }


H3_EXPECTATIONS: dict = {
    "introspector_role": INTROSPECTOR_ROLE,
    "side_effects": ["introspecting H3-C2..H3-C6 updates last_seen of their sessions and of the root H3-C1 "
                     "session; H3-I1 reads the H3-C1 session state (no audit rows)",
                     "the admin /auth/login token is never introspected (inactive by design)"],
    "introspection": {"path": "/oauth/introspect", "token_type_hint": "access_token", "accept": "application/json"},
    "p1_case": "H3-C1",
    "chain": H3_CHAIN,
    "order": ["H3-C1", "H3-C2", "H3-C3", "H3-C4", "H3-C5", "H3-C6",
              "H3-I1", "H3-I2", "H3-I3", "H3-I4", "H3-I5", "H3-I6",
              "H3-T1", "H3-T2", "H3-T3", "H3-N1"],
    "cases": {
        # H3-C1..H3-C6 are filled from H2_EXPECTATIONS below.
        "H3-I1": _introspect_case(1, "human PKCE (authorization-code)", INTROSPECTION_COMMON + INTROSPECTION_HUMAN),
        "H3-I2": _introspect_case(2, "workforce->BFF (exchange_subject)",
                                  INTROSPECTION_COMMON + INTROSPECTION_EXCHANGED),
        "H3-I3": _introspect_case(3, "BFF->gateway (gateway_authorization)",
                                  INTROSPECTION_COMMON + INTROSPECTION_EXCHANGED),
        "H3-I4": _introspect_case(4, "broker->Agent (exchange_subject)",
                                  INTROSPECTION_COMMON + INTROSPECTION_EXCHANGED),
        "H3-I5": _introspect_case(5, "Agent->gateway (gateway_authorization)",
                                  INTROSPECTION_COMMON + INTROSPECTION_EXCHANGED),
        "H3-I6": _introspect_case(6, "broker->resource (delegated_access)",
                                  INTROSPECTION_COMMON + INTROSPECTION_EXCHANGED),
        "H3-T1": {
            "class": "tamper_signature_introspection", "kind": "tamper_introspect", "token_case": "H3-C6",
            "depends": ["H3-C6", "H3-I6"], "control_case": "H3-I6",
            "description": "H3-C6 token with signature byte len//2 XOR 0x01, introspected as the introspection "
                           "client: 200 with exactly {active:false}",
            "status": 200, "active": False, "only_fields": ["active"],
            "claim": TAMPER_CLAIM_T1,
            "note": "rejection shown; cause not distinguishable (authorization-store miss vs signature vs session); "
                    "not revocation evidence",
        },
        "H3-T2": {
            "class": "tamper_signature_exchange_subject", "kind": "tamper_exchange", "token_case": "H3-C5",
            "requester": "broker", "audience": "{tool_aud}", "scope": SCOPE, "depends": ["H3-C5", "H3-C6"],
            "control_case": "H3-C6",
            "description": "broker exchanges the signature-tampered H3-C5 token to the tool audience (the exact "
                           "H3-C6 request; H3-C6 is the untampered positive control): 400 invalid_grant; "
                           "no access_token",
            "denial": {"status": 400, "error": "invalid_grant"},
            "claim": TAMPER_CLAIM,
            "note": "expected to exercise the subject-token RS256 decoder (H3-C6 is the untampered control); "
                    "invalid_grant by itself does not distinguish the cause",
        },
        "H3-T3": {
            "class": "tamper_signature_primary_decoder", "kind": "tamper_admin", "depends": [],
            "method": "GET", "path": "/api/me/sessions",
            "description": "untampered admin /auth/login token on GET /api/me/sessions: 200 (control); then the "
                           "signature-tampered admin token: 401 with WWW-Authenticate containing invalid_token",
            # Positive control with the genuine admin token first; a failed control means no signature result.
            "control_status": 200,
            "status": 401, "www_authenticate_contains": "invalid_token",
            "claim": TAMPER_CLAIM,
            "note": "exercises the primary resource-server decoder; the tampered token is used for this request only",
        },
        "H3-N1": {
            "class": "introspection_unauthenticated", "kind": "introspect_noauth", "token_case": "H3-C1",
            "depends": ["H3-C1"],
            "description": "introspect the genuine H3-C1 token with no client authentication: 401 "
                           "(challenge scheme and body are not part of this security assertion); never active:true",
            "status": 401,
        },
    },
}

H3_KINDS = ("chain", "introspect", "tamper_introspect", "tamper_exchange", "tamper_admin", "introspect_noauth")


def _rewrite_ids(value: Any, mapping: dict) -> Any:
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, tuple):
        return tuple(_rewrite_ids(v, mapping) for v in value)
    if isinstance(value, list):
        return [_rewrite_ids(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _rewrite_ids(v, mapping) for k, v in value.items()}
    return value


def _mentions_h2_id(value: Any) -> bool:
    if isinstance(value, str):
        return bool(re.fullmatch(r"H2-[A-Z][0-9]+", value))
    if isinstance(value, (list, tuple)):
        return any(_mentions_h2_id(v) for v in value)
    if isinstance(value, dict):
        return any(_mentions_h2_id(v) for k, v in value.items() if k not in ("description", "source_case"))
    return False


def derive_chain_specs(chain: dict, h2_table: dict) -> dict:
    """H-2 positive specs re-labelled as H-3 prerequisites (every H-2 case reference rewritten)."""
    mapping = {src: cid for cid, src in chain.items()}
    out = {}
    for cid, src in chain.items():
        base = h2_table["cases"].get(src)
        if base is None or "checks" not in base:
            raise HarnessError(f"{cid}: {src} is not a positive H-2 case")
        spec = _rewrite_ids(copy.deepcopy(base), mapping)
        spec["h2_kind"] = spec["kind"]
        spec["kind"] = "chain"
        spec["class"] = "prerequisite"
        spec["source_case"] = src
        spec["description"] = f"= {src}: {base['description']}"
        if _mentions_h2_id(spec):
            raise HarnessError(f"{cid}: references an H-2 case outside the chain")
        out[cid] = spec
    return out


H3_EXPECTATIONS["cases"].update(derive_chain_specs(H3_CHAIN, h2.H2_EXPECTATIONS))


def validate_h3_expectations(table: dict) -> None:
    order, cases = table.get("order"), table.get("cases")
    if not isinstance(order, list) or not isinstance(cases, dict) or sorted(order) != sorted(cases) \
            or len(set(order)) != len(order):
        raise HarnessError("expectation table order/cases mismatch")
    if not isinstance(table.get("introspector_role"), str) or not table["introspector_role"]:
        raise HarnessError("introspector_role missing")
    intro = table.get("introspection")
    if not isinstance(intro, dict) or not all(isinstance(intro.get(k), str) and intro.get(k)
                                              for k in ("path", "token_type_hint", "accept")):
        raise HarnessError("introspection request settings missing")
    if table.get("p1_case") not in cases or cases[table["p1_case"]].get("kind") != "chain":
        raise HarnessError("p1_case must be a chain case")
    for cid in order:
        spec = cases[cid]
        kind = spec.get("kind")
        if kind not in H3_KINDS:
            raise HarnessError(f"{cid}: unknown kind {kind!r}")
        for key in ("class", "description"):
            if not isinstance(spec.get(key), str):
                raise HarnessError(f"{cid}: {key} missing")
        for dep in spec.get("depends", []):
            if dep not in cases or order.index(dep) >= order.index(cid):
                raise HarnessError(f"{cid}: dependency {dep} must run earlier")
        if kind == "chain":
            if cid not in table.get("chain", {}) or ("checks" in spec) == ("denial" in spec):
                raise HarnessError(f"{cid}: malformed chain case")
            if _mentions_h2_id(spec):
                raise HarnessError(f"{cid}: references an H-2 case id")
            continue
        if kind in ("introspect", "tamper_introspect", "tamper_exchange", "introspect_noauth"):
            tc = spec.get("token_case")
            if tc not in cases or cases[tc].get("kind") != "chain" or tc not in spec.get("depends", []):
                raise HarnessError(f"{cid}: token_case must be an earlier chain case listed in depends")
        if kind in ("introspect", "tamper_introspect", "tamper_admin", "introspect_noauth") \
                and not isinstance(spec.get("status"), int):
            raise HarnessError(f"{cid}: status missing")
        if kind == "introspect":
            if spec.get("active") is not True or not isinstance(spec.get("fields"), list):
                raise HarnessError(f"{cid}: active/fields missing")
            for item in spec["fields"]:
                ok = isinstance(item, (list, tuple)) and len(item) >= 2 and item[0] in INTROSPECTION_FIELD_NAMES \
                    and ((len(item) == 2 and item[1] in FIELD_MODES)
                         or (len(item) == 3 and item[1] == LITERAL_MODE and isinstance(item[2], str)))
                if not ok:
                    raise HarnessError(f"{cid}: bad field entry {item!r}")
        if kind == "tamper_introspect":
            if spec.get("active") is not False or not isinstance(spec.get("only_fields"), list):
                raise HarnessError(f"{cid}: active/only_fields missing")
        if kind == "tamper_exchange":
            if not isinstance(spec.get("denial"), dict) or spec.get("requester") is None:
                raise HarnessError(f"{cid}: denial/requester missing")
        if kind == "tamper_admin":
            if not isinstance(spec.get("path"), str) or spec.get("method") not in ("GET", "POST"):
                raise HarnessError(f"{cid}: method/path missing")
            if spec.get("control_status") is not None and not isinstance(spec.get("control_status"), int):
                raise HarnessError(f"{cid}: control_status must be int or None")
        expected_claim = TAMPER_CLAIM_T1 if kind == "tamper_introspect" else TAMPER_CLAIM
        if kind.startswith("tamper_") and spec.get("claim") != expected_claim:
            raise HarnessError(f"{cid}: tamper case carries the wrong evidence claim")
        if kind.startswith("tamper_") and "not revocation evidence" not in str(spec.get("claim")):
            raise HarnessError(f"{cid}: tamper claims must state they are not revocation evidence")
        if "control_case" in spec and spec["control_case"] not in spec.get("depends", []):
            raise HarnessError(f"{cid}: control_case must be listed in depends")
        if spec.get("www_authenticate_contains") is not None \
                and not isinstance(spec.get("www_authenticate_contains"), str):
            raise HarnessError(f"{cid}: www_authenticate_contains must be a string")
    if not isinstance(table.get("side_effects"), list):
        raise HarnessError("side_effects list missing")


def chain_table(table: dict) -> dict:
    """The H-2-compatible sub-table of the prerequisite chain (validated by H-2's own validator)."""
    order = [cid for cid in table["order"] if table["cases"][cid]["kind"] == "chain"]
    return {"order": order, "cases": {cid: table["cases"][cid] for cid in order}}


validate_h3_expectations(H3_EXPECTATIONS)
h2.validate_expectations(chain_table(H3_EXPECTATIONS))
CASE_IDS = tuple(H3_EXPECTATIONS["order"])


# ---------------------------------------------------------------------------------------------------------------------
# Tamper helper (design §8, corrected method)
# ---------------------------------------------------------------------------------------------------------------------

_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode_strict(segment: str) -> bytes:
    if not isinstance(segment, str) or not _B64URL.match(segment) or len(segment) % 4 == 1:
        raise TamperError("signature segment is not unpadded base64url")
    try:
        return base64.urlsafe_b64decode((segment + "=" * (-len(segment) % 4)).encode("ascii"))
    except (binascii.Error, ValueError):
        raise TamperError("signature segment does not decode") from None


def tamper_jwt_signature(token: str) -> str:
    """Return ``token`` with signature byte ``len(sig)//2`` XOR 0x01, re-encoded without padding.

    1. split the JWS; 2. base64url-decode the signature; 3. flip the low bit of the middle byte; 4. re-encode
    without padding; 5. assert the new segment differs as a string AND decodes to different bytes (raises
    TamperError otherwise). Header and payload are untouched.
    """
    if not isinstance(token, str):
        raise TamperError("token is not a string")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise TamperError("token is not a three-part JWS")
    sig = _b64url_decode_strict(parts[2])
    if not sig:
        raise TamperError("empty signature")
    if _b64url_encode(sig) != parts[2]:
        raise TamperError("signature segment is not canonical base64url")
    flipped = bytearray(sig)
    flipped[len(sig) // 2] ^= 0x01
    new_segment = _b64url_encode(bytes(flipped))
    if new_segment == parts[2]:
        raise TamperError("tampered signature segment is identical")
    decoded = _b64url_decode_strict(new_segment)
    if decoded == sig or decoded != bytes(flipped):
        raise TamperError("tampered signature does not decode to different bytes")
    return ".".join((parts[0], parts[1], new_segment))


def tamper_info(original: str, tampered: str) -> dict:
    sig = _b64url_decode_strict(original.split(".")[2])
    return {"original_token_sha256_12": h1.token_hash(original), "tampered_token_sha256_12": h1.token_hash(tampered),
            "signature_bytes": len(sig), "flipped_byte_index": len(sig) // 2, "xor": "0x01"}


# ---------------------------------------------------------------------------------------------------------------------
# Introspection evaluators (pure)
# ---------------------------------------------------------------------------------------------------------------------

_SESSION_STEP = re.compile(r"^(revoke_sessions:[A-Za-z0-9_-]+):(?!session$)(.+)$")


def sha12(value: Any) -> str | None:
    if value is None:
        return None
    return "sha256_12:" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


def _lookup(doc: Any, path: str) -> tuple[bool, Any]:
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur or cur[part] is None:
            return False, None
        cur = cur[part]
    return True, cur


_INVALID = object()


def _normalise(path: str, value: Any) -> Any:
    if path == "aud":
        aud = h1.normalize_aud(value)
        return _INVALID if aud is None else sorted(aud)
    if path == "scope":
        scope = h1.normalize_scope(value)
        return _INVALID if scope is None else sorted(scope)
    if path in ("exp", "iat"):
        if isinstance(value, bool):
            return _INVALID
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return _INVALID
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return _INVALID
    return str(value)


def _display(path: str, value: Any) -> Any:
    if path.split(".")[-1] in HASHED_FIELDS:
        return sha12(value)
    norm = _normalise(path, value)
    return None if norm is _INVALID else norm


def compare_field(path: str, mode: str, token_claims: dict, response: dict) -> str | None:
    """Mismatch reason, or None when the field satisfies its mode."""
    t_present, t_val = _lookup(token_claims, path)
    r_present, r_val = _lookup(response, path)
    if mode == "eq":
        if not t_present:
            return "issued token lacks the claim"
        if not r_present:
            return "missing from the introspection response"
    elif mode == "eq_if_present":
        if not r_present:
            return None
        if not t_present:
            return "present in the response but not in the issued token"
    elif mode == "absent_ok":
        if not t_present and not r_present:
            return None
        if t_present != r_present:
            return "present in only one of issued token / response"
    else:
        raise HarnessError(f"unknown comparison mode {mode!r}")
    t_norm, r_norm = _normalise(path, t_val), _normalise(path, r_val)
    if r_norm is _INVALID:
        return "response value has an unexpected type"
    if t_norm is _INVALID or t_norm != r_norm:
        return "differs from the issued token"
    return None


def h3_case_result(case_id: str, spec: dict, observed: dict, mismatches: list[str]) -> dict:
    return {"event": "case", "package": PACKAGE, "case_id": case_id, "class": spec["class"],
            "expected": spec["description"], "observed": observed, "mismatches": mismatches,
            "result": "pass" if not mismatches else "fail"}


def _error_code(parsed: Any) -> Any:
    """Only the RFC 6749 ``error`` code is printed from an error body (never its description)."""
    err = parsed.get("error") if isinstance(parsed, dict) else None
    return err if isinstance(err, str) else None


def evaluate_introspection(case_id: str, spec: dict, status: Any, body: Any, token_claims: dict,
                           now: float | None = None) -> dict:
    parsed = parse_json(body)
    observed: dict = {"status": status}
    m: list[str] = []
    if status != spec["status"]:
        m.append(f"status {status} != {spec['status']}")
    if not isinstance(parsed, dict):
        m.append("body is not a JSON object")
        return h3_case_result(case_id, spec, observed, m)
    if status != 200:
        observed["error"] = _error_code(parsed)
    active = parsed.get("active")
    observed["active"] = active if isinstance(active, bool) else None
    iat = h2._int(token_claims.get("iat"))
    if now is not None and iat is not None:
        observed["token_age_s"] = int(now) - iat
    if active is not spec["active"]:
        m.append(f"active is not {str(spec['active']).lower()}")
        return h3_case_result(case_id, spec, observed, m)
    fields: dict = {}
    for item in spec["fields"]:
        path, mode = item[0], item[1]
        present, value = _lookup(parsed, path)
        if mode == LITERAL_MODE:
            reason = None if present and value == item[2] else f"expected literal {item[2]!r}"
        else:
            reason = compare_field(path, mode, token_claims, parsed)
        fields[path] = {"mode": mode, "match": reason is None, "value": _display(path, value) if present else None}
        if reason:
            m.append(f"{path}: {reason}")
    observed["fields"] = fields
    return h3_case_result(case_id, spec, observed, m)


def evaluate_tampered_introspection(case_id: str, spec: dict, status: Any, body: Any) -> dict:
    parsed = parse_json(body)
    observed: dict = {"status": status}
    m: list[str] = []
    if status != spec["status"]:
        m.append(f"status {status} != {spec['status']}")
    if not isinstance(parsed, dict):
        m.append("body is not a JSON object")
        return h3_case_result(case_id, spec, observed, m)
    if status != 200:
        observed["error"] = _error_code(parsed)
    active = parsed.get("active")
    observed["active"] = active if isinstance(active, bool) else None
    if active is not spec["active"]:
        m.append(f"active is not {str(spec['active']).lower()}")
    extra = [k for k in parsed if k not in spec["only_fields"]]
    observed["extra_member_count"] = len(extra)
    if extra:
        observed["extra_members"] = sorted(k for k in extra if k in INTROSPECTION_FIELD_NAMES)
        m.append("response carries members other than " + ", ".join(spec["only_fields"]))
    return h3_case_result(case_id, spec, observed, m)


def _check_challenge(spec: dict, headers: Any, observed: dict, m: list[str]) -> None:
    """WWW-Authenticate must contain the table's token (case-insensitive). Only presence is printed."""
    want = spec.get("www_authenticate_contains")
    if want is None:
        return
    values = h2.header_values(h2.normalize_headers(headers), "WWW-Authenticate")
    observed["www_authenticate_present"] = bool(values)
    ok = any(want.lower() in v.lower() for v in values)
    observed["www_authenticate_contains_" + re.sub(r"[^a-z0-9_]", "_", want.lower())] = ok
    if not ok:
        m.append(f"WWW-Authenticate does not contain {want}")


def evaluate_noauth_introspection(case_id: str, spec: dict, status: Any, body: Any, headers: Any = None) -> dict:
    """The body may be empty or non-JSON; it is never printed (only an RFC 6749 error code, if any)."""
    parsed = parse_json(body)
    observed: dict = {"status": status, "error": _error_code(parsed)}
    m: list[str] = []
    if status != spec["status"]:
        m.append(f"status {status} != {spec['status']}")
    _check_challenge(spec, headers, observed, m)
    active = parsed.get("active") if isinstance(parsed, dict) else None
    observed["active_true"] = active is True
    if active is True:
        m.append("active:true returned without client authentication")
    return h3_case_result(case_id, spec, observed, m)


def evaluate_status(case_id: str, spec: dict, status: Any, body: Any, headers: Any = None) -> dict:
    observed: dict = {"status": status, "error": _error_code(parse_json(body))}
    m = [] if status == spec["status"] else [f"status {status} != {spec['status']}"]
    _check_challenge(spec, headers, observed, m)
    return h3_case_result(case_id, spec, observed, m)


def _scrub_sids(value: Any) -> Any:
    """Replace sid/subject_sid values (at any depth) by their sha256[:12]."""
    if isinstance(value, dict):
        return {k: (sha12(v) if k in HASHED_FIELDS and isinstance(v, (str, int)) else _scrub_sids(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_sids(v) for v in value]
    return value


# ---------------------------------------------------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------------------------------------------------

class H3Runner(h2.H2Runner):
    def __init__(self, *, expectations: dict | None = None, prefix: str | None = None,
                 token_hex: Callable[[int], str] = secrets.token_hex, **kw: Any):
        table = expectations or H3_EXPECTATIONS
        validate_h3_expectations(table)
        # H-2's runner validates and runs only the prerequisite chain (its own evaluators and handlers).
        super().__init__(expectations=chain_table(table), prefix=prefix or new_prefix_h3(token_hex), **kw)
        # From here on, H-2's generic run() iterates over the full H-3 table (summary, skips, exit code).
        self.expectations = table
        self.case_ids = tuple(table["order"])
        self.h3_table = table

    # -- output -------------------------------------------------------------------------------------------------------
    def emit(self, event: dict) -> None:
        ev = dict(event)
        step = ev.get("step")
        if isinstance(step, str):
            # H-2's session-revoke cleanup step names carry the IAM session id, which equals the JWT sid.
            m = _SESSION_STEP.match(step)
            if m:
                ev["step"] = f"{m.group(1)}:{sha12(m.group(2))}"
        name = str(ev.get("event", ""))
        if name.startswith(h2.EVENT_PREFIX):
            name = name[len(h2.EVENT_PREFIX):]
        ev["event"] = name if name.startswith(EVENT_PREFIX) else EVENT_PREFIX + name
        ev["package"] = PACKAGE
        h1.Runner.emit(self, ev)

    def _record(self, result: dict) -> dict:
        res = dict(result)
        res["package"] = PACKAGE
        res["observed"] = _scrub_sids(res.get("observed", {}))
        spec = self.h3_table["cases"].get(res.get("case_id"), {})
        for key in ("claim", "note"):
            if key in spec:
                res[key] = spec[key]
        return super()._record(res)

    # -- chain --------------------------------------------------------------------------------------------------------
    def _store_token(self, case_id: str, raw: Any) -> None:
        super()._store_token(case_id, raw)
        if case_id == self.h3_table["p1_case"]:
            self.env.variables["p1_sid"] = self.env.sids.get(case_id)

    def case_chain(self, cid: str, spec: dict) -> None:
        if spec["h2_kind"] == "pkce_login":
            self.case_pkce_login(cid, spec)
        elif spec["h2_kind"] == "exchange":
            self.case_exchange(cid, spec)
        else:
            raise HarnessError(f"{cid}: unsupported chain kind")

    # -- introspection ------------------------------------------------------------------------------------------------
    def _introspector(self) -> tuple[str, SensitiveValue] | None:
        role = self.h3_table["introspector_role"]
        client = self.names["clients"].get(role)
        secret = self.client_secrets.get(role)
        if client is None or secret is None:
            return None
        return client["clientId"], secret

    def _introspect(self, token: SensitiveValue,
                    basic: tuple[str, SensitiveValue] | None) -> tuple[int, list[tuple[str, str]], Any]:
        intro = self.h3_table["introspection"]
        form = {"token": token.reveal(), "token_type_hint": intro["token_type_hint"]}
        status, headers, raw = self.request_full("POST", intro["path"], form=form, basic=basic,
                                                 accept=intro["accept"], abort_on_5xx=False)
        self._register_body_tokens(raw)
        return status, headers, raw

    def _token_for(self, cid: str, spec: dict) -> SensitiveValue | None:
        token = self.tokens.get(spec["token_case"])
        if token is None:
            self._record(h2.skipped_case(cid, spec, f"no {spec['token_case']} token"))
        return token

    def case_introspect(self, cid: str, spec: dict) -> None:
        token = self._token_for(cid, spec)
        if token is None:
            return
        who = self._introspector()
        if who is None:
            self._record(h3_case_result(cid, spec, {}, ["introspection client unavailable"]))
            return
        _h, claims = h1.decode_jwt(token.reveal())
        status, _hdrs, raw = self._introspect(token, who)
        result = evaluate_introspection(cid, spec, status, raw, claims, self.now())
        result["observed"]["introspector"] = who[0]
        result["observed"]["token_sha256_12"] = h1.token_hash(token.reveal())
        self._record(result)
        self._check_5xx(cid, status)

    def _tampered(self, cid: str, spec: dict, original: SensitiveValue) -> tuple[SensitiveValue, dict] | None:
        try:
            tampered = tamper_jwt_signature(original.reveal())
        except TamperError as exc:
            self._record(h3_case_result(cid, spec, {}, [f"tamper helper refused: {exc}"]))
            return None
        return self._sensitive(tampered), tamper_info(original.reveal(), tampered)

    def case_tamper_introspect(self, cid: str, spec: dict) -> None:
        token = self._token_for(cid, spec)
        if token is None:
            return
        who = self._introspector()
        if who is None:
            self._record(h3_case_result(cid, spec, {}, ["introspection client unavailable"]))
            return
        got = self._tampered(cid, spec, token)
        if got is None:
            return
        tampered, info = got
        status, _hdrs, raw = self._introspect(tampered, who)
        result = evaluate_tampered_introspection(cid, spec, status, raw)
        result["observed"].update(info, introspector=who[0], source_case=spec["token_case"],
                                  control_case=spec.get("control_case"))
        self._record(result)
        self._check_5xx(cid, status)

    def case_tamper_exchange(self, cid: str, spec: dict) -> None:
        token = self._token_for(cid, spec)
        if token is None:
            return
        role = spec["requester"]
        client_id = self.names["clients"][role]["clientId"]
        secret = self.client_secrets.get(role)
        if secret is None:
            self._record(h3_case_result(cid, spec, {}, [f"no secret for requester {role}"]))
            return
        try:
            audience = h2.resolve(spec["audience"], self.env.variables)
        except h2.UnknownValue as u:
            self._record(h3_case_result(cid, spec, {}, [f"audience unknown ({u})"]))
            return
        got = self._tampered(cid, spec, token)
        if got is None:
            return
        tampered, info = got
        form = {"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": tampered.reveal(),
                "subject_token_type": ACCESS_TOKEN_TYPE, "requested_token_type": ACCESS_TOKEN_TYPE,
                "audience": audience, "scope": spec["scope"]}
        status, raw = self.request("POST", "/oauth/token", form=form, basic=(client_id, secret), abort_on_5xx=False)
        self._register_body_tokens(raw)
        result = h2.evaluate_denial(cid, spec, status, raw)
        result["observed"].pop("error_description", None)
        result["observed"].update(info, requester=client_id, audience=audience, source_case=spec["token_case"],
                                  control_case=spec.get("control_case"))
        self._record(result)
        self._check_5xx(cid, status)

    def case_tamper_admin(self, cid: str, spec: dict) -> None:
        if self.admin_token is None:
            self._record(h3_case_result(cid, spec, {}, ["no admin token"]))
            return
        observed: dict = {"path": spec["path"]}
        if spec.get("control_status") is not None:
            # Untampered control first. If it fails, the tampered request is not sent: no signature result.
            c_status, _c_raw = self.request(spec["method"], spec["path"], bearer=self.admin_token, abort_on_5xx=False)
            observed["control_status"] = c_status
            if c_status != spec["control_status"]:
                observed["signature_result"] = False
                self._record(h3_case_result(cid, spec, observed, [
                    f"control failed (status {c_status} != {spec['control_status']}); no signature result"]))
                self._check_5xx(cid, c_status)
                return
        got = self._tampered(cid, spec, self.admin_token)
        if got is None:
            return
        tampered, info = got
        # The tampered admin token is used for this single request and then dropped.
        status, headers, raw = self.request_full(spec["method"], spec["path"], bearer=tampered, abort_on_5xx=False)
        del tampered
        result = evaluate_status(cid, spec, status, raw, headers)
        result["observed"].update(observed, **info, signature_result=True)
        self._record(result)
        self._check_5xx(cid, status)

    def case_introspect_noauth(self, cid: str, spec: dict) -> None:
        token = self._token_for(cid, spec)
        if token is None:
            return
        status, headers, raw = self._introspect(token, None)
        result = evaluate_noauth_introspection(cid, spec, status, raw, headers)
        result["observed"]["token_sha256_12"] = h1.token_hash(token.reveal())
        self._record(result)
        self._check_5xx(cid, status)

    # -- orchestration ------------------------------------------------------------------------------------------------
    def run_cases(self) -> None:
        handlers = {"chain": self.case_chain, "introspect": self.case_introspect,
                    "tamper_introspect": self.case_tamper_introspect, "tamper_exchange": self.case_tamper_exchange,
                    "tamper_admin": self.case_tamper_admin, "introspect_noauth": self.case_introspect_noauth}
        cases = self.h3_table["cases"]
        for cid in self.case_ids:
            spec = cases[cid]
            blocked = [d for d in spec.get("depends", []) if self.results.get(d, {}).get("result") != "pass"]
            if blocked:
                self._record(h2.skipped_case(cid, spec, f"prerequisite {', '.join(blocked)} did not pass"))
                continue
            try:
                handlers[spec["kind"]](cid, spec)
            except AbortRun as exc:
                if cid not in self.results:
                    self._record(h2.skipped_case(cid, spec, str(exc)))
                raise


# ---------------------------------------------------------------------------------------------------------------------
# Plan mode and CLI
# ---------------------------------------------------------------------------------------------------------------------

def plan_events(expectations: dict | None = None) -> list[dict]:
    table = expectations or H3_EXPECTATIONS
    names = h2.identity_names_h2("<p>")
    variables = h2.base_vars("<p>", names)
    role = table["introspector_role"]
    events: list[dict] = [{"event": "h3_plan", "package": PACKAGE, "mode": "dry",
                           "note": "no subprocess or network calls; pass --execute to run",
                           "context": CONTEXT, "namespace": NAMESPACE, "expected_issuer": EXPECTED_ISSUER,
                           "prefix_template": f"{PREFIX_HEAD} + secrets.token_hex(5)",
                           "introspection": table["introspection"], "introspector_role": role,
                           "introspector": names["clients"].get(role, {}).get("clientId"),
                           "side_effects": list(table["side_effects"]),
                           "h1_sha256": H1_SHA256, "h2_sha256": H2_SHA256}]
    for ev in h1.plan_events():
        if ev.get("event") == "plan_verify":
            events.append({**ev, "event": "h3_plan_verify", "package": PACKAGE})
    events.append({"event": "h3_plan_identities", "package": PACKAGE, **names})
    for cid in table["order"]:
        spec = table["cases"][cid]
        ev = {"event": "h3_plan_case", "package": PACKAGE, "case_id": cid, "class": spec["class"],
              "kind": spec["kind"], "depends": list(spec.get("depends", [])), "expected": spec["description"]}
        if spec["kind"] == "chain":
            ev["source_case"] = spec["source_case"]
            if spec["h2_kind"] == "exchange":
                ev["requester"] = names["clients"][spec["requester"]]["clientId"]
                ev["subject"] = spec["subject"]
                ev["audience"] = h2.resolve_for_display(spec["audience"], variables)
                ev["scope"] = spec["scope"]
            ev["checks"] = [[c[0], *[h2.resolve_for_display(x, variables) for x in c[1:]]] for c in spec["checks"]]
        else:
            for key in ("token_case", "control_case", "status", "active", "only_fields", "method", "path",
                        "control_status", "www_authenticate_contains", "denial", "scope", "claim", "note"):
                if key in spec:
                    ev[key] = spec[key]
            if "fields" in spec:
                ev["fields"] = [list(f) for f in spec["fields"]]
            if "requester" in spec:
                ev["requester"] = names["clients"][spec["requester"]]["clientId"]
                ev["audience"] = h2.resolve_for_display(spec["audience"], variables)
        events.append(ev)
    events.append({"event": "h3_plan_cleanup", "package": PACKAGE, "order": list(h2.CLEANUP_ORDER),
                   "persists": "application role and audit rows have no delete API"})
    return events


def main(argv: list[str] | None = None, *, out: Any = None, runner_factory: Callable[..., H3Runner] = H3Runner) -> int:
    out = out if out is not None else sys.stdout
    if sys.version_info < (3, 13):
        sys.stderr.write("phase0_harness_h3 requires Python 3.13+\n")
        return 2
    parser = argparse.ArgumentParser(description="Phase 0.2 isolated harness, package H-3 "
                                                 "(H-1 and H-2 stay in their own files)")
    parser.add_argument("--package", required=True, choices=("h3",), help="test package to run (h3 only)")
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
