"""Where the cookbook is allowed to point, and with what permissions.

Defaults are deliberately inert: no target, no writes. A run must name its target, its fixture namespace and opt in to
writes. Only loopback targets are accepted unless ``AXIOM_COOKBOOK_ALLOW_REMOTE=1`` names an explicitly disposable
remote; known shared or production-looking hosts are always refused.
"""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlparse

# Hosts the cookbook must never write to, even with every opt-in set.
REFUSED_HOST_PATTERNS = (
    r"(^|\.)prod(uction)?([.-]|$)", r"(^|\.)prd([.-]|$)", r"(^|\.)openwolf\.(com|io|ai)$",
    r"(^|\.)axiom\.(com|io|ai)$", r"\.svc(\.cluster\.local)?$", r"(^|\.)argus[.-]",
)


class TargetRefused(RuntimeError):
    """The requested target or write mode is not allowed."""


@dataclass(frozen=True)
class Target:
    base_url: str
    tenant_id: str
    namespace: str
    allow_writes: bool

    def require_writes(self) -> None:
        if not self.allow_writes:
            raise TargetRefused("writes are disabled: set AXIOM_COOKBOOK_ALLOW_WRITES=1 for a disposable target")


def guard(base_url: str, tenant_id: str, namespace: str, allow_writes: bool,
          allow_remote: bool = False) -> Target:
    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or not host:
        raise TargetRefused(f"not an http(s) URL: {base_url!r}")
    for pattern in REFUSED_HOST_PATTERNS:
        if re.search(pattern, host):
            raise TargetRefused(f"refusing shared or production-looking host {host!r}")
    if not _loopback(host) and not allow_remote:
        raise TargetRefused(f"refusing non-loopback host {host!r} (set AXIOM_COOKBOOK_ALLOW_REMOTE=1 for a disposable one)")
    if not re.fullmatch(r"ckbk-[a-z0-9]{6,12}", namespace):
        raise TargetRefused("fixture namespace must look like ckbk-<6-12 lowercase alphanumerics>")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", tenant_id):
        raise TargetRefused("tenant id is malformed")
    return Target(base_url.rstrip("/"), tenant_id, namespace, allow_writes)


def from_environment() -> Target:
    """Target from AXIOM_COOKBOOK_* variables (see README); refuses when anything is missing."""
    base = os.environ.get("AXIOM_COOKBOOK_TARGET")
    tenant = os.environ.get("AXIOM_COOKBOOK_TENANT")
    if not base or not tenant:
        raise TargetRefused("set AXIOM_COOKBOOK_TARGET and AXIOM_COOKBOOK_TENANT (or use the disposable estate)")
    return guard(base, tenant, os.environ.get("AXIOM_COOKBOOK_NAMESPACE") or new_namespace(),
                 os.environ.get("AXIOM_COOKBOOK_ALLOW_WRITES") == "1",
                 os.environ.get("AXIOM_COOKBOOK_ALLOW_REMOTE") == "1")


def new_namespace() -> str:
    return "ckbk-" + secrets.token_hex(4)


def _loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
