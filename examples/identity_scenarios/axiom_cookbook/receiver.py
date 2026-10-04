"""A generic receiver fixture: what any API, tool server, gateway or broker in front of a protected action must
do with an Axiom token. It is a *simulation of a consumer*, not part of Axiom, and its "protected actions" are
entries in a list — nothing real happens.

Two validation modes, so the residual window is visible rather than hidden:

* ``offline`` — signature (JWKS), ``iss``, ``aud``, ``exp``, ``typ`` and scope only. Fast; cannot see revocation.
* ``online`` — the offline checks plus RFC 7662 introspection by the receiver's own confidential client. Sees
  logout, revocation, withdrawal, suspension and disabled clients immediately.

A denied request never appends to ``performed``; that statement is about this fixture only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import oauth
from .http import AxiomHttp
from .oauth import Client
from .redaction import Secret
from .tokens import InvalidToken, Validator


@dataclass
class Decision:
    allowed: bool
    reason: str
    claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class Receiver:
    name: str
    audience: str
    validator: Validator
    http: AxiomHttp
    introspector: Client | None = None
    online: bool = False
    performed: list[dict[str, Any]] = field(default_factory=list)

    def handle(self, token: Secret, action: str, required_scope: str, request_text: str = "") -> Decision:
        """Authorizes ``action`` if the token is valid for this audience and carries ``required_scope``.
        ``request_text`` stands for caller-authored content (a prompt, a note); it is deliberately never consulted."""
        try:
            claims = self.validator.access_token(token, self.audience)
        except InvalidToken as invalid:
            return Decision(False, f"offline validation failed: {invalid}")
        scopes = claims.get("scope", "")
        scopes = set(scopes.split() if isinstance(scopes, str) else scopes)
        if required_scope not in scopes:
            return Decision(False, f"scope {required_scope} not granted", claims)
        if self.online:
            if self.introspector is None:
                raise ValueError("an online receiver needs an introspecting client")
            if not oauth.introspect(self.http, self.introspector, token).get("active"):
                return Decision(False, "issuer reports the token inactive", claims)
        self.performed.append({"action": action, "sub": claims.get("sub"),
                               "act": (claims.get("act") or {}).get("client_id"), "jti": claims.get("jti")})
        return Decision(True, "ok", claims)
