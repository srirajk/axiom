"""Keeps credentials out of output. Every printable object in the cookbook goes through these helpers.

Secrets (passwords, client secrets, access/ID tokens, authorization codes, PKCE verifiers, renewal handles,
cookies) are held in :class:`Secret` wrappers whose ``repr``/``str`` never reveal the value, and HTTP bodies are
scrubbed before they appear in errors, logs or test failures.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SENSITIVE_KEYS = {
    "access_token", "id_token", "refresh_token", "accessToken", "token", "code", "code_verifier", "client_secret",
    "clientSecret", "serviceSecret", "oneTimeSecret", "password", "newPassword", "renewal_handle", "subject_token",
    "assertion", "client_assertion", "secret", "bearerCredential", "authorization", "cookie", "set-cookie",
}
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


class Secret:
    """A credential value that never prints. Use ``.reveal()`` only at the point of sending it."""

    __slots__ = ("_value", "label")

    def __init__(self, value: str, label: str = "secret") -> None:
        if value is None or value == "":
            raise ValueError(f"{label} is empty")
        self._value = value
        self.label = label

    def reveal(self) -> str:
        return self._value

    def fingerprint(self) -> str:
        """Short, non-reversible reference that lets two runs talk about the same credential."""
        return hashlib.sha256(self._value.encode()).hexdigest()[:10]

    def __repr__(self) -> str:
        return f"<{self.label} sha256:{self.fingerprint()}>"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)


def scrub(value: Any) -> Any:
    """Recursively replaces sensitive fields and anything that looks like a JWT."""
    if isinstance(value, dict):
        return {k: ("[redacted]" if k in SENSITIVE_KEYS or k.lower() in SENSITIVE_KEYS else scrub(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, Secret):
        return repr(value)
    if isinstance(value, str):
        return _JWT.sub("[jwt]", value)
    return value


def scrub_text(text: str) -> str:
    """Scrubs a raw HTTP body: JSON is scrubbed structurally, anything else by pattern."""
    try:
        return json.dumps(scrub(json.loads(text)))
    except (ValueError, TypeError):
        text = _JWT.sub("[jwt]", text)
        return re.sub(r"(?i)(code|access_token|state|code_verifier)=[^&\s]+", r"\1=[redacted]", text)[:2000]
