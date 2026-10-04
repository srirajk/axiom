"""Validating Axiom tokens the way a receiver must: signature against the published JWKS, issuer, audience, time
claims and token type. Decoding a JWT without these checks is *not* validation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient

from .http import AxiomHttp
from .redaction import Secret

ACCEPTED_ALGORITHMS = ["RS256"]


class InvalidToken(AssertionError):
    pass


@dataclass
class Validator:
    issuer: str
    jwks_uri: str
    _client: PyJWKClient | None = None

    @classmethod
    def discover(cls, http: AxiomHttp) -> "Validator":
        meta = http.get("/.well-known/openid-configuration").expect(200).json()
        # Trust anchors come only from the verified origin: the issuer must be the target and keys must live there.
        if meta.get("issuer") != http.base_url:
            raise InvalidToken("discovered issuer is not the verified target")
        http.resolve(meta["jwks_uri"])  # raises ForeignOrigin for keys published anywhere else
        return cls(meta["issuer"], meta["jwks_uri"])

    def _keys(self) -> PyJWKClient:
        if self._client is None:
            self._client = PyJWKClient(self.jwks_uri, cache_keys=False)
        return self._client

    def access_token(self, token: Secret, audience: str, leeway: int = 5) -> dict[str, Any]:
        """Validates an RFC 9068 access token for one intended audience; returns its claims."""
        return self._validate(token, audience, expected_typ="at+jwt", leeway=leeway)

    def id_token(self, token: Secret, client_id: str, nonce: str | None = None) -> dict[str, Any]:
        claims = self._validate(token, client_id, expected_typ=None, leeway=5)
        if nonce is not None and claims.get("nonce") != nonce:
            raise InvalidToken("nonce mismatch")
        return claims

    def _validate(self, token: Secret, audience: str, expected_typ: str | None, leeway: int) -> dict[str, Any]:
        value = token.reveal()
        try:
            header = jwt.get_unverified_header(value)
        except jwt.PyJWTError as e:
            raise InvalidToken(f"malformed token: {type(e).__name__}") from None
        if header.get("alg") not in ACCEPTED_ALGORITHMS:
            raise InvalidToken(f"algorithm {header.get('alg')!r} not accepted")
        if not header.get("kid"):
            raise InvalidToken("token has no key id")
        if expected_typ is not None and header.get("typ") != expected_typ:
            raise InvalidToken(f"token type {header.get('typ')!r} is not {expected_typ!r}")
        try:
            key = self._keys().get_signing_key(header["kid"]).key
            return jwt.decode(value, key, algorithms=ACCEPTED_ALGORITHMS, audience=audience, issuer=self.issuer,
                              leeway=leeway, options={"require": ["exp", "iat", "iss", "sub", "aud"]})
        except jwt.PyJWTError as e:
            raise InvalidToken(f"{type(e).__name__}") from None


def unverified_claims(token: Secret) -> dict[str, Any]:
    """For *displaying* what a token says after it has been validated (or to show why it fails). Never trust it."""
    return jwt.decode(token.reveal(), options={"verify_signature": False})
