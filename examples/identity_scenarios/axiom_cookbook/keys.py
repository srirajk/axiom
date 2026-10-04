"""Client key material for ``private_key_jwt``. The private key stays in this process (in memory); only the public JWK
is registered with Axiom. Nothing here is written to disk or printed."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm


@dataclass
class ClientKey:
    kid: str
    algorithm: str
    private_key: object = field(repr=False)

    def public_jwk(self) -> dict:
        algo = RSAAlgorithm if self.algorithm == "RS256" else ECAlgorithm
        jwk = json.loads(algo.to_jwk(self.private_key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": self.algorithm})
        return jwk

    def __repr__(self) -> str:
        return f"ClientKey(kid={self.kid!r}, algorithm={self.algorithm!r}, private_key=[in memory])"


def generate(algorithm: str = "RS256") -> ClientKey:
    kid = "k-" + secrets.token_hex(4)
    if algorithm == "RS256":
        return ClientKey(kid, algorithm, rsa.generate_private_key(public_exponent=65537, key_size=2048))
    if algorithm == "ES256":
        return ClientKey(kid, algorithm, ec.generate_private_key(ec.SECP256R1()))
    raise ValueError("RS256 or ES256")


def jwks(*keys: ClientKey) -> dict:
    return {"keys": [k.public_jwk() for k in keys]}
