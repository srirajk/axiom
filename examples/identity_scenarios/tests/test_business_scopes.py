"""B12: tenant-scoped custom business-scope catalog through the real Axiom HTTP API."""
from __future__ import annotations

from basics import b12_custom_business_scopes
from tests.conftest import record


def test_custom_business_scopes(ctx):
    outcome = b12_custom_business_scopes.run(ctx)
    record(outcome)
    assert outcome.allowed and outcome.denied
