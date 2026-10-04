"""Package C: CIAM customer identities, customer application access, consent grants and the customer sign-in contract."""
from __future__ import annotations

import importlib

import pytest

from tests.conftest import record

EXAMPLES = [
    "ciam.b06_customer_identity",
    "ciam.b07_customer_application_access",
    "ciam.b08_consent_grants",
    "ciam.o03_customer_login",
]


@pytest.mark.parametrize("module", EXAMPLES)
def test_example(module, ctx):
    outcome = importlib.import_module(module).run(ctx)
    record(outcome)
    assert outcome.allowed and outcome.denied
