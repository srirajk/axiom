"""Package A: foundation examples B01-B05 and OAuth O01, O02, O04 against a real Axiom (PostgreSQL + Redis)."""
from __future__ import annotations

import importlib

import pytest

from tests.conftest import record

EXAMPLES = [
    "basics.b01_connect",
    "basics.b02_workforce_user",
    "basics.b03_apps_and_clients",
    "basics.b04_roles_and_entitlements",
    "basics.b05_groups",
    "oauth.o01_discovery_and_validation",
    "oauth.o02_workforce_authorization_code",
    "oauth.o04_client_credentials",
]


@pytest.mark.parametrize("module", EXAMPLES)
def test_example(module, ctx):
    outcome = importlib.import_module(module).run(ctx)
    record(outcome)
    assert outcome.allowed, "an example must make at least one positive assertion"
    assert outcome.denied, "an example must make at least one denial assertion"
