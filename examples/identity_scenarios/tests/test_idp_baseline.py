"""IDP-01..12 baseline contracts and the IDP-13..15 conditional-profile report, against a real isolated Axiom
(PostgreSQL + Redis). Each test runs the example of the same name; nothing here imitates an example."""
from __future__ import annotations

import importlib

import pytest

from tests.conftest import record

EXAMPLES = [
    "idp.idp01_metadata",
    "idp.idp02_browser_signin",
    "idp.idp03_client_credentials",
    "idp.idp04_token_contract",
    "idp.idp05_token_exchange",
    "idp.idp06_refresh",
    "idp.idp07_introspection",
    "idp.idp08_revocation_logout",
    "idp.idp09_key_client_lifecycle",
    "idp.idp10_isolation",
    "idp.idp11_directory_admin",
    "idp.idp12_client_admin",
    "idp.idp13_15_conditional_profiles",
]


@pytest.mark.parametrize("module", EXAMPLES)
def test_idp(module, ctx):
    outcome = importlib.import_module(module).run(ctx)
    record(outcome)
    assert outcome.allowed and outcome.denied
