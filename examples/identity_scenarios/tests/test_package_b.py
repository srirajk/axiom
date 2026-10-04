"""Package B: issuer lifecycle, exchange, status, revocation, logout, discovery honesty and credential lifecycle."""
from __future__ import annotations

import importlib

import pytest

from tests.conftest import record

EXAMPLES = [
    "oauth.o05_token_exchange",
    "oauth.o06_introspection_revocation_logout",
    "oauth.o07_renewal",
    "oauth.o08_key_and_credential_lifecycle",
    "oauth.o09_capability_enumeration",
    "basics.b09_workloads_and_edges",
    "basics.b10_sessions_and_lifecycle",
    "basics.b11_rerun_and_cleanup",
]


@pytest.mark.parametrize("module", EXAMPLES)
def test_example(module, ctx):
    outcome = importlib.import_module(module).run(ctx)
    record(outcome)
    assert outcome.allowed and outcome.denied
