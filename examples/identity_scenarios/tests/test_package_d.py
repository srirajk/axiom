"""Package D: consumer contracts — generic receiver/broker fixtures exercising generic Axiom handshakes (receiver, isolation, chains, untrusted issuers, assurance)."""
from __future__ import annotations

import importlib

import pytest

from tests.conftest import record

EXAMPLES = [
    "consumer_contracts.c01_receiver_enforcement",
    "consumer_contracts.c02_one_workload_many_subjects",
    "consumer_contracts.c03_workload_chains",
    "consumer_contracts.c04_untrusted_issuers",
    "consumer_contracts.c05_authentication_assurance",
]


@pytest.mark.parametrize("module", EXAMPLES)
def test_example(module, ctx):
    outcome = importlib.import_module(module).run(ctx)
    record(outcome)
    assert outcome.allowed and outcome.denied
