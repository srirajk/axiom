"""Shared shape of every example: a ``run(ctx)`` function that performs the flow, records allowed and denied
outcomes, and returns plain observations; plus a ``main()`` for running one example by itself."""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Outcome:
    """What an example observed. ``allowed`` and ``denied`` are the positive and negative assertions it made."""
    example: str
    allowed: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    consumer_must: list[str] = field(default_factory=list)

    def ok(self, condition: bool, statement: str) -> None:
        if not condition:
            raise AssertionError(f"[{self.example}] expected: {statement}")
        self.allowed.append(statement)

    def refused(self, condition: bool, statement: str) -> None:
        if not condition:
            raise AssertionError(f"[{self.example}] expected refusal: {statement}")
        self.denied.append(statement)

    def summary(self) -> str:
        lines = [f"== {self.example}"]
        lines += [f"  ALLOWED  {s}" for s in self.allowed]
        lines += [f"  DENIED   {s}" for s in self.denied]
        if self.facts:
            lines.append("  FACTS    " + json.dumps(self.facts, sort_keys=True, default=str))
        lines += [f"  CONSUMER {s}" for s in self.consumer_must]
        return "\n".join(lines)


def standalone(run: Callable[[Any], Outcome]) -> None:
    """Runs one example against the estate named by AXIOM_COOKBOOK_STATE and cleans up its records."""
    from .context import Context
    ctx = Context.from_environment()
    try:
        print(run(ctx).summary())
    finally:
        report = ctx.registry.cleanup()
        print("cleanup:", json.dumps(report, indent=2))
    sys.exit(0)
