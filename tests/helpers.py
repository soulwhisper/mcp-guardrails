"""Shared test helpers used across the engine + servicer test suites.

Kept separate from ``conftest.py`` so the classes are importable as
``from tests.helpers import ...`` (conftest is special-cased by pytest and not
meant to be imported as a module).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from guardrails.models import Decision, McpCallContext, ScanResult


class StubEngine:
    """Async engine stand-in returning pre-programmed Decisions.

    Implements the same ``check_request`` / ``check_response`` surface as
    :class:`guardrails.engine.GuardrailEngine`.
    """

    def __init__(self) -> None:
        self.request_decision: Decision = Decision(deny=False)
        self.response_decision: Decision = Decision(deny=False)
        self.request_calls: list[dict[str, Any]] = []
        self.response_calls: list[dict[str, Any]] = []

    async def check_request(self, **kwargs: Any) -> Decision:
        self.request_calls.append(kwargs)
        return self.request_decision

    async def check_response(self, **kwargs: Any) -> Decision:
        self.response_calls.append(kwargs)
        return self.response_decision


class ScriptedScanner:
    """Scanner that returns a pre-seeded list of results, in order."""

    def __init__(self, name: str, results: Sequence[ScanResult]):
        self.name = name
        self._results = list(results)
        self.calls: list[tuple[str, str]] = []

    async def scan(
        self,
        content: str,
        role: str,
        *,
        context: McpCallContext | None = None,
    ) -> ScanResult:
        self.calls.append((content, role))
        if not self._results:
            return ScanResult.allow(self.name)
        return self._results.pop(0)
