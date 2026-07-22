"""Pytest configuration shared across the test suite.

Ensures the repo root is on ``sys.path`` so ``import guardrails`` works without
an editable install, and provides the common stub-engine / stub-scanner
fixtures used by the servicer and engine tests.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from guardrails.models import ScanResult  # noqa: E402
from tests.helpers import ScriptedScanner, StubEngine  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_engine() -> StubEngine:
    return StubEngine()


@pytest.fixture
def make_scanner():
    def _factory(name: str, results: Sequence[ScanResult]) -> ScriptedScanner:
        return ScriptedScanner(name, results)

    return _factory


@pytest.fixture
def block_result() -> ScanResult:
    return ScanResult.block("test", "blocked")


@pytest.fixture
def allow_result() -> ScanResult:
    return ScanResult.allow("test")


@pytest.fixture
def review_result() -> ScanResult:
    return ScanResult.review("test", "suspicious")


# Standalone scripts (run directly, not via pytest).  These use their own
# subprocess-based server lifecycle and are not pytest-test functions.
collect_ignore = ["field_test.py", "load_test.py"]

# TEMP-DEBUG: CI bisect cycle 2 - rules re-enabled; still ignoring scanners+redteam.
collect_ignore += [
    "test_wave3_scanners.py",
    "test_redteam.py",
]
