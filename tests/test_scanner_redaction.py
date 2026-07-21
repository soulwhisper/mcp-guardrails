"""Regression tests for secret redaction in scanner reasons."""

from __future__ import annotations

import pytest

from guardrails.models import ScanOutcome
from guardrails.scanners import RegexScanner


@pytest.mark.asyncio
async def test_regex_reason_redacts_secret_match():
    """Scanner reasons must not copy secret material into audit logs."""
    scanner = RegexScanner()
    secret = "AKIA" + "B" * 16
    result = await scanner.scan(f"aws key {secret} here", "tool")
    assert result.outcome is ScanOutcome.BLOCK
    assert "aws_access_key" in result.scanner
    assert secret not in result.reason
    assert "match_len=20" in result.reason
    assert "match_sha256=" in result.reason
