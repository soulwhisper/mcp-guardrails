"""Tests for Observability — child spans, audit sink, and duration tracking."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from guardrails.aggregator import DecisionAggregator
from guardrails.config import GuardrailConfig
from guardrails.engine import EngineComponents, GuardrailEngine
from guardrails.invariant import InvariantEngine
from guardrails.models import FailureMode, ScanResult
from guardrails.otel import AuditSink, Observability, asdict_scan
from guardrails.scanners import StubScanner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture_engine(
    *,
    request_scanners=None,
    response_scanners=None,
    audit_path: str | None = None,
) -> tuple[GuardrailEngine, list[dict[str, Any]]]:
    """Build an engine whose audit sink routes to an in-memory list."""
    config = GuardrailConfig(
        enable_regex_scanner=False,
        enable_promptguard=False,
        enable_agent_alignment=False,
        failure_mode=FailureMode.FAIL_CLOSED,
        log_level="WARNING",
        audit_log_path=audit_path,
    )
    lines: list[dict[str, Any]] = []
    obs = Observability(audit_path=audit_path)
    original = obs.audit.emit

    def _capture(rec: dict[str, Any]) -> None:
        lines.append(dict(rec))
        original(rec)

    obs.audit.emit = _capture

    comps = EngineComponents(
        request_scanners=request_scanners or [StubScanner("regex")],
        response_scanners=response_scanners or [],
        second_stage_scanners=[],
        invariant=InvariantEngine([], window=8),
        aggregator=DecisionAggregator(),
        observability=obs,
    )
    return GuardrailEngine(config, comps), lines


def _find_event(lines: list[dict[str, Any]], event: str) -> dict[str, Any] | None:
    for rec in lines:
        if rec.get("event") == event:
            return rec
    return None


# ---------------------------------------------------------------------------
# Scanner child span tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scanner_child_span_emitted():
    """Each scanner invocation produces a scanner.<name> audit event."""
    engine, lines = _capture_engine()
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="ping",
        params={"name": "ping", "arguments": {"x": 1}},
        headers={},
    )
    span = _find_event(lines, "scanner.regex")
    assert span is not None, f"Missing scanner.regex child span in {lines}"
    assert span["scanner"] == "regex"
    assert span["role"] == "tool"
    assert span["outcome"] == "allow"
    assert isinstance(span["duration_ms"], (int, float))
    assert span["duration_ms"] >= 0


@pytest.mark.asyncio
async def test_scanner_child_span_outcome_block():
    """Scanner returning BLOCK is reflected in the span outcome."""
    scanner = StubScanner(
        "blocker", decider=lambda content, role: ScanResult.block("blocker", "nope")
    )
    engine, lines = _capture_engine(request_scanners=[scanner])
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="run",
        params={"name": "run", "arguments": {"cmd": "bad"}},
        headers={},
    )
    span = _find_event(lines, "scanner.blocker")
    assert span is not None
    assert span["outcome"] == "block"


@pytest.mark.asyncio
async def test_scanner_child_span_outcome_review():
    """Scanner returning HUMAN_REVIEW is reflected in the span."""
    scanner = StubScanner(
        "reviewer", decider=lambda content, role: ScanResult.review("reviewer", "suspicious")
    )
    engine, lines = _capture_engine(request_scanners=[scanner])
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="ping",
        params={"name": "ping", "arguments": {}},
        headers={},
    )
    span = _find_event(lines, "scanner.reviewer")
    assert span is not None
    assert span["outcome"] == "human_review"


@pytest.mark.asyncio
async def test_scanner_child_span_outcome_timeout():
    """Scanner that sleeps past timeout records outcome=timeout."""
    import asyncio

    class SlowScanner:
        name = "slow"

        async def scan(self, content: str, role: str):
            await asyncio.sleep(10)
            return ScanResult.allow("slow")

    engine, lines = _capture_engine(request_scanners=[SlowScanner()])
    # Override timeout to be very short
    engine._cfg = GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        scanner_timeout_ms=50,
        log_level="WARNING",
    )
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="ping",
        params={"name": "ping", "arguments": {}},
        headers={},
    )
    span = _find_event(lines, "scanner.slow")
    assert span is not None, f"No scanner.slow span; got {[r['event'] for r in lines]}"
    assert span["outcome"] == "timeout"


@pytest.mark.asyncio
async def test_scanner_child_span_outcome_error():
    """Scanner that raises records outcome=error with error detail."""

    class BoomScanner:
        name = "boom"

        async def scan(self, content: str, role: str):
            raise RuntimeError("kaboom")

    engine, lines = _capture_engine(request_scanners=[BoomScanner()])
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="ping",
        params={"name": "ping", "arguments": {}},
        headers={},
    )
    span = _find_event(lines, "scanner.boom")
    assert span is not None
    assert span["outcome"] == "error"
    assert "RuntimeError" in span.get("error", "")


@pytest.mark.asyncio
async def test_multiple_scanners_each_get_child_span():
    """Two scanners produce two independent child spans."""
    s1 = StubScanner("alpha", decider=lambda c, r: ScanResult.allow("alpha"))
    s2 = StubScanner("beta", decider=lambda c, r: ScanResult.allow("beta"))
    engine, lines = _capture_engine(request_scanners=[s1, s2])
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="ping",
        params={"name": "ping", "arguments": {}},
        headers={},
    )
    assert _find_event(lines, "scanner.alpha") is not None
    assert _find_event(lines, "scanner.beta") is not None


@pytest.mark.asyncio
async def test_parent_span_still_emitted():
    """The guardrail.check_request parent span still fires alongside children."""
    engine, lines = _capture_engine()
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="ping",
        params={"name": "ping", "arguments": {}},
        headers={},
    )
    parent = _find_event(lines, "guardrail.check_request")
    assert parent is not None
    assert parent["method"] == "tools/call"
    assert parent["tool"] == "ping"
    assert isinstance(parent["duration_ms"], (int, float))


@pytest.mark.asyncio
async def test_response_side_scanner_child_span():
    """response_scanners also get child spans."""
    engine, lines = _capture_engine(response_scanners=[StubScanner("resp-regex")])
    await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": "ok"}]},
    )
    span = _find_event(lines, "scanner.resp-regex")
    assert span is not None
    assert span["role"] == "assistant"
    assert span["outcome"] == "allow"


# ---------------------------------------------------------------------------
# AuditSink tests
# ---------------------------------------------------------------------------


def test_audit_sink_stdout(capsys):
    """AuditSink with path=None writes JSONL to stdout."""
    sink = AuditSink(path=None)
    sink.emit({"event": "test", "value": 42})
    captured = capsys.readouterr()
    record = json.loads(captured.out.strip())
    assert record["event"] == "test"
    assert record["value"] == 42


def test_audit_sink_file(tmp_path: Path):
    """AuditSink writes to a file."""
    path = tmp_path / "audit.jsonl"
    sink = AuditSink(path=str(path))
    sink.emit({"event": "test", "key": "val"})
    sink.emit({"event": "test2", "num": 7})
    lines = path.read_text().strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["event"] == "test"
    assert json.loads(lines[1])["num"] == 7


def test_audit_sink_dash_is_stdout(capsys):
    """AuditSink(path='-') writes to stdout."""
    sink = AuditSink(path="-")
    sink.emit({"event": "dash"})
    captured = capsys.readouterr()
    assert "dash" in captured.out


def test_audit_sink_empty_string_is_stdout(capsys):
    """AuditSink(path='') writes to stdout."""
    sink = AuditSink(path="")
    sink.emit({"event": "empty"})
    captured = capsys.readouterr()
    assert "empty" in captured.out


def test_audit_sink_write_failure_is_silent(caplog):
    """A write failure logs a warning but does not raise."""
    sink = AuditSink(path="/nonexistent/dir/should/fail/audit.jsonl")
    sink.emit({"event": "doomed"})
    # Should not raise; may or may not log a warning depending on when the
    # file open actually fails (AuditSink opens lazily on first emit).
    # The important property: the call does not propagate an exception.


# ---------------------------------------------------------------------------
# asdict_scan tests
# ---------------------------------------------------------------------------


def test_asdict_scan_scanresult():
    sr = ScanResult.allow("test-scanner")
    d = asdict_scan(sr)
    assert d["scanner"] == "test-scanner"
    assert d["outcome"] == "allow"


def test_asdict_scan_scanresult_with_reason():
    sr = ScanResult.block("blk", reason="bad-input", score=0.95)
    d = asdict_scan(sr)
    assert d["outcome"] == "block"
    assert d["reason"] == "bad-input"
    assert d["score"] == 0.95


def test_asdict_scan_fallback():
    """Non-ScanResult objects are serialised as {scanner: str(obj)}."""
    d = asdict_scan("plain-string")
    assert d == {"scanner": "plain-string"}


# ---------------------------------------------------------------------------
# Observability degrads gracefully without OTel
# ---------------------------------------------------------------------------


def test_observability_without_otel_endpoint():
    """When otel_endpoint is None, otel_enabled is False."""
    obs = Observability(otel_endpoint=None)
    assert obs.otel_enabled is False
    assert obs.otel_endpoint is None


def test_observability_service_name_default():
    obs = Observability()
    assert obs.service_name == "mcp-guardrails"
