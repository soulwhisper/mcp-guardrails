"""Wave-1 reviewer follow-up tests.

Covers:
* Deny correlation ref: the audit decision line and the generalised wire
  reason carry the SAME ref (engine mints it; servicer reuses it).
* PromptGuard adaptive window budget: a marker at token ~2000 of a long
  payload is scored (previously a blind spot with a fixed 4-window budget);
  the budget still respects the max_windows cap and PG_MAX_WINDOWS env wiring.
* Fingerprint tiering: key_value_credential and connection_string matches
  record match_len only (no digest — the match IS the low-entropy secret).
* awarm() regex-only fallback: a scanner whose warmup raises ImportError
  (dependency not installed) is dropped from the scan chain with a warning,
  instead of failing closed on every scan.
"""

from __future__ import annotations

import json
import logging

import pytest

from guardrails.aggregator import DecisionAggregator
from guardrails.config import GuardrailConfig
from guardrails.engine import EngineComponents, GuardrailEngine
from guardrails.models import (
    FailureMode,
    HumanReviewMode,
    ScanOutcome,
)
from guardrails.proto_bridge import pb
from guardrails.scanners import (
    OnnxPromptGuardScanner,
    RegexScanner,
)
from guardrails.servicer import ExtMcpServicer


def _engine(scanners, **cfg_kwargs) -> GuardrailEngine:
    cfg_kwargs.setdefault("failure_mode", FailureMode.FAIL_CLOSED)
    cfg_kwargs.setdefault("human_review_mode", HumanReviewMode.PASS)
    cfg_kwargs.setdefault("scanner_timeout_ms", 500)
    config = GuardrailConfig(**cfg_kwargs)
    return GuardrailEngine(
        config,
        EngineComponents(
            request_scanners=list(scanners),
            response_scanners=list(scanners),
            aggregator=DecisionAggregator(human_review_mode=config.human_review_mode),
        ),
    )


# ---------------------------------------------------------------------------
# Deny ref: audit record and wire reason share the same ref
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_ref_in_audit_matches_wire_reason(tmp_path):
    """The ref the tenant sees on the wire greps to the audit decision line."""
    from guardrails.otel import Observability

    audit_path = tmp_path / "audit.jsonl"
    obs = Observability(audit_path=str(audit_path))
    config = GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        scanner_timeout_ms=500,
    )
    engine = GuardrailEngine(
        config,
        EngineComponents(
            request_scanners=[RegexScanner()],
            aggregator=DecisionAggregator(),
            observability=obs,
        ),
    )
    servicer = ExtMcpServicer(engine)
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps(
            {"name": "t", "arguments": {"q": "AKIA" + "B" * 16}}
        ).encode(),
    )
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "error"
    reason = result.error.reason
    assert reason.startswith("denied by content policy (ref ")
    wire_ref = reason.removeprefix("denied by content policy (ref ").rstrip(")")
    assert len(wire_ref) == 8

    records = [json.loads(line) for line in audit_path.read_text().splitlines()]
    decision_records = [r for r in records if r.get("phase") == "request"]
    assert decision_records
    # The SAME ref must appear on the audit decision record carrying the full
    # internal reason — this is what makes the ref greppable.
    assert decision_records[0]["ref"] == wire_ref
    assert "aws_access_key" in decision_records[0]["reason"]


@pytest.mark.asyncio
async def test_response_deny_ref_matches_audit(tmp_path):
    from guardrails.otel import Observability

    audit_path = tmp_path / "audit.jsonl"
    obs = Observability(audit_path=str(audit_path))
    config = GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        scanner_timeout_ms=500,
    )
    engine = GuardrailEngine(
        config,
        EngineComponents(
            response_scanners=[RegexScanner()],
            aggregator=DecisionAggregator(),
            observability=obs,
        ),
    )
    servicer = ExtMcpServicer(engine)
    req = pb.McpResponse(
        method="tools/call",
        mcp_response=json.dumps(
            {"content": [{"type": "text", "text": "AKIA" + "B" * 16}]}
        ).encode(),
    )
    result = await servicer.CheckResponse(req, None)
    assert result.WhichOneof("result") == "error"
    wire_ref = result.error.reason.removeprefix("denied by response policy (ref ").rstrip(")")
    records = [json.loads(line) for line in audit_path.read_text().splitlines()]
    decision_records = [r for r in records if r.get("phase") == "response"]
    assert decision_records
    assert decision_records[0]["ref"] == wire_ref


# ---------------------------------------------------------------------------
# PromptGuard adaptive window budget
# ---------------------------------------------------------------------------


class _CharTokenizer:
    """One token per character — exact token offsets without a real model."""

    def __call__(self, text, **kwargs):
        return {"input_ids": [[ord(c) % 251 for c in text]]}


class _MarkerSession:
    """Malicious logits when the window contains marker token id 250."""

    def __init__(self):
        import numpy as np

        self._np = np
        self.calls = 0

    def get_inputs(self):
        class _I:
            def __init__(self, name):
                self.name = name

        return [_I("input_ids"), _I("attention_mask")]

    def run(self, _targets, feed):
        self.calls += 1
        np = self._np
        ids = feed["input_ids"]
        if (ids == 250).any():
            return [np.array([[0.0, 5.0]])]
        return [np.array([[5.0, 0.0]])]


def _pg_scanner(**kwargs) -> OnnxPromptGuardScanner:
    scanner = OnnxPromptGuardScanner(block_threshold=0.9, **kwargs)
    scanner._loaded = True
    scanner._tokenizer = _CharTokenizer()
    scanner._sess = _MarkerSession()
    return scanner


def test_pg_mid_payload_marker_scored_by_adaptive_windows():
    """Marker at token ~2000 of an ~8000-token payload.

    With the old fixed 4-window budget (3 strided + tail) the region between
    token ~1344 and the tail window was never scored; the adaptive budget
    (default cap 16) covers it.
    """
    pytest.importorskip("numpy")
    scanner = _pg_scanner()
    text = "a" * 2000 + chr(250) + "b" * 6000
    score = scanner._score(text)
    assert score > 0.9
    # Adaptive budget grew beyond the old fixed 4 windows...
    assert scanner._sess.calls > 4
    # ...but stayed within the cap.
    assert scanner._sess.calls <= scanner.max_windows


def test_pg_window_budget_respects_cap_on_huge_payload():
    pytest.importorskip("numpy")
    scanner = _pg_scanner()
    scanner._score("a" * 100000)
    assert scanner._sess.calls == scanner.max_windows


def test_pg_window_budget_small_for_short_payload():
    pytest.importorskip("numpy")
    scanner = _pg_scanner()
    # ~1000 tokens: adaptive budget = clamp(ceil(1000/448)+1, 4, 16) = 4.
    scanner._score("a" * 1000)
    assert scanner._sess.calls <= 4


def test_pg_max_windows_env_wiring(monkeypatch):
    monkeypatch.setenv("PG_MAX_WINDOWS", "8")
    cfg = GuardrailConfig.from_env()
    assert cfg.pg_max_windows == 8
    monkeypatch.delenv("PG_MAX_WINDOWS")
    assert GuardrailConfig.from_env().pg_max_windows == 16


# ---------------------------------------------------------------------------
# Fingerprint tiering: low-entropy credential patterns record length only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_key_value_credential_fingerprint_has_no_digest():
    res = await RegexScanner().scan("PASSWORD=hunter2abc123", "tool")
    assert res.scanner == "regex:key_value_credential"
    assert res.outcome is ScanOutcome.HUMAN_REVIEW
    assert "match_len=" in res.reason
    assert "match_sha256=" not in res.reason
    assert "match_hmac=" not in res.reason
    assert "hunter2abc123" not in res.reason


@pytest.mark.asyncio
async def test_connection_string_fingerprint_has_no_digest():
    res = await RegexScanner().scan(
        "mongodb://admin:secret@db.internal:27017/production", "tool"
    )
    assert res.scanner == "regex:connection_string"
    assert "match_len=" in res.reason
    assert "match_sha256=" not in res.reason
    assert "match_hmac=" not in res.reason
    assert "db.internal" not in res.reason


# ---------------------------------------------------------------------------
# awarm(): ImportError -> drop scanner (regex-only fallback), keep serving
# ---------------------------------------------------------------------------


class _MissingDepScanner:
    name = "missing-dep"

    async def scan(self, content, role, *, context=None):
        raise ImportError("onnxruntime not installed")


@pytest.mark.asyncio
async def test_awarm_drops_scanner_on_missing_dependency(caplog):
    from guardrails.models import ScanResult

    class _OkScanner:
        name = "ok"

        async def scan(self, content, role, *, context=None):
            return ScanResult.allow(self.name)

    missing = _MissingDepScanner()
    engine = _engine([_OkScanner(), missing])
    with caplog.at_level(logging.WARNING, logger="mcp.guardrails.engine"):
        await engine.awarm()
    # The dependency-missing scanner is gone from BOTH phase lists.
    assert all(s is not missing for s in engine._c.request_scanners)
    assert all(s is not missing for s in engine._c.response_scanners)
    assert any("removed from the scan chain" in r.message for r in caplog.records)
    assert engine.ready
    # And traffic still flows (allowed by the remaining scanner).
    decision = await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="t",
        params={"name": "t", "arguments": {"q": "benign"}},
        headers={},
    )
    assert not decision.deny


@pytest.mark.asyncio
async def test_awarm_keeps_fail_closed_on_model_load_failure():
    """A non-ImportError warmup failure (model present but broken) keeps the
    scanner in the chain — scan-time fail-closed semantics still apply."""

    class _BrokenModelScanner:
        name = "broken-model"

        async def scan(self, content, role, *, context=None):
            raise RuntimeError("model.onnx corrupt")

    broken = _BrokenModelScanner()
    engine = _engine([broken])
    await engine.awarm()
    assert any(s is broken for s in engine._c.request_scanners)
    # failClosed: scan-time error still denies.
    decision = await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="t",
        params={"name": "t", "arguments": {"q": "benign"}},
        headers={},
    )
    assert decision.deny
