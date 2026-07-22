"""Wave-2 audit & observability hardening tests (PR-B scope).

Covers:
* A-P0-1 exchange_id correlation (servicer extraction -> engine ref -> wire
  reason -> both audit lines),
* A-P1-1 audit field expansion (caller, payload_sha256, rules_version,
  sidecar_version, duration_ms, int-second ts + float-ms ts_ms) + OTel
  span sync,
* A-P0-2 AgentAlignment LLM-output redaction in audit reasons,
* A-P1-3 rules_reload audit line + counter on success AND failure,
* A-P0-4 sliding-window scanner error-rate health degradation,
* A-P1-2 metric instrument registration + low-cardinality labels.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import pytest

from guardrails.aggregator import DecisionAggregator
from guardrails.config import GuardrailConfig
from guardrails.engine import EngineComponents, GuardrailEngine
from guardrails.invariant import InvariantEngine
from guardrails.models import FailureMode, ScanOutcome, ScanResult
from guardrails.otel import Observability
from guardrails.proto_bridge import pb
from guardrails.scanners import AgentAlignmentScanner, StubScanner
from guardrails.servicer import ExtMcpServicer, _extract_exchange_id

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture_engine(
    *,
    request_scanners=None,
    response_scanners=None,
    config: GuardrailConfig | None = None,
) -> tuple[GuardrailEngine, list[dict[str, Any]]]:
    """Engine whose audit sink appends parsed records to a list."""
    config = config or GuardrailConfig(
        enable_regex_scanner=False,
        enable_promptguard=False,
        enable_agent_alignment=False,
        enable_redaction=False,
        failure_mode=FailureMode.FAIL_CLOSED,
        log_level="WARNING",
    )
    lines: list[dict[str, Any]] = []
    obs = Observability()
    obs.audit.emit = lambda rec: lines.append(dict(rec))
    comps = EngineComponents(
        request_scanners=request_scanners
        if request_scanners is not None
        else [StubScanner("regex")],
        response_scanners=response_scanners
        if response_scanners is not None
        else [StubScanner("regex")],
        invariant=InvariantEngine([], window=8),
        aggregator=DecisionAggregator(),
        observability=obs,
    )
    return GuardrailEngine(config, comps), lines


def _decision_lines(lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in lines if r.get("phase") in ("request", "response")]


# ---------------------------------------------------------------------------
# A-P0-1 — exchange_id correlation
# ---------------------------------------------------------------------------


def test_extract_exchange_id_never_trusts_payload_id():
    """A JSON-RPC ``id`` inside the attacker-controlled params/result body
    must NOT be adopted as the correlation id (forgery / log-injection)."""
    req = pb.McpRequest(method="tools/call")
    exchange_id = _extract_exchange_id(req)
    # No metadata/header -> uuid8 fallback; the forged payload id is ignored
    # by construction (the payload is not even an argument any more).
    assert len(exchange_id) == 8
    int(exchange_id, 16)  # hex


@pytest.mark.asyncio
async def test_forged_payload_id_not_adopted_end_to_end():
    """End-to-end: ``{"id": "forged"}`` in params never reaches the audit
    line's exchange_id (nor the wire ref)."""
    engine, lines = _capture_engine()
    servicer = ExtMcpServicer(engine)
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"id": "forged", "name": "t", "arguments": {}}).encode(),
    )
    await servicer.CheckRequest(req, None)
    audit = _decision_lines(lines)[-1]
    assert audit["exchange_id"] != "forged"
    assert audit["ref"] != "forged"


def test_extract_exchange_id_from_metadata_context():
    from google.protobuf import struct_pb2

    md = struct_pb2.Struct()
    md.update({"request_id": "req-abc"})
    req = pb.McpRequest(method="tools/call", metadata_context=md)
    assert _extract_exchange_id(req) == "req-abc"


def test_extract_exchange_id_sanitizes_control_chars():
    """A metadata-supplied id containing CR/LF is neutralised (log-injection
    guard) — control chars are stripped before the id is used."""
    from google.protobuf import struct_pb2

    md = struct_pb2.Struct()
    md.update({"exchange_id": "legit\nforge: injected\r\nevil"})
    req = pb.McpRequest(method="tools/call", metadata_context=md)
    cleaned = _extract_exchange_id(req)
    assert "\n" not in cleaned and "\r" not in cleaned
    assert cleaned == "legitforge: injectedevil"
    # An id that is ONLY control chars falls through to the uuid8 fallback.
    md2 = struct_pb2.Struct()
    md2.update({"exchange_id": "\r\n"})
    req2 = pb.McpRequest(method="tools/call", metadata_context=md2)
    fallback = _extract_exchange_id(req2)
    assert len(fallback) == 8
    int(fallback, 16)


def test_extract_exchange_id_from_header_and_fallback():
    req = pb.McpRequest(method="tools/call")
    assert _extract_exchange_id(req, {"X-Request-Id": "hdr-1"}) == "hdr-1"
    # Header ids are sanitised too.
    assert "\n" not in _extract_exchange_id(req, {"x-request-id": "a\nb"})
    # uuid8 fallback when nothing is available
    fallback = _extract_exchange_id(req)
    assert len(fallback) == 8
    int(fallback, 16)  # hex


@pytest.mark.asyncio
async def test_exchange_id_flows_to_audit_but_ref_stays_random():
    """metadata_context exchange_id lands on the audit line, but the wire
    deny reason's ref is an engine-minted random uuid8 — never the supplied
    exchange_id (PR-#65 semantics)."""
    from google.protobuf import struct_pb2

    engine, lines = _capture_engine(
        request_scanners=[StubScanner("regex", lambda c, r: ScanResult.block("regex", "boom"))]
    )
    servicer = ExtMcpServicer(engine)
    md = struct_pb2.Struct()
    md.update({"exchange_id": "ex-123"})
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"name": "t", "arguments": {}}).encode(),
        metadata_context=md,
    )
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "error"
    assert "ref ex-123" not in result.error.reason
    wire_ref = result.error.reason.removeprefix("denied by content policy (ref ").rstrip(")")
    assert len(wire_ref) == 8
    int(wire_ref, 16)
    audit = _decision_lines(lines)[-1]
    assert audit["exchange_id"] == "ex-123"
    assert audit["ref"] == wire_ref
    assert audit["ref"] != audit["exchange_id"]


@pytest.mark.asyncio
async def test_exchange_id_shared_across_request_and_response():
    """Same exchange_id supplied on both sides -> both audit lines correlate."""
    engine, lines = _capture_engine()
    d_req = await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="t",
        params={"name": "t", "arguments": {}},
        headers={},
        exchange_id="ex-both",
    )
    d_resp = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": "ok"}]},
        exchange_id="ex-both",
    )
    # refs are independent random uuid8s; exchange_id correlates the lines.
    assert d_req.ref != d_resp.ref
    assert "ex-both" not in (d_req.ref, d_resp.ref)
    audits = _decision_lines(lines)
    by_phase = {r["phase"]: r for r in audits}
    assert by_phase["request"]["exchange_id"] == "ex-both"
    assert by_phase["response"]["exchange_id"] == "ex-both"
    assert by_phase["request"]["ref"] == d_req.ref
    assert by_phase["response"]["ref"] == d_resp.ref


@pytest.mark.asyncio
async def test_exchange_id_uuid_fallback_unique():
    engine, _ = _capture_engine()
    d1 = await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="t",
        params={"name": "t", "arguments": {}},
        headers={},
    )
    d2 = await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="t",
        params={"name": "t", "arguments": {}},
        headers={},
    )
    assert d1.ref and d2.ref and d1.ref != d2.ref


# ---------------------------------------------------------------------------
# A-P1-1 — audit field expansion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_line_carries_new_fields():
    engine, lines = _capture_engine()
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="t",
        params={"name": "t", "arguments": {"q": "hello"}},
        headers={"X-Forwarded-User": "alice", "authorization": "Bearer SECRET"},
    )
    rec = _decision_lines(lines)[-1]
    # caller: whitelisted header only — authorization must NOT leak.
    assert rec["caller"] == "alice"
    assert "SECRET" not in json.dumps(rec)
    assert rec["payload_sha256"] and len(rec["payload_sha256"]) == 12
    assert "rules_version" in rec
    assert rec["sidecar_version"]
    assert isinstance(rec["duration_ms"], float) and rec["duration_ms"] >= 0
    # ts is epoch SECONDS as an int; ts_ms is epoch milliseconds as a
    # float, sampled from the same clock reading.
    assert isinstance(rec["ts"], int)
    assert rec["ts"] > 1_000_000_000  # > 2001 in s
    assert abs(rec["ts"] - time.time()) < 60
    assert isinstance(rec["ts_ms"], float)
    assert rec["ts_ms"] > 1_000_000_000_000  # > 2001 in ms
    assert abs(rec["ts_ms"] - rec["ts"] * 1000.0) < 1_000
    assert "exchange_id" in rec


def test_caller_header_whitelist_configurable():
    cfg = GuardrailConfig(audit_caller_headers=("x-operator",))
    assert cfg.audit_caller_headers == ("x-operator",)
    # from_env honours AUDIT_CALLER_HEADERS
    import os

    os.environ["AUDIT_CALLER_HEADERS"] = "x-a, x-b ,,"
    try:
        env_cfg = GuardrailConfig.from_env()
    finally:
        del os.environ["AUDIT_CALLER_HEADERS"]
    assert env_cfg.audit_caller_headers == ("x-a", "x-b")


@pytest.mark.asyncio
async def test_span_attrs_carry_exchange_and_payload_hash():
    """OTel span (audit span fallback) carries the correlation fields."""
    engine, lines = _capture_engine()
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="t",
        params={"name": "t", "arguments": {}},
        headers={"x-forwarded-user": "alice"},
        exchange_id="ex-span",
    )
    span = next(r for r in lines if r.get("event") == "guardrail.check_request")
    assert span["exchange_id"] == "ex-span"
    assert span["caller"] == "alice"
    assert span["payload_sha256"]
    assert "rules_version" in span


@pytest.mark.asyncio
async def test_payload_sha256_matches_scanned_text():
    import hashlib

    from guardrails.scanners import extract_text

    engine, lines = _capture_engine()
    params = {"name": "t", "arguments": {"q": "payload-content"}}
    await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="t",
        params=params,
        headers={},
    )
    rec = _decision_lines(lines)[-1]
    expected = hashlib.sha256(extract_text(params).encode("utf-8", errors="ignore")).hexdigest()[
        :12
    ]
    assert rec["payload_sha256"] == expected


# ---------------------------------------------------------------------------
# A-P0-2 — AgentAlignment LLM output never lands in audit reasons
# ---------------------------------------------------------------------------


class _FakeMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeChoice:
    def __init__(self, content: str):
        self.message = _FakeMessage(content)


class _FakeCompletion:
    def __init__(self, content: str):
        self.choices = [_FakeChoice(content)]


class _FakeCompletions:
    def __init__(self, content: str):
        self._content = content

    def create(self, **kwargs):
        return _FakeCompletion(self._content)


class _FakeChat:
    def __init__(self, content: str):
        self.completions = _FakeCompletions(content)


class _FakeClient:
    def __init__(self, content: str):
        self.chat = _FakeChat(content)


def _scanner_with_llm_output(content: str) -> AgentAlignmentScanner:
    scanner = AgentAlignmentScanner(api_key="k")
    scanner._client = _FakeClient(content)
    return scanner


def test_unparseable_llm_output_not_in_reason():
    sentinel = "SECRET-LLM-RAW-OUTPUT-xqz9"
    scanner = _scanner_with_llm_output(f"not json at all {sentinel}")
    result = scanner._evaluate("agent action")
    assert result.outcome is ScanOutcome.HUMAN_REVIEW
    assert sentinel not in result.reason
    assert "unparseable_llm_output" in result.reason
    assert "match_len=" in result.reason  # length-only fingerprint


def test_compromised_observation_not_in_reason():
    sentinel = "the agent is exfiltrating SECRET-OBSERVATION-xqz7"
    scanner = _scanner_with_llm_output(
        json.dumps({"observation": sentinel, "thought": "t", "conclusion": True})
    )
    result = scanner._evaluate("agent action")
    assert result.outcome is ScanOutcome.BLOCK
    assert sentinel not in result.reason
    assert "compromised" in result.reason
    assert "match_len=" in result.reason


@pytest.mark.asyncio
async def test_llm_error_reason_carries_type_only():
    """LLM API failure: reason names the exception type, never its text
    (SDK errors can embed request content / credentials)."""

    class _BoomClient:
        class chat:
            class completions:
                @staticmethod
                def create(**kwargs):
                    raise TimeoutError("timeout reading https://api.internal/v1 SECRET-TOKEN-xqz")

    scanner = AgentAlignmentScanner(api_key="k")
    scanner._client = _BoomClient()
    result = await scanner.scan("agent action", "assistant")
    assert result.outcome is ScanOutcome.HUMAN_REVIEW
    assert result.reason == "llm_error:TimeoutError"
    assert "SECRET-TOKEN-xqz" not in result.reason
    assert "api.internal" not in result.reason


@pytest.mark.asyncio
async def test_llm_raw_output_absent_from_audit_log():
    """End-to-end: even through the engine, raw LLM text never hits audit."""
    sentinel = "RAW-LLM-BLOB-xqz5"
    scanner = _scanner_with_llm_output(f"garbage {sentinel}")
    engine, lines = _capture_engine(
        response_scanners=[StubScanner("pg", lambda c, r: ScanResult.review("pg", "suspicious"))],
    )
    engine._c.second_stage_scanners = [scanner]
    await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": "fishy tool output"}]},
    )
    blob = json.dumps(lines)
    assert sentinel not in blob
    assert "unparseable_llm_output" in blob


# ---------------------------------------------------------------------------
# A-P1-3 — rules_reload audit + counter
# ---------------------------------------------------------------------------


def test_reload_emits_audit_on_success_and_failure(monkeypatch, tmp_path, caplog):
    import textwrap

    from guardrails.rules import RulePack

    pack = tmp_path / "rules.policy"
    pack.write_text(
        textwrap.dedent(
            """
            from guardrails.invariant import FlowStep, ToxicFlowRule
            RULES = [ToxicFlowRule(name='r0', steps=[FlowStep(tool='a')])]
            """
        )
    )
    monkeypatch.setenv("INVARIANT_RULES_PATH", str(pack))
    monkeypatch.setenv("AUDIT_LOG_PATH", "-")

    engine, lines = _capture_engine()
    engine._c.rule_pack = RulePack.from_env()

    count = engine.reload_rules()
    assert count == 1
    reload_lines = [r for r in lines if r.get("event") == "rules_reload"]
    assert reload_lines and reload_lines[-1]["ok"] is True
    assert reload_lines[-1]["rule_count"] == 1
    assert "rules_version" in reload_lines[-1]

    # Break the pack — failure must also be audited, and the error re-raised.
    pack.write_text("RULES = [")
    with caplog.at_level(logging.WARNING), pytest.raises(SyntaxError):
        engine.reload_rules()
    reload_lines = [r for r in lines if r.get("event") == "rules_reload"]
    assert reload_lines[-1]["ok"] is False
    assert "SyntaxError" in reload_lines[-1]["error"]


# ---------------------------------------------------------------------------
# A-P1-2 — metric registration + label cardinality
# ---------------------------------------------------------------------------


class _FakeInstrument:
    def __init__(self, kind: str):
        self.kind = kind
        self.calls: list[tuple[Any, Any]] = []

    def add(self, value, attributes=None):
        self.calls.append((value, attributes))

    def record(self, value, attributes=None):
        self.calls.append((value, attributes))


class _FakeMeter:
    def __init__(self):
        self.instruments: dict[str, _FakeInstrument] = {}

    def create_counter(self, name, unit=None, description=None):
        inst = _FakeInstrument("counter")
        self.instruments[name] = inst
        return inst

    def create_histogram(self, name, unit=None, description=None):
        inst = _FakeInstrument("histogram")
        self.instruments[name] = inst
        return inst


def test_metric_instruments_registered():
    obs = Observability()
    meter = _FakeMeter()
    obs._meter = meter
    obs._init_instruments()
    names = set(meter.instruments)
    assert names == {
        "mcp.guardrails.decisions",
        "mcp.guardrails.scanner_results",
        "mcp.guardrails.redactions",
        "mcp.guardrails.invariant_hits",
        "mcp.guardrails.rules_reload",
        "mcp.guardrails.decision_duration_ms",
    }
    assert meter.instruments["mcp.guardrails.decision_duration_ms"].kind == "histogram"


@pytest.mark.asyncio
async def test_metrics_recorded_with_low_cardinality_labels():
    from guardrails.invariant import FlowStep, ToxicFlowRule
    from guardrails.rules import RulePack

    obs = Observability()
    meter = _FakeMeter()
    obs._meter = meter
    obs._init_instruments()

    inv = InvariantEngine(
        [ToxicFlowRule(name="exfil", steps=[FlowStep(tool="email_send")])], window=8
    )
    config = GuardrailConfig(
        enable_redaction=False,
        failure_mode=FailureMode.FAIL_CLOSED,
        log_level="WARNING",
    )
    comps = EngineComponents(
        request_scanners=[StubScanner("regex")],
        response_scanners=[],
        invariant=inv,
        rule_pack=RulePack([]),
        aggregator=DecisionAggregator(),
        observability=obs,
    )
    engine = GuardrailEngine(config, comps)
    decision = await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="email_send",
        params={"name": "email_send", "arguments": {}},
        headers={},
    )
    assert decision.deny

    scanner_results = meter.instruments["mcp.guardrails.scanner_results"].calls
    scanners_labeled = {attrs["scanner"] for _, attrs in scanner_results}
    assert "regex" in scanners_labeled
    assert any(s.startswith("invariant:") for s in scanners_labeled)
    for _, attrs in scanner_results:
        assert set(attrs) <= {"scanner", "outcome"}

    hits = meter.instruments["mcp.guardrails.invariant_hits"].calls
    assert hits and hits[0][1] == {"rule": "exfil"}

    hist = meter.instruments["mcp.guardrails.decision_duration_ms"].calls
    assert hist and set(hist[0][1]) <= {"phase", "outcome"}

    # No per-exchange label values anywhere (ref, exchange_id, tool, caller).
    for inst in meter.instruments.values():
        for _, attrs in inst.calls:
            for key in attrs or {}:
                assert key in {"phase", "outcome", "method", "scanner", "rule", "result"}


def test_rules_reload_counter_and_redactions_counter():
    obs = Observability()
    meter = _FakeMeter()
    obs._meter = meter
    obs._init_instruments()
    obs.record_rules_reload(ok=True)
    obs.record_rules_reload(ok=False)
    calls = meter.instruments["mcp.guardrails.rules_reload"].calls
    assert [a["result"] for _, a in calls] == ["success", "error"]
    obs.record_redactions(3)
    obs.record_redactions(0)  # no-op
    red = meter.instruments["mcp.guardrails.redactions"].calls
    assert red == [(3, None)]


# ---------------------------------------------------------------------------
# A-P0-4 — runtime health degradation
# ---------------------------------------------------------------------------


class _FlakyScanner:
    def __init__(self, fail: bool):
        self.name = "flaky"
        self.fail = fail

    async def scan(self, content, role, *, context=None):
        if self.fail:
            raise RuntimeError("scanner exploded")
        return ScanResult.allow(self.name)


def _health_engine(fail: bool, **cfg_kw) -> GuardrailEngine:
    config = GuardrailConfig(
        enable_redaction=False,
        failure_mode=FailureMode.FAIL_OPEN,  # degradation tracked under failOpen too
        log_level="WARNING",
        **cfg_kw,
    )
    comps = EngineComponents(
        request_scanners=[_FlakyScanner(fail)],
        response_scanners=[],
        invariant=None,
        aggregator=DecisionAggregator(),
        observability=Observability(),
    )
    return GuardrailEngine(config, comps)


async def _drive(engine: GuardrailEngine, n: int) -> None:
    for _ in range(n):
        await engine.check_request(
            method="tools/call",
            service_names=["svc"],
            tool_name="t",
            params={"name": "t", "arguments": {}},
            headers={},
        )


@pytest.mark.asyncio
async def test_health_flips_not_serving_on_high_error_rate():
    engine = _health_engine(fail=True, unhealthy_scanner_min_samples=10)
    engine._ready = True
    await _drive(engine, 12)
    assert engine.healthy is False


@pytest.mark.asyncio
async def test_health_recovers_after_errors_age_out():
    engine = _health_engine(
        fail=True,
        unhealthy_scanner_min_samples=10,
        unhealthy_scanner_window=15,
    )
    engine._ready = True
    await _drive(engine, 12)
    assert engine.healthy is False
    # Scanner recovers; successful scans push the failures out of the window.
    engine._c.request_scanners[0].fail = False
    await _drive(engine, 15)
    assert engine.healthy is True


@pytest.mark.asyncio
async def test_health_holds_below_min_samples_and_before_warmup():
    engine = _health_engine(fail=True, unhealthy_scanner_min_samples=20)
    # Not warmed up yet -> unhealthy regardless of scanner stats.
    assert engine.healthy is False
    engine._ready = True
    await _drive(engine, 5)  # 5 errors < min_samples 20
    assert engine.healthy is True


@pytest.mark.asyncio
async def test_health_ok_under_threshold():
    engine = _health_engine(
        fail=False, unhealthy_scanner_min_samples=5, unhealthy_scanner_error_rate=0.5
    )
    engine._ready = True
    await _drive(engine, 10)
    assert engine.healthy is True


@pytest.mark.asyncio
async def test_health_timeout_counts_as_error():
    class _SlowScanner:
        name = "slow"

        async def scan(self, content, role, *, context=None):
            import asyncio

            await asyncio.sleep(5)
            return ScanResult.allow(self.name)

    config = GuardrailConfig(
        enable_redaction=False,
        failure_mode=FailureMode.FAIL_OPEN,
        log_level="WARNING",
        scanner_timeout_ms=20,
        unhealthy_scanner_min_samples=5,
    )
    comps = EngineComponents(
        request_scanners=[_SlowScanner()],
        response_scanners=[],
        invariant=None,
        aggregator=DecisionAggregator(),
        observability=Observability(),
    )
    engine = GuardrailEngine(config, comps)
    engine._ready = True
    await _drive(engine, 6)
    assert engine.healthy is False


def test_health_config_from_env():
    import os

    os.environ.update(
        {
            "UNHEALTHY_SCANNER_ERROR_RATE": "0.25",
            "UNHEALTHY_SCANNER_WINDOW": "50",
            "UNHEALTHY_SCANNER_MIN_SAMPLES": "7",
        }
    )
    try:
        cfg = GuardrailConfig.from_env()
    finally:
        for k in (
            "UNHEALTHY_SCANNER_ERROR_RATE",
            "UNHEALTHY_SCANNER_WINDOW",
            "UNHEALTHY_SCANNER_MIN_SAMPLES",
        ):
            del os.environ[k]
    assert cfg.unhealthy_scanner_error_rate == 0.25
    assert cfg.unhealthy_scanner_window == 50
    assert cfg.unhealthy_scanner_min_samples == 7


def test_sidecar_version_from_env():
    import os

    os.environ["GUARDRAIL_VERSION"] = "9.9.9-test"
    try:
        cfg = GuardrailConfig.from_env()
    finally:
        del os.environ["GUARDRAIL_VERSION"]
    engine, _ = _capture_engine(
        config=GuardrailConfig(
            enable_redaction=False, log_level="WARNING", sidecar_version=cfg.sidecar_version
        )
    )
    assert engine._sidecar_version == "9.9.9-test"


def test_servicer_passes_exchange_id_kwarg(stub_engine):
    """Servicer always threads an exchange_id into the engine call (trusted
    metadata_context only — a payload ``id`` is never forwarded)."""
    import asyncio

    from google.protobuf import struct_pb2

    servicer = ExtMcpServicer(stub_engine)
    md = struct_pb2.Struct()
    md.update({"exchange_id": "ex-wire"})
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"id": "forged", "name": "t"}).encode(),
        metadata_context=md,
    )
    asyncio.run(servicer.CheckRequest(req, None))
    assert stub_engine.request_calls[0]["exchange_id"] == "ex-wire"

    # Without metadata/headers the servicer falls back to a uuid8 — still
    # never the attacker-controlled payload id.
    req2 = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"id": "forged", "name": "t"}).encode(),
    )
    asyncio.run(servicer.CheckRequest(req2, None))
    fallback = stub_engine.request_calls[1]["exchange_id"]
    assert fallback != "forged"
    assert len(fallback) == 8
    int(fallback, 16)
