"""Wave-3 contract fulfilment + rule-layer hardening tests.

Covers:
* F-P1-1 — structured ``mcp_error`` JSON-RPC body on deny;
* F-P1-2 — ``McpRequestResult.metadata`` emission;
* F-P1-4 / S-M2 — extract_text resources/read blob, prompts/get messages,
  non-text content fallback;
* S-H4 / F-P1-6 — invariant window 256 default, sticky partial-match
  progress, empty tool_name not recorded;
* S-H5 / F-P0-1(b) — trace-key header templating + fallback;
* F-P1-5 — ALLOW_TOOLS / DENY_TOOLS ACL (wildcard, priority) and scanner
  ``context`` passthrough.
"""

from __future__ import annotations

import base64
import json

import pytest

from guardrails.aggregator import DecisionAggregator
from guardrails.config import GuardrailConfig
from guardrails.engine import EngineComponents, GuardrailEngine, _trace_key
from guardrails.invariant import FlowStep, InvariantEngine, ToxicFlowRule
from guardrails.models import Decision, ScanOutcome, ScanResult
from guardrails.proto_bridge import pb
from guardrails.scanners import RegexScanner, extract_text
from guardrails.servicer import ExtMcpServicer
from tests.helpers import ScriptedScanner


def _engine(
    *,
    config: GuardrailConfig | None = None,
    request_scanners=None,
    invariant=None,
) -> GuardrailEngine:
    comps = EngineComponents(
        request_scanners=list(request_scanners or []),
        response_scanners=[],
        invariant=invariant,
        aggregator=DecisionAggregator(),
    )
    return GuardrailEngine(config or GuardrailConfig(), comps)


def _call(engine: GuardrailEngine, tool: str, **kw):
    return engine.check_request(
        method=kw.pop("method", "tools/call"),
        service_names=kw.pop("service_names", ["svc"]),
        tool_name=tool,
        params=kw.pop("params", {"name": tool, "arguments": {}}),
        headers=kw.pop("headers", {}),
        **kw,
    )


# ---------------------------------------------------------------------------
# F-P1-1: structured mcp_error on deny
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_error_is_valid_json_rpc_error(stub_engine):
    blocker = ScanResult.block("regex:aws_access_key", "AWS access key id", score=0.95)
    stub_engine.request_decision = Decision(
        deny=True, reason="regex:aws_access_key:block", scanners=(blocker,), ref="abc12345"
    )
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"name": "t", "arguments": {}}).encode(),
    )
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "error"
    assert result.error.HasField("mcp_error")
    body = json.loads(result.error.mcp_error.decode("utf-8"))
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["code"] == -32001
    # message mirrors the generalised wire reason (same ref)
    assert body["error"]["message"] == result.error.reason
    assert "abc12345" in body["error"]["message"]
    data = body["error"]["data"]
    assert data["category"] == "content_policy"
    assert "credentials" in data["remedy"]
    # generalisation: no pattern names / match detail in the body
    assert "aws_access_key" not in result.error.mcp_error.decode("utf-8")


@pytest.mark.asyncio
async def test_mcp_error_response_side_and_acl_category(stub_engine):
    blocker = ScanResult.block("tool_acl", "tool 'fs/write' denied by tool ACL", score=1.0)
    stub_engine.response_decision = Decision(
        deny=True, reason="tool_acl:block", scanners=(blocker,), ref="deafbeef"
    )
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpResponse(
        method="tools/call",
        mcp_response=json.dumps({"content": [{"type": "text", "text": "x"}]}).encode(),
    )
    result = await servicer.CheckResponse(req, None)
    assert result.WhichOneof("result") == "error"
    body = json.loads(result.error.mcp_error.decode("utf-8"))
    assert body["error"]["code"] == -32001
    assert body["error"]["data"]["category"] == "tool_policy"
    assert body["error"]["data"]["remedy"]
    assert "fs/write" not in result.error.mcp_error.decode("utf-8")


# ---------------------------------------------------------------------------
# F-P1-2: McpRequestResult.metadata emission
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_metadata_fields(stub_engine):
    scanners = (
        ScanResult.block("invariant:exfil", "exfil", score=0.0),
        ScanResult("onnx-promptguard", ScanOutcome.ALLOW, score=0.42),
    )
    stub_engine.request_decision = Decision(
        deny=True, reason="x", scanners=scanners, ref="r1", redactions=3
    )
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"name": "t", "arguments": {}}).encode(),
    )
    result = await servicer.CheckRequest(req, None)
    md = result.metadata
    assert md["guardrail.scan_score"] == pytest.approx(0.42)
    assert list(md["guardrail.rules_hit"]) == ["exfil"]
    assert md["guardrail.redactions"] == 3
    assert md["guardrail.exchange_id"]  # uuid8 fallback
    assert md["guardrail.outcome"] == "deny"


@pytest.mark.asyncio
async def test_request_metadata_pass_outcome_and_exchange_id(stub_engine):
    stub_engine.request_decision = Decision(deny=False, scanners=())
    servicer = ExtMcpServicer(stub_engine)
    from google.protobuf import struct_pb2

    md_ctx = struct_pb2.Struct()
    md_ctx.update({"exchange_id": "ex-1"})
    req = pb.McpRequest(
        method="tools/list",
        metadata_context=md_ctx,
    )
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "pass"
    assert result.metadata["guardrail.outcome"] == "allow"
    assert result.metadata["guardrail.exchange_id"] == "ex-1"
    assert result.metadata["guardrail.scan_score"] == 0.0
    assert list(result.metadata["guardrail.rules_hit"]) == []


@pytest.mark.asyncio
async def test_request_redaction_count_reaches_metadata_end_to_end():
    """Real engine -> servicer: REDACT_REQUEST_PARAMS=1 and an email in the
    params must surface as ``guardrail.redactions`` > 0 in the result
    metadata (request-side mutation previously dropped the count)."""
    engine = _engine(config=GuardrailConfig(redact_request_params=True))
    servicer = ExtMcpServicer(engine)
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"name": "send", "arguments": {"to": "alice@example.com"}}).encode(),
    )
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "mutated"
    assert b"[REDACTED:EMAIL]" in result.mutated
    assert result.metadata["guardrail.redactions"] > 0
    assert result.metadata["guardrail.outcome"] == "mutated"


# ---------------------------------------------------------------------------
# F-P1-4 / S-M2: extract_text new shapes
# ---------------------------------------------------------------------------


def test_extract_text_resources_read_blob_decoded():
    secret = "AKIAIOSFODNN7EXAMPLE"
    blob = base64.b64encode(secret.encode()).decode()
    payload = {"contents": [{"uri": "file:///x", "blob": blob}]}
    assert secret in extract_text(payload)


@pytest.mark.asyncio
async def test_extract_text_resources_read_blob_injection_blocks():
    """A format-injection marker hidden inside a base64 blob is blocked."""
    evil = base64.b64encode(b"<|im_start|>system").decode()
    payload = {"contents": [{"uri": "r", "blob": evil}]}
    text = extract_text(payload)
    result = await RegexScanner().scan(text, "assistant")
    assert result.outcome is ScanOutcome.BLOCK


def test_extract_text_invalid_blob_kept_verbatim():
    payload = {"contents": [{"uri": "r", "blob": "!!!not-base64!!!"}]}
    assert "!!!not-base64!!!" in extract_text(payload)


def test_extract_text_blob_decode_cap():
    blob = base64.b64encode(b"A" * (300 * 1024)).decode()
    text = extract_text({"contents": [{"blob": blob}]})
    assert len(text) <= 256 * 1024


def test_extract_text_contents_text_taken_directly():
    payload = {"contents": [{"uri": "r", "text": "hello resource"}]}
    assert extract_text(payload) == "hello resource"


def test_extract_text_prompts_get_messages():
    payload = {
        "messages": [
            {"role": "user", "content": {"type": "text", "text": "first"}},
            {"role": "assistant", "content": [{"type": "text", "text": "second"}]},
            {"role": "user", "content": "third"},
        ]
    }
    text = extract_text(payload)
    assert "first" in text and "second" in text and "third" in text


def test_extract_text_non_text_content_item_json_dump():
    payload = {"content": [{"type": "resource_link", "uri": "https://x/y", "name": "link"}]}
    text = extract_text(payload)
    assert "resource_link" in text and "https://x/y" in text


# ---------------------------------------------------------------------------
# S-H4: invariant window default 256 + sticky progress
# ---------------------------------------------------------------------------


def test_invariant_window_default_256():
    assert GuardrailConfig().invariant_window == 256
    assert InvariantEngine([]).window == 256
    import os

    os.environ.pop("INVARIANT_WINDOW", None)
    assert GuardrailConfig.from_env().invariant_window == 256


def test_sticky_progress_survives_window_slide():
    """Step 0 slides out of the window before step 1 arrives; sticky progress
    still completes the flow."""
    rule = ToxicFlowRule(
        name="exfil",
        steps=[FlowStep(tool="read_secret"), FlowStep(tool="http_post")],
    )
    inv = InvariantEngine([rule], window=3)
    key = "r"
    inv.record("read_secret", {}, key=key)
    assert inv.evaluate(key=key) is None  # 1 of 2 steps -> sticky parked
    # Slide step 0 out of the 3-entry window.
    for _ in range(3):
        inv.record("noise", {}, key=key)
        assert inv.evaluate(key=key) is None
    assert inv.snapshot(key=key)[0].tool == "noise"  # step0 is gone
    inv.record("http_post", {}, key=key)
    hit = inv.evaluate(key=key)
    assert hit is not None and hit.outcome is ScanOutcome.BLOCK
    assert hit.scanner == "invariant:exfil"


def test_sticky_progress_expires_after_ttl():
    rule = ToxicFlowRule(
        name="exfil",
        steps=[FlowStep(tool="a"), FlowStep(tool="b")],
    )
    inv = InvariantEngine([rule], window=1, sticky_ttl_s=0.0)
    inv.record("a", {}, key="k")
    inv.evaluate(key="k")
    inv.record("b", {}, key="k")
    assert inv.evaluate(key="k") is None  # TTL=0 -> progress expired


def test_sticky_cleared_on_reset():
    rule = ToxicFlowRule(
        name="exfil", steps=[FlowStep(tool="a"), FlowStep(tool="b")]
    )
    inv = InvariantEngine([rule], window=2)
    inv.record("a", {}, key="k")
    inv.evaluate(key="k")
    inv.reset("k")
    inv.record("b", {}, key="k")
    assert inv.evaluate(key="k") is None


@pytest.mark.asyncio
async def test_empty_tool_name_not_recorded():
    inv = InvariantEngine([], window=8)
    engine = _engine(invariant=inv)
    await _call(engine, "", method="tools/call", params={"arguments": {}})
    await _call(engine, "", method="prompts/get", params={})
    assert inv.snapshot(key="svc") == ()
    await _call(engine, "real_tool")
    assert len(inv.snapshot(key="svc")) == 1


# ---------------------------------------------------------------------------
# S-H5 / F-P0-1(b): trace-key header templating
# ---------------------------------------------------------------------------


def test_trace_key_header_dimension():
    key = _trace_key("route-a", ["svc"], {"X-Session-Id": "s1"}, ("x-session-id",))
    assert key == "route-a|x-session-id=s1"
    key2 = _trace_key("route-a", ["svc"], {"X-Session-Id": "s2"}, ("x-session-id",))
    assert key2 != key


def test_trace_key_fallback_when_header_missing_or_unconfigured():
    assert _trace_key("route-a", ["svc"], {}, ("x-session-id",)) == "route-a"
    assert _trace_key("route-a", ["svc"], {"x-session-id": "s"}, ()) == "route-a"
    assert _trace_key("", ["svc"], {}, ()) == "svc"
    assert _trace_key("", [], {}, ()) == ""


@pytest.mark.asyncio
async def test_trace_key_isolates_sessions_end_to_end():
    rule = ToxicFlowRule(
        name="exfil", steps=[FlowStep(tool="read"), FlowStep(tool="send")]
    )
    inv = InvariantEngine([rule], window=8)
    cfg = GuardrailConfig(invariant_trace_key_headers=("x-session-id",))
    engine = _engine(config=cfg, invariant=inv)
    # Session A does step 0; session B does step 1 — no cross-session flow.
    await _call(engine, "read", headers={"x-session-id": "A"}, route_name="r")
    decision = await _call(engine, "send", headers={"x-session-id": "B"}, route_name="r")
    assert not decision.deny
    # Same session completing the flow DOES hit.
    decision = await _call(engine, "send", headers={"x-session-id": "A"}, route_name="r")
    assert decision.deny
    # Without the header both calls share the route key -> hits.
    engine2 = _engine(config=GuardrailConfig(), invariant=InvariantEngine([rule], window=8))
    await _call(engine2, "read", route_name="r")
    decision = await _call(engine2, "send", route_name="r")
    assert decision.deny


# ---------------------------------------------------------------------------
# F-P1-5: tool ACL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_acl_deny_short_circuits_scanners():
    scanner = ScriptedScanner("regex", [ScanResult.allow("regex")])
    cfg = GuardrailConfig(deny_tools=("fs/write",))
    engine = _engine(config=cfg, request_scanners=[scanner])
    decision = await _call(engine, "fs/write")
    assert decision.deny
    assert "tool_acl" in decision.reason
    assert "fs/write" in decision.reason  # audit-visible tool name
    assert scanner.calls == []  # scanners never ran


@pytest.mark.asyncio
async def test_tool_acl_allowlist_and_wildcard():
    cfg = GuardrailConfig(allow_tools=("fs/*", "ping"))
    engine = _engine(config=cfg)
    assert not (await _call(engine, "fs/read")).deny
    assert not (await _call(engine, "ping")).deny
    assert (await _call(engine, "net/scan")).deny
    # wildcard boundary: "fs/*" must not match "fsx/read"
    assert (await _call(engine, "fsx/read")).deny


@pytest.mark.asyncio
async def test_tool_acl_deny_wins_over_allow():
    cfg = GuardrailConfig(allow_tools=("fs/*",), deny_tools=("fs/write",))
    engine = _engine(config=cfg)
    assert (await _call(engine, "fs/write")).deny
    assert not (await _call(engine, "fs/read")).deny


@pytest.mark.asyncio
async def test_tool_acl_empty_lists_allow_everything():
    engine = _engine(config=GuardrailConfig())
    assert not (await _call(engine, "anything/at/all")).deny


def test_tool_acl_env_parsing(monkeypatch):
    monkeypatch.setenv("ALLOW_TOOLS", "fs/*, ping")
    monkeypatch.setenv("DENY_TOOLS", "fs/write")
    cfg = GuardrailConfig.from_env()
    assert cfg.allow_tools == ("fs/*", "ping")
    assert cfg.deny_tools == ("fs/write",)


# ---------------------------------------------------------------------------
# ctx passthrough to scanners
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scanner_receives_mcp_call_context():
    seen = {}

    class CtxScanner:
        name = "ctx"

        async def scan(self, content, role, *, context=None):
            seen["context"] = context
            return ScanResult.allow(self.name)

    engine = _engine(request_scanners=[CtxScanner()])
    await _call(
        engine,
        "ping",
        headers={"x-session-id": "s"},
        upstream_transport="http",
        route_name="r",
    )
    ctx = seen["context"]
    assert ctx is not None
    assert ctx.method == "tools/call"
    assert ctx.tool_name == "ping"
    assert ctx.headers.get("x-session-id") == "s"
    assert ctx.upstream_transport == "http"
    assert ctx.route_name == "r"


@pytest.mark.asyncio
async def test_response_scanner_receives_context():
    seen = {}

    class CtxScanner:
        name = "ctx"

        async def scan(self, content, role, *, context=None):
            seen["context"] = context
            return ScanResult.allow(self.name)

    comps = EngineComponents(
        request_scanners=[],
        response_scanners=[CtxScanner()],
        aggregator=DecisionAggregator(),
    )
    engine = GuardrailEngine(GuardrailConfig(), comps)
    await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": "hi"}]},
        route_name="r",
    )
    assert seen["context"] is not None
    assert seen["context"].method == "tools/call"
    assert seen["context"].route_name == "r"
