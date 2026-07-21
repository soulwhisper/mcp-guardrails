"""Regression tests for the P1 security hardening round.

Covers two gaps called out in the security assessment:

1. **Truncation bypass** — an attacker pads a payload past ``max_content_bytes``
   so the injection lands beyond the scanned head. ``scan_windows`` now feeds
   the head AND a UTF-8-safe tail window to the content scanners.
2. **Cross-tenant trace contamination** — the InvariantEngine kept ONE global
   trace, so interleaved calls from different routes could assemble a
   cross-tenant toxic flow or trip a loop rule. Traces are now isolated per
   route key with a bounded LRU.
"""

from __future__ import annotations

import pytest

from guardrails.engine import EngineComponents, GuardrailEngine
from guardrails.invariant import FlowStep, InvariantEngine, LoopRule, ToxicFlowRule
from guardrails.scanners import RegexScanner, scan_windows, truncate


def _big_pad(n: int) -> str:
    return "benign padding. " * (n // 16 + 1)


# ---------------------------------------------------------------------------
# scan_windows
# ---------------------------------------------------------------------------


def test_scan_windows_in_budget_single_chunk():
    chunks, truncated = scan_windows("short text", 1024, 256)
    assert chunks == ["short text"]
    assert truncated is False


def test_scan_windows_over_budget_returns_head_and_tail():
    text = _big_pad(4096) + "TAIL_MARK"
    chunks, truncated = scan_windows(text, 1024, 256)
    assert truncated is True
    assert len(chunks) == 2
    assert len(chunks[0].encode()) <= 1024
    assert chunks[1].endswith("TAIL_MARK")
    assert len(chunks[1].encode()) <= 256


def test_scan_windows_tail_disabled():
    text = _big_pad(4096) + "TAIL_MARK"
    chunks, truncated = scan_windows(text, 1024, 0)
    assert truncated is True
    assert len(chunks) == 1


def test_scan_windows_tail_utf8_safe():
    # Multi-byte emoji straddling the tail cut must not produce mojibake.
    text = _big_pad(2048) + "\U0001f512" * 200
    chunks, truncated = scan_windows(text, 1024, 100)
    assert truncated is True
    tail = chunks[1]
    tail.encode("utf-8")  # round-trips without error
    assert "\U0001f512" in tail
    assert tail.endswith("\U0001f512")


def test_scan_windows_tail_overlaps_head():
    # tail_bytes >= max_bytes: the tail window covers the head — still exactly
    # two chunks, both scanned, no crash.
    text = _big_pad(4096) + "TAIL_MARK"
    chunks, truncated = scan_windows(text, 512, 2048)
    assert truncated is True
    assert len(chunks) == 2
    assert chunks[1].endswith("TAIL_MARK")


def test_truncate_contract_unchanged():
    assert truncate("abc", 10) == ("abc", False)


# ---------------------------------------------------------------------------
# Engine: injection hidden in the tail is blocked (truncation bypass)
# ---------------------------------------------------------------------------


@pytest.fixture
def regex_engine():
    from guardrails.config import GuardrailConfig

    config = GuardrailConfig(
        max_content_bytes=1024,
        scan_tail_bytes=256,
        enable_regex_scanner=True,
        enable_promptguard=False,
    )
    return GuardrailEngine(
        config,
        EngineComponents(
            request_scanners=[RegexScanner()],
            response_scanners=[RegexScanner()],
        ),
    )


@pytest.mark.asyncio
async def test_tail_injection_blocked_on_request(regex_engine):
    payload = {
        "name": "read",
        "arguments": {"data": _big_pad(4096) + "-----BEGIN RSA PRIVATE KEY-----\nMIIEp"},
    }
    decision = await regex_engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="read",
        params=payload,
        headers={},
    )
    assert decision.deny, "private key hidden beyond the head cut must be caught by the tail window"


@pytest.mark.asyncio
async def test_tail_injection_blocked_on_response(regex_engine):
    result = {"content": [{"type": "text", "text": _big_pad(4096) + "-----BEGIN OPENSSH PRIVATE KEY-----"}]}
    decision = await regex_engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result=result,
    )
    assert decision.deny


@pytest.mark.asyncio
async def test_clean_over_budget_payload_passes(regex_engine):
    payload = {"name": "read", "arguments": {"data": _big_pad(8192)}}
    decision = await regex_engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="read",
        params=payload,
        headers={},
    )
    assert not decision.deny


# ---------------------------------------------------------------------------
# InvariantEngine: per-route trace isolation
# ---------------------------------------------------------------------------


def test_loop_rule_isolated_per_route():
    engine = InvariantEngine([LoopRule(name="loop", threshold=3)], window=16)
    # Two routes interleave the same call; neither route alone reaches the
    # threshold, so nothing must fire.
    for _ in range(2):
        engine.record("http_get", {"url": "http://x"}, key="route-a")
        assert engine.evaluate(key="route-a") is None
        engine.record("http_get", {"url": "http://x"}, key="route-b")
        assert engine.evaluate(key="route-b") is None
    # Third identical call on route-a crosses the threshold there only.
    engine.record("http_get", {"url": "http://x"}, key="route-a")
    assert engine.evaluate(key="route-a") is not None
    assert engine.evaluate(key="route-b") is None


def test_toxic_flow_not_assembled_across_routes():
    rule = ToxicFlowRule(
        name="exfil",
        steps=[FlowStep(tool="inbox_read"), FlowStep(tool="email_send")],
        description="inbox -> external email",
    )
    engine = InvariantEngine([rule], window=16)
    engine.record("inbox_read", {}, key="route-a")
    engine.record("email_send", {"to": "x@y.com"}, key="route-b")
    assert engine.evaluate(key="route-a") is None
    assert engine.evaluate(key="route-b") is None
    # Same sequence within ONE route fires.
    engine.record("inbox_read", {}, key="route-c")
    engine.record("email_send", {"to": "x@y.com"}, key="route-c")
    assert engine.evaluate(key="route-c") is not None


def test_default_key_preserves_single_tenant_behaviour():
    engine = InvariantEngine([LoopRule(name="loop", threshold=2)], window=8)
    engine.record("t", {})
    assert engine.evaluate() is None
    engine.record("t", {})
    assert engine.evaluate() is not None


def test_max_traces_lru_eviction():
    engine = InvariantEngine([], window=4, max_traces=2)
    engine.record("t", {}, key="a")
    engine.record("t", {}, key="b")
    assert engine.snapshot(key="a")
    engine.record("t", {}, key="c")  # evicts "a" (LRU)
    assert engine.snapshot(key="a") == ()
    assert engine.snapshot(key="b")
    assert engine.snapshot(key="c")


def test_max_traces_clamped_to_minimum_one():
    engine = InvariantEngine([], window=4, max_traces=0)
    assert engine.max_traces == 1
    engine.record("t", {}, key="a")
    engine.record("t", {}, key="b")  # evicts "a" immediately
    assert engine.snapshot(key="a") == ()
    assert engine.snapshot(key="b")


def test_reset_scoped_to_key():
    engine = InvariantEngine([], window=4)
    engine.record("t", {}, key="a")
    engine.record("t", {}, key="b")
    engine.reset(key="a")
    assert engine.snapshot(key="a") == ()
    assert engine.snapshot(key="b")
    engine.reset()
    assert engine.snapshot(key="b") == ()


# ---------------------------------------------------------------------------
# Engine wiring: route_name becomes the trace key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_uses_route_scoped_traces(regex_engine):
    inv = InvariantEngine([LoopRule(name="loop", threshold=2)], window=8)
    from guardrails.config import GuardrailConfig

    engine = GuardrailEngine(
        GuardrailConfig(enable_promptguard=False),
        EngineComponents(
            request_scanners=[],
            invariant=inv,
        ),
    )

    async def call(route: str) -> bool:
        decision = await engine.check_request(
            method="tools/call",
            service_names=["svc"],
            tool_name="read",
            params={"name": "read", "arguments": {"path": "/x"}},
            headers={},
            route_name=route,
        )
        return decision.deny

    # threshold=2: the 2nd identical call on a route trips that route's loop
    # rule. With a GLOBAL trace the 2nd call overall would already trip it for
    # every route; with isolation each route gets its own counter.
    assert await call("route-a") is False
    assert await call("route-a") is True  # 2nd identical call on route-a
    # route-b starts from a clean window: first call must NOT fire even though
    # route-a already crossed the threshold.
    assert await call("route-b") is False
    assert await call("route-b") is True
    # Traces contain only their own route's calls.
    assert len(inv.snapshot(key="route-a")) == 2
    assert len(inv.snapshot(key="route-b")) == 2
