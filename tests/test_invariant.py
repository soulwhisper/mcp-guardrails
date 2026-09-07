"""Tests for the Invariant toxic-flow engine + rule pack loader."""

from __future__ import annotations

import os
import textwrap
import time
from pathlib import Path

import pytest

from guardrails.invariant import (
    FlowStep,
    InvariantEngine,
    LoopRule,
    RateLimitRule,
    ToxicFlowRule,
    TraceEntry,
)
from guardrails.rules import RulePack, load_rules
from guardrails.trace_store import MemoryTraceStore, RedisTraceStore, make_trace_store

# ---------------------------------------------------------------------------
# FlowStep matching
# ---------------------------------------------------------------------------


def test_flowstep_exact_tool_match():
    step = FlowStep(tool="inbox_read")
    assert step.matches("inbox_read", {})
    assert not step.matches("email_send", {})


def test_flowstep_regex_tool_match():
    import re

    step = FlowStep(tool=re.compile(r"(secret|vault)_read", re.IGNORECASE))
    assert step.matches("vault_read", {})
    assert step.matches("SECRET_READ", {})
    assert not step.matches("http_post", {})


def test_flowstep_arg_matcher_callable():
    step = FlowStep(
        tool="email_send",
        args={"to": lambda v: isinstance(v, str) and not v.endswith("@internal.local")},
    )
    assert step.matches("email_send", {"to": "evil@external.com"})
    assert not step.matches("email_send", {"to": "bob@internal.local"})


def test_flowstep_dotted_path_resolution():
    step = FlowStep(tool="x", args={"to.address": lambda v: v == "evil@x.com"})
    assert step.matches("x", {"to": {"address": "evil@x.com"}})
    assert not step.matches("x", {"to": {"address": "ok@x.com"}})
    # missing path -> None -> matcher decides
    assert not step.matches("x", {"to": {}})


def test_flowstep_list_index_path():
    step = FlowStep(tool="x", args={"recipients.0": lambda v: v == "a@x.com"})
    assert step.matches("x", {"recipients": ["a@x.com", "b@x.com"]})
    assert not step.matches("x", {"recipients": ["b@x.com"]})


# ---------------------------------------------------------------------------
# ToxicFlowRule ordered subsequence matching
# ---------------------------------------------------------------------------


def test_toxic_flow_matches_in_order():
    rule = ToxicFlowRule(
        name="exfil",
        steps=[
            FlowStep(tool="inbox_read"),
            FlowStep(tool="email_send", args={"to": lambda v: "@" in str(v)}),
        ],
    )
    assert (
        rule.match([TraceEntry("inbox_read", {}), TraceEntry("email_send", {"to": "x@y.com"})])
        == "exfil"
    )


def test_toxic_flow_allows_intervening_calls():
    rule = ToxicFlowRule(
        name="exfil",
        steps=[FlowStep(tool="a"), FlowStep(tool="b")],
    )
    trace = [TraceEntry("a"), TraceEntry("x"), TraceEntry("y"), TraceEntry("b")]
    assert rule.match(trace) == "exfil"


def test_toxic_flow_no_match_when_out_of_order():
    rule = ToxicFlowRule(
        name="exfil",
        steps=[FlowStep(tool="a"), FlowStep(tool="b")],
    )
    assert rule.match([TraceEntry("b"), TraceEntry("a")]) is None


def test_toxic_flow_no_match_when_partial():
    rule = ToxicFlowRule(
        name="exfil",
        steps=[FlowStep(tool="a"), FlowStep(tool="b")],
    )
    assert rule.match([TraceEntry("a"), TraceEntry("c")]) is None


def test_toxic_flow_arg_gate_prevents_match():
    rule = ToxicFlowRule(
        name="exfil",
        steps=[
            FlowStep(tool="inbox_read"),
            FlowStep(
                tool="email_send", args={"to": lambda v: "@" in str(v) and "external" in str(v)}
            ),
        ],
    )
    # email to internal -> second step's arg matcher fails -> no match
    trace = [TraceEntry("inbox_read"), TraceEntry("email_send", {"to": "bob@internal.local"})]
    assert rule.match(trace) is None


def test_toxic_flow_rejects_empty_steps():
    with pytest.raises(ValueError):
        ToxicFlowRule(name="x", steps=[])


# ---------------------------------------------------------------------------
# LoopRule
# ---------------------------------------------------------------------------


def test_loop_rule_fires_on_repetition():
    rule = LoopRule(name="loop", threshold=3)
    trace = [TraceEntry("t", {"a": 1})] * 3
    assert rule.match(trace) == "loop"


def test_loop_rule_distinct_args_do_not_fire():
    rule = LoopRule(name="loop", threshold=3)
    trace = [TraceEntry("t", {"a": 1}), TraceEntry("t", {"a": 2}), TraceEntry("t", {"a": 3})]
    assert rule.match(trace) is None


def test_loop_rule_threshold_validation():
    with pytest.raises(ValueError):
        LoopRule(name="x", threshold=1)


# ---------------------------------------------------------------------------
# InvariantEngine end-to-end
# ---------------------------------------------------------------------------


def test_engine_records_and_evaluates():
    engine = InvariantEngine(
        [
            ToxicFlowRule(
                name="exfil",
                steps=[FlowStep(tool="inbox_read"), FlowStep(tool="email_send")],
            )
        ],
        window=8,
    )
    assert engine.evaluate() is None
    engine.record("inbox_read", {})
    assert engine.evaluate() is None
    engine.record("email_send", {"to": "x@y.com"})
    result = engine.evaluate()
    assert result is not None
    assert result.outcome.value == "block"
    assert "exfil" in result.scanner


def test_engine_window_evicts_old_entries():
    engine = InvariantEngine(
        [
            ToxicFlowRule(
                name="exfil",
                steps=[FlowStep(tool="a"), FlowStep(tool="b")],
            )
        ],
        window=2,
    )
    engine.record("a")
    engine.record("x")  # evicts a
    engine.record("b")
    assert engine.evaluate() is None  # a was evicted, no match


def test_engine_evaluate_or_allow():
    engine = InvariantEngine([], window=4)
    res = engine.evaluate_or_allow()
    assert res.outcome.value == "allow"


def test_engine_reset():
    engine = InvariantEngine([ToxicFlowRule(name="x", steps=[FlowStep(tool="a")])])
    engine.record("a")
    assert engine.evaluate() is not None
    engine.reset()
    assert engine.evaluate() is None


# ---------------------------------------------------------------------------
# Rule pack loader
# ---------------------------------------------------------------------------


def test_load_default_pack():
    rules = load_rules()
    assert len(rules) >= 3
    names = {r.name for r in rules}
    assert "inbox-to-external-email" in names
    assert "denied-tool-retry-loop" in names


def test_load_from_module():
    rules = load_rules(module="guardrails.rules.default")
    assert any(r.name == "inbox-to-external-email" for r in rules)


def test_load_from_path(tmp_path):
    rules_file = tmp_path / "custom.py"
    rules_file.write_text(
        textwrap.dedent(
            """
            from guardrails.invariant import FlowStep, ToxicFlowRule
            RULES = [
                ToxicFlowRule(name="custom", steps=[FlowStep(tool="zzz")])
            ]
            """
        )
    )
    rules = load_rules(path=str(rules_file))
    assert len(rules) == 1
    assert rules[0].name == "custom"


def test_load_from_path_env(tmp_path, monkeypatch):
    rules_file = tmp_path / "env.py"
    rules_file.write_text(
        textwrap.dedent(
            """
            from guardrails.invariant import FlowStep, ToxicFlowRule
            RULES = [ToxicFlowRule(name="env-loaded", steps=[FlowStep(tool="a")])]
            """
        )
    )
    monkeypatch.setenv("INVARIANT_RULES_PATH", str(rules_file))
    rules = load_rules()
    assert rules[0].name == "env-loaded"


def _write_and_sync(path: Path, content: str) -> None:
    """Write text and force-flush to disk so a subsequent read sees it.

    ``Path.write_text`` uses a buffered write that may linger in the page
    cache on some CI filesystems (overlayfs with writeback). For the
    hot-reload test we need the on-disk bytes to be current before the next
    read, so we open with O_SYNC semantics: write, flush, fsync, close.
    """
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())


def test_rule_pack_reload(tmp_path, monkeypatch):
    rules_file = tmp_path / "pack.py"
    _write_and_sync(
        rules_file,
        "from guardrails.invariant import FlowStep, ToxicFlowRule\n"
        "RULES = [ToxicFlowRule(name='v1', steps=[FlowStep(tool='a')])]\n",
    )
    monkeypatch.setenv("INVARIANT_RULES_PATH", str(rules_file))
    pack = RulePack.from_env()
    assert pack.version == 0
    assert pack.rules[0].name == "v1"
    # rewrite the file and reload
    _write_and_sync(
        rules_file,
        "from guardrails.invariant import FlowStep, ToxicFlowRule\n"
        "RULES = [ToxicFlowRule(name='v2', steps=[FlowStep(tool='b')])]\n",
    )
    pack.reload()
    assert pack.version == 1
    assert pack.rules[0].name == "v2"


def test_invalid_rules_rejected():
    # A module without a RULES attribute is rejected with AttributeError.
    with pytest.raises(AttributeError):
        load_rules(module="guardrails.invariant")  # no RULES attr


def test_set_rules_swaps_atomically():
    engine = InvariantEngine([ToxicFlowRule(name="old", steps=[FlowStep(tool="a")])], window=8)
    engine.record("a")
    assert engine.evaluate() is not None  # old rule fires
    engine.set_rules([ToxicFlowRule(name="new", steps=[FlowStep(tool="b")])])
    # old rule no longer present; trace still has "a" but no rule matches it
    assert engine.evaluate() is None
    assert [r.name for r in engine.rules] == ["new"]


def test_set_rules_accepts_iterable():
    engine = InvariantEngine([], window=4)
    gen = (ToxicFlowRule(name=f"r{i}", steps=[FlowStep(tool="t")]) for i in range(3))
    engine.set_rules(gen)
    assert len(engine.rules) == 3


# ---------------------------------------------------------------------------
# TraceStore backends (R-1: shared invariant trace state)
# ---------------------------------------------------------------------------


def test_memory_store_append_read_order():
    store = MemoryTraceStore(window=8)
    store.append("k", TraceEntry("a"))
    store.append("k", TraceEntry("b"))
    assert [e.tool for e in store.read("k")] == ["a", "b"]
    assert store.read("missing") == []


def test_memory_store_prunes_to_window():
    store = MemoryTraceStore(window=2)
    for tool in ("a", "b", "c"):
        store.append("k", TraceEntry(tool))
    assert [e.tool for e in store.read("k")] == ["b", "c"]


def test_memory_store_max_traces_lru_eviction():
    store = MemoryTraceStore(window=4, max_traces=2)
    store.append("a", TraceEntry("t"))
    store.append("b", TraceEntry("t"))
    store.append("c", TraceEntry("t"))  # evicts "a"
    assert store.read("a") == []
    assert store.read("b") and store.read("c")


def test_memory_store_read_does_not_refresh_lru():
    # Evaluation is read-only: it must not keep an idle tenant trace alive.
    store = MemoryTraceStore(window=4, max_traces=2)
    store.append("a", TraceEntry("t"))
    store.append("b", TraceEntry("t"))
    assert store.read("a")  # read-only, no LRU refresh
    store.append("c", TraceEntry("t"))  # still evicts "a"
    assert store.read("a") == []


def test_memory_store_reset_scoped_and_all():
    store = MemoryTraceStore(window=4)
    store.append("a", TraceEntry("t"))
    store.append("b", TraceEntry("t"))
    store.reset("a")
    assert store.read("a") == []
    assert store.read("b")
    store.reset()
    assert store.read("b") == []


def test_engine_with_explicit_memory_store_behaves_like_default():
    rule = ToxicFlowRule(name="exfil", steps=[FlowStep(tool="a"), FlowStep(tool="b")])
    engine = InvariantEngine([rule], window=8, store=MemoryTraceStore(window=8))
    engine.record("a")
    assert engine.evaluate() is None
    engine.record("b")
    assert engine.evaluate() is not None


def test_make_trace_store_memory_backend():
    store = make_trace_store("memory", window=8, max_traces=4)
    assert isinstance(store, MemoryTraceStore)
    assert store.window == 8 and store.max_traces == 4


def test_make_trace_store_unknown_backend_raises():
    with pytest.raises(ValueError):
        make_trace_store("etcd")


def test_make_trace_store_redis_unreachable_fails_closed():
    # Fail-closed at startup: backend=redis with an unreachable server must
    # raise, never fall back to silently-weakened per-replica state.
    redis = pytest.importorskip("redis", reason="redis not installed (redis extra)")
    with pytest.raises(redis.exceptions.ConnectionError):
        make_trace_store("redis", "redis://127.0.0.1:1/0")


def _fake_redis_client():
    fakeredis = pytest.importorskip("fakeredis", reason="fakeredis not installed (dev extra)")
    return fakeredis.FakeStrictRedis()


def test_redis_store_append_read_roundtrip():
    client = _fake_redis_client()
    store = RedisTraceStore(client=client, window=8)
    before = time.monotonic()
    store.append("k", TraceEntry("inbox_read", {"id": 7}, fp="fp1", ts=time.monotonic()))
    (entry,) = store.read("k")
    assert entry.tool == "inbox_read"
    assert entry.args == {"id": 7}
    assert entry.fp == "fp1"
    # ts is mapped back into this process's monotonic frame (module docstring).
    assert 0.0 < entry.ts <= time.monotonic()
    assert entry.ts >= before - 1.0


def test_redis_store_prunes_to_window():
    store = RedisTraceStore(client=_fake_redis_client(), window=2)
    for tool in ("a", "b", "c"):
        store.append("k", TraceEntry(tool, ts=time.monotonic()))
    assert [e.tool for e in store.read("k")] == ["b", "c"]


def test_redis_store_max_traces_eviction():
    store = RedisTraceStore(client=_fake_redis_client(), window=4, max_traces=2)
    for key in ("a", "b", "c"):
        store.append(key, TraceEntry("t", ts=time.monotonic()))
    assert store.read("a") == []  # least-recently-appended evicted
    assert store.read("b") and store.read("c")


def test_redis_store_sets_key_ttl():
    client = _fake_redis_client()
    store = RedisTraceStore(client=client, window=4, ttl_s=3600.0)
    store.append("k", TraceEntry("t", ts=time.monotonic()))
    assert 0 < client.ttl("mcpg:trace:k") <= 3600


def test_redis_store_reset_scoped_and_all():
    client = _fake_redis_client()
    store = RedisTraceStore(client=client, window=4)
    store.append("a", TraceEntry("t", ts=time.monotonic()))
    store.append("b", TraceEntry("t", ts=time.monotonic()))
    store.reset("a")
    assert store.read("a") == []
    assert store.read("b")
    store.reset()
    assert store.read("b") == []


def test_redis_store_skips_undecodable_entries():
    client = _fake_redis_client()
    store = RedisTraceStore(client=client, window=8)
    client.rpush("mcpg:trace:k", "not-json")
    store.append("k", TraceEntry("t", ts=time.monotonic()))
    assert [e.tool for e in store.read("k")] == ["t"]


def test_engine_with_redis_store_detects_flow_and_rate():
    flow = ToxicFlowRule(name="exfil", steps=[FlowStep(tool="a"), FlowStep(tool="b")])
    engine = InvariantEngine([flow], window=8, store=RedisTraceStore(client=_fake_redis_client()))
    engine.record("a")
    assert engine.evaluate() is None
    engine.record("b")
    assert engine.evaluate() is not None

    # Time-windowed rules see correct entry ages through the ts mapping.
    rate = RateLimitRule(name="rl", tool="*", window_s=60.0, max_calls=2)
    engine = InvariantEngine([rate], window=8, store=RedisTraceStore(client=_fake_redis_client()))
    for _ in range(2):
        engine.record("noisy")
        assert engine.evaluate() is None
    engine.record("noisy")
    assert engine.evaluate() is not None
