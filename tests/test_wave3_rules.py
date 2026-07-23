"""Wave-3 rule-layer tests: RateLimitRule, AggregateRule, FlowStep.negate.

Covers the new time-windowed rules (which consume the ``TraceEntry.ts``
timestamp written by ``InvariantEngine.record``) and the negative-guard
step semantics on ToxicFlowRule (including the sticky-progress interplay).
"""

from __future__ import annotations

import time

import pytest

from guardrails.invariant import (
    AggregateRule,
    FlowStep,
    InvariantEngine,
    LoopRule,
    RateLimitRule,
    ToxicFlowRule,
    TraceEntry,
)


def _entry(tool: str, args: dict | None = None, age_s: float = 0.0) -> TraceEntry:
    """Build an entry ``age_s`` seconds in the past (monotonic clock)."""
    return TraceEntry(tool=tool, args=args or {}, ts=time.monotonic() - age_s)


# ---------------------------------------------------------------------------
# TraceEntry.ts
# ---------------------------------------------------------------------------


def test_record_stamps_monotonic_ts():
    engine = InvariantEngine([], window=8)
    before = time.monotonic()
    engine.record("tool_a", {"x": 1})
    after = time.monotonic()
    (entry,) = engine.snapshot()
    assert before <= entry.ts <= after


def test_entry_ts_defaults_to_zero_for_backcompat():
    entry = TraceEntry(tool="t")
    assert entry.ts == 0.0


# ---------------------------------------------------------------------------
# RateLimitRule
# ---------------------------------------------------------------------------


def test_rate_limit_fires_over_threshold_same_tool():
    rule = RateLimitRule(name="rl", tool="*", window_s=60.0, max_calls=3)
    trace = [_entry("http_post") for _ in range(4)]
    assert rule.match(trace) == "rl"


def test_rate_limit_counts_per_tool_name_not_pooled():
    # Wildcard matcher: each concrete tool keeps its own budget — 2+2 calls
    # must NOT trip a max_calls=3 limit.
    rule = RateLimitRule(name="rl", tool="*", window_s=60.0, max_calls=3)
    trace = [_entry("a"), _entry("b")] * 2
    assert rule.match(trace) is None


def test_rate_limit_matcher_scopes_counting():
    rule = RateLimitRule(name="rl", tool="http_.*", window_s=60.0, max_calls=2)
    # 3 http_post calls in-window -> fire even with other tools interleaved.
    trace = [
        _entry("fs_read"),
        _entry("http_post"),
        _entry("fs_read"),
        _entry("http_post"),
        _entry("http_post"),
    ]
    assert rule.match(trace) == "rl"
    # Only non-matching tools -> no fire.
    assert rule.match([_entry("fs_read") for _ in range(10)]) is None


def test_rate_limit_old_entries_slide_out():
    rule = RateLimitRule(name="rl", tool="*", window_s=30.0, max_calls=2)
    # Two calls 60s ago (outside the window) + one now -> under the limit.
    trace = [_entry("t", age_s=60.0), _entry("t", age_s=60.0), _entry("t")]
    assert rule.match(trace) is None
    # Three now -> fire.
    assert rule.match([_entry("t") for _ in range(3)]) == "rl"


def test_rate_limit_legacy_zero_ts_counts_as_now():
    rule = RateLimitRule(name="rl", tool="*", window_s=60.0, max_calls=2)
    trace = [TraceEntry(tool="t") for _ in range(3)]  # ts=0.0 legacy entries
    assert rule.match(trace) == "rl"


def test_rate_limit_negative_ts_slides_out_low_uptime_runner():
    # Regression: on fresh CI runners time.monotonic() < age_s, so
    # ``time.monotonic() - 60`` is negative. Only ts == 0.0 may count as
    # "now"; negative ts is "long ago" and must slide out of the window.
    rule = RateLimitRule(name="rl", tool="*", window_s=30.0, max_calls=2)
    trace = [
        TraceEntry(tool="t", ts=-3.858),
        TraceEntry(tool="t", ts=-3.857),
        TraceEntry(tool="t", ts=time.monotonic()),
    ]
    assert rule.match(trace) is None
    assert rule.match([_entry("t") for _ in range(3)]) == "rl"


def test_rate_limit_validation():
    with pytest.raises(ValueError):
        RateLimitRule(name="rl", max_calls=0)
    with pytest.raises(ValueError):
        RateLimitRule(name="rl", window_s=0)


def test_rate_limit_plugs_into_engine_via_record():
    engine = InvariantEngine(
        [RateLimitRule(name="rl", tool="*", window_s=60.0, max_calls=2)],
        window=16,
    )
    for _ in range(2):
        engine.record("spam_tool", {"n": 1})
        assert engine.evaluate() is None
    engine.record("spam_tool", {"n": 2})  # 3rd call inside the window
    result = engine.evaluate()
    assert result is not None
    assert result.scanner == "invariant:rl"


# ---------------------------------------------------------------------------
# AggregateRule
# ---------------------------------------------------------------------------


def test_aggregate_fires_when_sum_exceeds_budget():
    rule = AggregateRule(name="agg", field="size", max_total=100, window_s=300.0)
    trace = [_entry("fs_read", {"size": 60}), _entry("fs_read", {"size": 50})]
    assert rule.match(trace) == "agg"


def test_aggregate_under_budget_does_not_fire():
    rule = AggregateRule(name="agg", field="size", max_total=100, window_s=300.0)
    trace = [_entry("fs_read", {"size": 60}), _entry("fs_read", {"size": 40})]
    assert rule.match(trace) is None


def test_aggregate_window_slides_out_exactly():
    rule = AggregateRule(name="agg", field="size", max_total=100, window_s=30.0)
    # 90 in-window + 90 out-of-window: only the in-window 90 counts.
    trace = [
        _entry("fs_read", {"size": 90}, age_s=120.0),
        _entry("fs_read", {"size": 90}),
    ]
    assert rule.match(trace) is None
    # Two in-window contributions summing over the budget fire.
    trace.append(_entry("fs_read", {"size": 20}))
    assert rule.match(trace) == "agg"


def test_aggregate_negative_ts_slides_out_low_uptime_runner():
    # Regression: same low-uptime CI scenario as the rate-limit test —
    # a negative monotonic timestamp is "long ago", not "now".
    rule = AggregateRule(name="agg", field="size", max_total=100, window_s=30.0)
    trace = [
        TraceEntry(tool="fs_read", args={"size": 90}, ts=-63.82),
        TraceEntry(tool="fs_read", args={"size": 90}, ts=time.monotonic()),
    ]
    assert rule.match(trace) is None
    trace.append(_entry("fs_read", {"size": 20}))
    assert rule.match(trace) == "agg"


def test_aggregate_tool_matcher_and_missing_or_bad_values():
    rule = AggregateRule(name="agg", field="bytes", max_total=10, tool=r"http_.*", window_s=60.0)
    trace = [
        _entry("fs_read", {"bytes": 999}),  # tool doesn't match
        _entry("http_post", {}),  # missing field -> 0
        _entry("http_post", {"bytes": "oops"}),  # cast failure -> 0
    ]
    assert rule.match(trace) is None
    trace.append(_entry("http_post", {"bytes": 11}))
    assert rule.match(trace) == "agg"


def test_aggregate_dotted_path_and_custom_cast():
    rule = AggregateRule(
        name="agg",
        field="meta.recipients",
        max_total=5,
        window_s=60.0,
        cast=lambda v: len(v),
    )
    trace = [
        _entry("email_send", {"meta": {"recipients": ["a@x.io", "b@x.io"]}}),
        _entry("email_send", {"meta": {"recipients": ["c@x.io", "d@x.io"]}}),
        _entry("email_send", {"meta": {"recipients": ["e@x.io", "f@x.io"]}}),
    ]
    assert rule.match(trace) == "agg"


def test_aggregate_validation():
    with pytest.raises(ValueError):
        AggregateRule(name="agg", field="", max_total=1)
    with pytest.raises(ValueError):
        AggregateRule(name="agg", field="x", max_total=0)
    with pytest.raises(ValueError):
        AggregateRule(name="agg", field="x", max_total=1, window_s=0)


def test_aggregate_plugs_into_engine_via_record():
    engine = InvariantEngine(
        [AggregateRule(name="agg", field="size", max_total=100, window_s=300.0)],
        window=16,
    )
    engine.record("fs_read", {"size": 80})
    assert engine.evaluate() is None
    engine.record("fs_read", {"size": 30})
    result = engine.evaluate()
    assert result is not None
    assert result.scanner == "invariant:agg"


# ---------------------------------------------------------------------------
# FlowStep.negate
# ---------------------------------------------------------------------------


def _flow() -> ToxicFlowRule:
    return ToxicFlowRule(
        name="unapproved-send",
        steps=[
            FlowStep(tool="inbox_read"),
            FlowStep(tool="email_approve", negate=True),
            FlowStep(tool="email_send"),
        ],
    )


def test_negate_clean_sequence_still_fires():
    rule = _flow()
    trace = [_entry("inbox_read"), _entry("email_send")]
    assert rule.match(trace) == "unapproved-send"


def test_negate_intervening_step_voids_match():
    rule = _flow()
    trace = [_entry("inbox_read"), _entry("email_approve"), _entry("email_send")]
    assert rule.match(trace) is None


def test_negate_before_first_step_does_not_void():
    # The guard only arms AFTER inbox_read matched; an approval that came
    # before the read is irrelevant.
    rule = _flow()
    trace = [_entry("email_approve"), _entry("inbox_read"), _entry("email_send")]
    assert rule.match(trace) == "unapproved-send"


def test_negate_unrelated_calls_do_not_void():
    rule = _flow()
    trace = [
        _entry("inbox_read"),
        _entry("fs_read"),
        _entry("calendar_list"),
        _entry("email_send"),
    ]
    assert rule.match(trace) == "unapproved-send"


def test_negate_void_restarts_from_zero():
    # After a void, a fresh inbox_read can start a new attempt that fires.
    rule = _flow()
    trace = [
        _entry("inbox_read"),
        _entry("email_approve"),  # voids the first attempt
        _entry("email_send"),  # no live prefix -> no fire from this alone
        _entry("inbox_read"),
        _entry("email_send"),  # second attempt completes
    ]
    assert rule.match(trace) == "unapproved-send"


def test_negate_progress_reporting():
    # Partial prefix parks progress at the guard boundary (step index 1).
    rule = _flow()
    hit, progress = rule.match_from([_entry("inbox_read")], 0)
    assert hit is None and progress == 1
    # A guard hit returns progress 0 (the "void" signal).
    hit, progress = rule.match_from([_entry("email_approve")], 1)
    assert hit is None and progress == 0


def test_negate_clears_sticky_progress_in_engine():
    engine = InvariantEngine([_flow()], window=4, sticky_ttl_s=600.0)
    engine.record("inbox_read")
    assert engine.evaluate() is None
    # Sticky progress parked (prefix matched).
    assert engine._sticky  # parked prefix progress
    # The approval voids the flow: sticky progress must be dropped, and a
    # later email_send alone must not complete the flow.
    engine.record("email_approve")
    assert engine.evaluate() is None
    assert not engine._sticky
    engine.record("email_send")
    assert engine.evaluate() is None


def test_negate_sticky_flow_completes_across_window_eviction():
    # S-H4 sticky + negate: prefix slides out of a tiny window, but the
    # parked progress still lets the flow complete — unless negated.
    engine = InvariantEngine([_flow()], window=2, sticky_ttl_s=600.0)
    engine.record("inbox_read")
    engine.evaluate()
    engine.record("noise_a")  # pushes inbox_read toward eviction
    engine.evaluate()
    engine.record("email_send")  # inbox_read evicted; sticky prefix completes
    result = engine.evaluate()
    assert result is not None
    assert result.scanner == "invariant:unapproved-send"


def test_negate_step_in_dict_form():
    # Plain-dict step definitions (pack ergonomics) accept "negate".
    rule = ToxicFlowRule(
        name="r",
        steps=[
            {"tool": "a"},
            {"tool": "guard", "negate": True},
            {"tool": "b"},
        ],
    )
    assert rule.match([_entry("a"), _entry("guard"), _entry("b")]) is None
    assert rule.match([_entry("a"), _entry("b")]) == "r"


def test_negate_guard_with_args():
    # The guard can be arg-scoped: only an approval for the SAME thread voids.
    rule = ToxicFlowRule(
        name="r",
        steps=[
            FlowStep(tool="ticket_read"),
            FlowStep(tool="ticket_approve", args={"thread": "T-1"}, negate=True),
            FlowStep(tool="ticket_close"),
        ],
    )
    # Approval for a DIFFERENT thread does not void.
    assert (
        rule.match(
            [
                _entry("ticket_read"),
                _entry("ticket_approve", {"thread": "T-2"}),
                _entry("ticket_close"),
            ]
        )
        == "r"
    )
    # Approval for T-1 voids.
    assert (
        rule.match(
            [
                _entry("ticket_read"),
                _entry("ticket_approve", {"thread": "T-1"}),
                _entry("ticket_close"),
            ]
        )
        is None
    )


def test_existing_rules_unaffected_by_negate_change():
    # Regression: plain rules keep their exact subsequence semantics.
    rule = ToxicFlowRule(name="r", steps=[FlowStep(tool="a"), FlowStep(tool="b")])
    assert rule.match([_entry("a"), _entry("x"), _entry("b")]) == "r"
    loop = LoopRule(name="l", threshold=2)
    assert loop.match([_entry("a"), _entry("a")]) == "l"
