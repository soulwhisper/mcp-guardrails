"""Tests for the Invariant toxic-flow engine + rule pack loader."""

from __future__ import annotations

import textwrap

import pytest

from guardrails.invariant import (
    FlowStep,
    InvariantEngine,
    LoopRule,
    ToxicFlowRule,
    TraceEntry,
)
from guardrails.rules import RulePack, load_rules

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


def test_rule_pack_reload(tmp_path, monkeypatch):
    rules_file = tmp_path / "pack.py"
    rules_file.write_text(
        "from guardrails.invariant import FlowStep, ToxicFlowRule\n"
        "RULES = [ToxicFlowRule(name='v1', steps=[FlowStep(tool='a')])]\n"
    )
    monkeypatch.setenv("INVARIANT_RULES_PATH", str(rules_file))
    pack = RulePack.from_env()
    assert pack.version == 0
    assert pack.rules[0].name == "v1"
    # rewrite the file and reload
    rules_file.write_text(
        "from guardrails.invariant import FlowStep, ToxicFlowRule\n"
        "RULES = [ToxicFlowRule(name='v2', steps=[FlowStep(tool='b')])]\n"
    )
    pack.reload()
    assert pack.version == 1
    assert pack.rules[0].name == "v2"


def test_invalid_rules_rejected():
    # A module without a RULES attribute is rejected with AttributeError.
    with pytest.raises(AttributeError):
        load_rules(module="guardrails.invariant")  # no RULES attr
