"""Tests for ``scripts/guardrail_ctl.py`` (rules lint + decision replay)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import guardrail_ctl

# ---------------------------------------------------------------------------
# rules lint
# ---------------------------------------------------------------------------


def test_rules_lint_default_pack_ok(capsys):
    rc = guardrail_ctl.main(["rules", "lint", "--module", "guardrails.rules.default"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "loaded 5 rule(s)" in out
    assert "pack is valid" in out
    # The dry-run must show each default rule firing on its signature trace.
    assert "trace 'inbox-to-external-email': inbox-to-external-email" in out
    assert "trace 'retry-loop': denied-tool-retry-loop" in out


def test_rules_lint_example_policy_ok(tmp_path, capsys):
    policy = Path(__file__).resolve().parent.parent / "examples" / "rules.policy"
    if not policy.exists():  # pragma: no cover - repo layout guard
        pytest.skip("examples/rules.policy missing")
    rc = guardrail_ctl.main(["rules", "lint", "--path", str(policy)])
    assert rc == 0
    assert "pack is valid" in capsys.readouterr().out


def test_rules_lint_missing_file_fails(capsys):
    rc = guardrail_ctl.main(["rules", "lint", "--path", "/nonexistent/rules.policy"])
    assert rc == 1
    assert "failed to load" in capsys.readouterr().err


def test_rules_lint_invalid_pack_exit_nonzero(tmp_path, capsys):
    pack = tmp_path / "bad.policy"
    pack.write_text(
        "from guardrails.invariant import ToxicFlowRule, LoopRule\n"
        "RULES = [\n"
        # No positive steps -> can never fire.
        "  ToxicFlowRule(name='neg-only', steps=[{'tool': 'a', 'negate': True},"
        " {'tool': 'b', 'negate': True}]),\n"
        # Leading negate guard -> authoring mistake.
        "  ToxicFlowRule(name='lead-neg', steps=[{'tool': 'g', 'negate': True},"
        " {'tool': 'a'}, {'tool': 'b'}]),\n"
        # Duplicate name.
        "  LoopRule(name='lead-neg', threshold=3),\n"
        "]\n"
    )
    rc = guardrail_ctl.main(["rules", "lint", "--path", str(pack)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "no positive steps" in err
    assert "leading negate" in err or "step[0] is a negate guard" in err
    assert "duplicate rule name" in err


def test_rules_lint_threshold_validation(tmp_path, capsys):
    # Bypass the dataclass __post_init__ guard by monkey-patching after
    # construction: the linter must catch illegal thresholds on hand-rolled
    # or tampered rule objects.
    pack = tmp_path / "thr.policy"
    pack.write_text(
        "from guardrails.invariant import LoopRule\n"
        "r = LoopRule(name='loop', threshold=2)\n"
        "object.__setattr__(r, 'threshold', 1)\n"
        "RULES = [r]\n"
    )
    rc = guardrail_ctl.main(["rules", "lint", "--path", str(pack)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "threshold" in err


# ---------------------------------------------------------------------------
# decision replay
# ---------------------------------------------------------------------------


def _write_audit(path: Path) -> None:
    records = [
        {
            "ts": 1,
            "ts_ms": 1000.0,
            "phase": "request",
            "method": "tools/call",
            "tool": "fs_read",
            "outcome": "allow",
            "reason": "",
            "ref": "aaaa1111",
            "exchange_id": "ex1",
            "scanners": [{"scanner": "regex", "outcome": "allow", "reason": "", "score": 0.0}],
        },
        {
            "ts": 1,
            "ts_ms": 1010.0,
            "phase": "response",
            "method": "tools/call",
            "tool": "",
            "outcome": "deny",
            "reason": "regex:block:aws",
            "ref": "bbbb2222",
            "exchange_id": "ex1",
            "scanners": [{"scanner": "regex", "outcome": "block", "reason": "aws", "score": 1.0}],
        },
        {
            "ts": 2,
            "ts_ms": 2000.0,
            "phase": "request",
            "method": "tools/call",
            "tool": "email_send",
            "outcome": "deny",
            "reason": "invariant:rule-x:block",
            "ref": "cccc3333",
            "exchange_id": "ex2",
            "scanners": [
                {"scanner": "invariant:rule-x", "outcome": "block", "reason": "", "score": 0.0}
            ],
        },
        {"event": "rules_reload", "ok": True},
    ]
    lines = [json.dumps(r) for r in records]
    lines.append("this is not json")
    path.write_text("\n".join(lines) + "\n")


def test_decision_replay_summary(tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    _write_audit(audit)
    rc = guardrail_ctl.main(["decision", "replay", str(audit)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "3 decision record(s)" in out
    assert "1 malformed skipped" in out
    assert "deny" in out and "allow" in out
    assert "invariant:rule-x" in out
    assert "request+response pairs: 1" in out
    assert "request-only          : 1" in out


def test_decision_replay_deny_detail(tmp_path, capsys):
    audit = tmp_path / "audit.jsonl"
    _write_audit(audit)
    rc = guardrail_ctl.main(["decision", "replay", str(audit), "--deny-detail"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ref=bbbb2222" in out
    assert "ref=cccc3333" in out
    assert "aaaa1111" not in out.split("deny / human_review detail:")[-1]


def test_decision_replay_empty_fails(tmp_path, capsys):
    audit = tmp_path / "empty.jsonl"
    audit.write_text('{"event": "rules_reload"}\n')
    rc = guardrail_ctl.main(["decision", "replay", str(audit)])
    assert rc == 1
    assert "no decision records" in capsys.readouterr().err


def test_decision_replay_missing_file_fails(capsys):
    rc = guardrail_ctl.main(["decision", "replay", "/nonexistent/audit.jsonl"])
    assert rc == 1
    assert "cannot read" in capsys.readouterr().err
