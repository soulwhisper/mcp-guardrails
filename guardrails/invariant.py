"""Invariant Guardrails — cross-call toxic-flow rule engine.

This module implements the *rule layer* of the guardrail: deterministic,
stateful pattern matching over the rolling window of MCP tool calls. It is the
complement to :mod:`guardrails.scanners` (the semantic content layer).

A rule is a :class:`ToxicFlowRule` describing an ordered *sequence* of tool
calls that, when observed within the sliding window, indicates a dangerous
agent behaviour — for example ``inbox_read`` followed by ``email_send`` to an
external recipient (data exfiltration via an email tool).

The engine is deliberately dependency-free and synchronous; rule evaluation is
microsecond-order, so no ``to_thread`` wrapping is required.
"""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Union

from .models import ScanResult

# A step matcher for a tool name: exact string, regex (compiled or str), or
# callable accepting the tool name and returning bool.
ToolMatcher = Union[str, "re.Pattern[str]", Callable[[str], bool]]

# A value matcher for an argument field: callable, regex (compiled or str), or
# a literal compared with ==.
ValueMatcher = Union[Callable[[Any], bool], "re.Pattern[str]", str, int, float, bool]


def _compile_tool(matcher: ToolMatcher) -> Callable[[str], bool]:
    if callable(matcher):
        return matcher
    if isinstance(matcher, re.Pattern):
        return lambda name: bool(matcher.search(name))
    if isinstance(matcher, str):
        # Treat strings starting with ^ or containing regex meta as regex,
        # otherwise exact match. This keeps the common case literal & obvious.
        if any(c in matcher for c in "^$.*+?[]()|") and matcher not in ("*",):
            pat = re.compile(matcher)
            return lambda name: bool(pat.search(name))
        return lambda name: name == matcher
    raise TypeError(f"Unsupported ToolMatcher: {matcher!r}")


def _compile_value(matcher: ValueMatcher) -> Callable[[Any], bool]:
    if callable(matcher):
        return matcher
    if isinstance(matcher, re.Pattern):
        return lambda v: isinstance(v, str) and bool(matcher.search(v))
    if isinstance(matcher, str):
        # Heuristic: strings that look like regex (contain meta chars) compile,
        # otherwise literal equality. Use re.fullmatch for string fields so a
        # rule "external" matches only the literal value "external".
        if any(c in matcher for c in "^$.*+?[]()|\\"):
            pat = re.compile(matcher)
            return lambda v: isinstance(v, str) and bool(pat.search(v))
        return lambda v: v == matcher
    return lambda v: v == matcher


@dataclass
class FlowStep:
    """One step in a toxic-flow sequence.

    ``tool``     — matcher for the MCP tool name (params["name"]).
    ``args``     — optional mapping of argument-path -> value matcher. Paths
                   use dot notation for nested fields, e.g. "to.address".
    ``args_any`` — if True, the step matches any args (only the tool name is
                   checked). Defaults to False; when ``args`` is empty the step
                   also matches any args.
    """

    tool: ToolMatcher
    args: Mapping[str, ValueMatcher] = field(default_factory=dict)
    args_any: bool = False
    _tool_fn: Callable[[str], bool] = field(init=False, repr=False)
    _arg_fns: tuple[tuple[str, Callable[[Any], bool]], ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._tool_fn = _compile_tool(self.tool)
        self._arg_fns = tuple((p, _compile_value(m)) for p, m in self.args.items())

    def matches(self, tool_name: str, args: Mapping[str, Any]) -> bool:
        if not self._tool_fn(tool_name):
            return False
        if not self._arg_fns:
            return True  # no arg constraints -> any args match
        for path, fn in self._arg_fns:
            value = _resolve_path(args, path)
            if not fn(value):
                return False
        return True


def _resolve_path(data: Any, path: str) -> Any:
    """Resolve a dotted path against nested dict/list structures.

    Returns ``None`` if any segment is missing. Supports integer list indices
    (e.g. "recipients.0.address").
    """
    current: Any = data
    for segment in path.split("."):
        if current is None:
            return None
        if isinstance(current, Mapping):
            current = current.get(segment)
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            try:
                current = current[int(segment)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


@dataclass
class ToxicFlowRule:
    """A toxic-flow rule: an ordered subsequence of tool calls.

    The rule fires when *all* steps match in order within the current trace
    window (steps need not be contiguous — intervening calls are allowed, which
    models real agent behaviour where a dangerous pattern is spread across
    several intermediate steps).
    """

    name: str
    steps: Sequence[FlowStep]
    description: str = ""

    def __post_init__(self) -> None:
        if not self.steps:
            raise ValueError(f"ToxicFlowRule {self.name!r} must have >=1 step")
        # Normalise: allow plain dicts in step definitions for ergonomics.
        normalised = []
        for s in self.steps:
            if isinstance(s, FlowStep):
                normalised.append(s)
            elif isinstance(s, Mapping):
                normalised.append(FlowStep(**s))
            else:
                raise TypeError(f"Unsupported step type: {type(s)!r}")
        self.steps = normalised

    def match(self, trace: Sequence[TraceEntry]) -> str | None:
        """Return a reason string if the rule matches the trace, else None.

        Implements ordered subsequence matching: greedily advance through the
        steps, consuming trace entries left-to-right.
        """
        if not self.steps:
            return None
        step_idx = 0
        for entry in trace:
            step = self.steps[step_idx]
            if step.matches(entry.tool, entry.args):
                step_idx += 1
                if step_idx == len(self.steps):
                    return self.name
        return None

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"ToxicFlowRule(name={self.name!r}, steps={len(self.steps)})"


@dataclass
class TraceEntry:
    """One entry in the rolling tool-call trace."""

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable identity for loop detection — tool + sorted args JSON.

        Two calls with the same tool and arguments share a fingerprint, which
        is what distinguishes a genuine retry loop from a parameterised search
        (where args differ each call).
        """
        return f"{self.tool}:{json.dumps(self.args, sort_keys=True, default=str)}"


@dataclass
class LoopRule:
    """Rule that fires when the same call fingerprint repeats ``threshold``
    times within the window.

    Models the prompt-injection "retry loop" signature: a compromised agent
    hammering the same denied tool over and over hoping a guardrail hiccups.
    """

    name: str
    threshold: int = 3
    description: str = ""

    def __post_init__(self) -> None:
        if self.threshold < 2:
            raise ValueError("LoopRule threshold must be >= 2")

    def match(self, trace: Sequence[TraceEntry]) -> str | None:
        counts: dict[str, int] = {}
        for entry in trace:
            fp = entry.fingerprint()
            counts[fp] = counts.get(fp, 0) + 1
            if counts[fp] >= self.threshold:
                return self.name
        return None

    def __repr__(self) -> str:  # pragma: no cover
        return f"LoopRule(name={self.name!r}, threshold={self.threshold})"


# Any object exposing ``match(trace) -> Optional[str]`` and a ``name``.
Rule = ToxicFlowRule | LoopRule


class InvariantEngine:
    """Cross-call toxic-flow matcher with a bounded sliding window.

    The window (``maxlen``) should be large enough to span a typical agent
    tool-use chain (the design default of 64 covers most homelab flows) but
    bounded to cap memory and rule-evaluation cost.
    """

    def __init__(self, rules: Iterable[ToxicFlowRule], window: int = 64):
        self._rules: list[ToxicFlowRule] = list(rules)
        self._trace: deque[TraceEntry] = deque(maxlen=window)
        self._window = window

    @property
    def rules(self) -> tuple[ToxicFlowRule, ...]:
        return tuple(self._rules)

    @property
    def window(self) -> int:
        return self._window

    def set_rules(self, rules: Iterable[ToxicFlowRule]) -> None:
        """Atomically swap the active rule list.

        Replaces the ``self._rules`` reference wholesale rather than mutating
        it in place, so an in-flight :meth:`evaluate` (which captured the old
        list reference when building its iterator) is unaffected. Used by the
        engine's hot-reload path (SIGHUP).
        """
        self._rules = list(rules)

    def reset(self) -> None:
        self._trace.clear()

    def record(self, tool: str, args: Mapping[str, Any] | None = None) -> None:
        """Append a tool call to the trace.

        Called by the engine on every ``tools/call`` request *before* rule
        evaluation, so the current call participates in matching.
        """
        self._trace.append(TraceEntry(tool=tool, args=dict(args or {})))

    def evaluate(self) -> ScanResult | None:
        """Run all rules against the current trace.

        Returns the first matching rule as a BLOCK ``ScanResult``, or ``None``
        if no rule fires. First-match wins; rule order in the config therefore
        expresses priority.
        """
        snapshot = list(self._trace)
        for rule in self._rules:
            hit = rule.match(snapshot)
            if hit is not None:
                return ScanResult.block(
                    scanner=f"invariant:{hit}",
                    reason=rule.description or hit,
                )
        return None

    def evaluate_or_allow(self) -> ScanResult:
        """Convenience: evaluate, returning ALLOW if nothing fires."""
        return self.evaluate() or ScanResult.allow("invariant")

    def snapshot(self) -> tuple[TraceEntry, ...]:
        """Return an immutable copy of the current trace (for tests/audit)."""
        return tuple(self._trace)
