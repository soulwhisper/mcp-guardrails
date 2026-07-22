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
import time
from collections import OrderedDict, deque
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
        hit, _progress = self.match_from(trace, 0)
        return hit

    def match_from(
        self, trace: Sequence[TraceEntry], start_step: int = 0
    ) -> tuple[str | None, int]:
        """Match from ``start_step``, returning ``(hit, progress)``.

        ``progress`` is the number of rule steps matched so far in ORDER —
        ``start_step`` plus however many further steps this trace advanced.
        A ``(None, p)`` result with ``p > start_step`` means a PREFIX of the
        flow matched; the engine keeps that progress in its sticky map so a
        flow whose early steps slide out of the rolling window is not lost
        (S-H4). A full match returns ``(self.name, len(self.steps))``.
        """
        if not self.steps or start_step >= len(self.steps):
            return None, start_step
        step_idx = start_step
        for entry in trace:
            step = self.steps[step_idx]
            if step.matches(entry.tool, entry.args):
                step_idx += 1
                if step_idx == len(self.steps):
                    return self.name, step_idx
        return None, step_idx

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"ToxicFlowRule(name={self.name!r}, steps={len(self.steps)})"


def _truncate_args(args: Mapping[str, Any], max_bytes: int) -> Mapping[str, Any]:
    """Bound the stored copy of a call's arguments (S-M4).

    The Invariant window keeps a copy of every call's args; an agent passing
    a multi-MB argument would otherwise let a single call bloat the rolling
    window. When the serialised args exceed ``max_bytes`` the STRUCTURE is
    preserved and long string values are truncated (with an explicit marker)
    so ``FlowStep`` arg matchers still resolve field paths and can match on
    the retained prefix. ``max_bytes <= 0`` disables truncation.
    """
    if max_bytes <= 0:
        return dict(args)
    try:
        if len(json.dumps(args, sort_keys=True, default=str)) <= max_bytes:
            return dict(args)
    except (TypeError, ValueError):
        return dict(args)

    strings = sum(1 for _ in _iter_strings(args))
    per_string = max(64, max_bytes // max(1, strings))

    def _shrink(value: Any) -> Any:
        if isinstance(value, str):
            if len(value) <= per_string:
                return value
            return value[:per_string] + "…[truncated]"
        if isinstance(value, Mapping):
            return {k: _shrink(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_shrink(v) for v in value]
        return value

    return _shrink(dict(args))


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


@dataclass
class TraceEntry:
    """One entry in the rolling tool-call trace.

    ``args`` may be a size-bounded copy (see :func:`_truncate_args`); the
    fingerprint is computed from the FULL original args at record time and
    stored in ``fp`` so loop detection is unaffected by truncation.
    """

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)
    fp: str = ""

    def fingerprint(self) -> str:
        """Stable identity for loop detection — tool + sorted args JSON.

        Two calls with the same tool and arguments share a fingerprint, which
        is what distinguishes a genuine retry loop from a parameterised search
        (where args differ each call).
        """
        if self.fp:
            return self.fp
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
    tool-use chain (the design default of 256 covers long multi-step plans;
    memory bound: window x ``args_max_bytes`` x ``max_traces``) but bounded to
    cap memory and rule-evaluation cost. Partial (prefix) ToxicFlowRule
    matches are parked in a TTL-bounded *sticky* map so a flow whose early
    steps slide out of the window still completes (S-H4).

    Traces are isolated per *trace key* (the engine passes the route name /
    first service name): one compromised or noisy tenant cannot poison the
    sliding window another tenant's rules are evaluated against, and
    interleaved calls from different agents can no longer assemble a
    cross-tenant toxic flow or trip a loop rule. The number of distinct keys
    is bounded by ``max_traces`` with LRU eviction, so a key-flooding client
    cannot grow memory without limit.
    """

    def __init__(
        self,
        rules: Iterable[ToxicFlowRule],
        window: int = 256,
        max_traces: int = 1024,
        args_max_bytes: int = 4 * 1024,
        sticky_ttl_s: float = 600.0,
    ):
        self._rules: list[ToxicFlowRule] = list(rules)
        self._traces: OrderedDict[str, deque[TraceEntry]] = OrderedDict()
        self._window = window
        self._max_traces = max(1, max_traces)
        self._args_max_bytes = args_max_bytes
        self._sticky_ttl_s = max(0.0, sticky_ttl_s)
        # S-H4 sticky partial-match progress: ``(trace_key, rule_name)`` ->
        # ``(steps_matched, last_updated_epoch)``. When a ToxicFlowRule matches
        # a PREFIX of its steps the progress is parked here (TTL-bounded) so
        # the flow survives its early steps sliding out of the rolling window.
        # Bounded LRU like ``_traces`` (same ``max_traces`` cap), so a
        # key-flooding client cannot grow it without limit.
        self._sticky: OrderedDict[tuple[str, str], tuple[int, float]] = OrderedDict()

    @property
    def rules(self) -> tuple[ToxicFlowRule, ...]:
        return tuple(self._rules)

    @property
    def window(self) -> int:
        return self._window

    @property
    def max_traces(self) -> int:
        return self._max_traces

    def _get_trace(self, key: str) -> deque[TraceEntry]:
        """Return the deque for ``key``, creating / LRU-refreshing it."""
        trace = self._traces.get(key)
        if trace is None:
            if len(self._traces) >= self._max_traces:
                # Evict the least-recently-used tenant trace.
                self._traces.popitem(last=False)
            trace = deque(maxlen=self._window)
            self._traces[key] = trace
        else:
            self._traces.move_to_end(key)
        return trace

    def set_rules(self, rules: Iterable[ToxicFlowRule]) -> None:
        """Atomically swap the active rule list.

        Replaces the ``self._rules`` reference wholesale rather than mutating
        it in place, so an in-flight :meth:`evaluate` (which captured the old
        list reference when building its iterator) is unaffected. Used by the
        engine's hot-reload path (SIGHUP).
        """
        self._rules = list(rules)

    def reset(self, key: str | None = None) -> None:
        """Clear one tenant's trace (and sticky progress), or all when None."""
        if key is None:
            self._traces.clear()
            self._sticky.clear()
        else:
            self._traces.pop(key, None)
            for skey in [k for k in self._sticky if k[0] == key]:
                self._sticky.pop(skey, None)

    def _sticky_progress(self, key: str, rule_name: str, now: float) -> int:
        """Return the fresh sticky step progress for ``(key, rule_name)``.

        Entries older than ``sticky_ttl_s`` are dropped (a flow spread over
        longer than the TTL is treated as abandoned).
        """
        skey = (key, rule_name)
        entry = self._sticky.get(skey)
        if entry is None:
            return 0
        progress, ts = entry
        if now - ts > self._sticky_ttl_s:
            self._sticky.pop(skey, None)
            return 0
        self._sticky.move_to_end(skey)
        return progress

    def _set_sticky(self, key: str, rule_name: str, progress: int, now: float) -> None:
        """Park / refresh partial-match progress, bounded LRU."""
        skey = (key, rule_name)
        if progress <= 0:
            self._sticky.pop(skey, None)
            return
        if skey not in self._sticky and len(self._sticky) >= self._max_traces:
            self._sticky.popitem(last=False)
        self._sticky[skey] = (progress, now)
        self._sticky.move_to_end(skey)

    def record(
        self,
        tool: str,
        args: Mapping[str, Any] | None = None,
        *,
        key: str = "",
    ) -> None:
        """Append a tool call to the trace for ``key``.

        Called by the engine on every ``tools/call`` request *before* rule
        evaluation, so the current call participates in matching.

        The stored args copy is size-bounded (``args_max_bytes``, S-M4) so a
        giant argument cannot bloat the rolling window; the loop fingerprint
        is computed from the FULL args before truncation, so loop detection
        is unaffected, and structure-preserving truncation keeps dotted-path
        arg matchers working on the retained value prefixes.
        """
        full_args = dict(args or {})
        fp = f"{tool}:{json.dumps(full_args, sort_keys=True, default=str)}"
        stored = _truncate_args(full_args, self._args_max_bytes)
        self._get_trace(key).append(TraceEntry(tool=tool, args=stored, fp=fp))

    def evaluate(self, *, key: str = "") -> ScanResult | None:
        """Run all rules against the current trace for ``key``.

        Returns the first matching rule as a BLOCK ``ScanResult``, or ``None``
        if no rule fires. First-match wins; rule order in the config therefore
        expresses priority.
        """
        trace = self._traces.get(key)
        snapshot = list(trace) if trace is not None else []
        now = time.monotonic()
        for rule in self._rules:
            if isinstance(rule, ToxicFlowRule):
                # Sticky prefix progress (S-H4): resume from parked progress
                # so early flow steps that slid out of the window still count.
                start = self._sticky_progress(key, rule.name, now)
                hit, progress = rule.match_from(snapshot, start)
                if hit is not None:
                    self._sticky.pop((key, rule.name), None)
                    return ScanResult.block(
                        scanner=f"invariant:{hit}",
                        reason=rule.description or hit,
                    )
                if progress > start:
                    # Only new advancement refreshes the TTL — parked progress
                    # that is not extended ages out per sticky_ttl_s.
                    self._set_sticky(key, rule.name, progress, now)
                continue
            hit = rule.match(snapshot)
            if hit is not None:
                return ScanResult.block(
                    scanner=f"invariant:{hit}",
                    reason=rule.description or hit,
                )
        return None

    def evaluate_or_allow(self, *, key: str = "") -> ScanResult:
        """Convenience: evaluate, returning ALLOW if nothing fires."""
        return self.evaluate(key=key) or ScanResult.allow("invariant")

    def snapshot(self, *, key: str = "") -> tuple[TraceEntry, ...]:
        """Return an immutable copy of a trace (for tests/audit)."""
        trace = self._traces.get(key)
        return tuple(trace) if trace is not None else ()
