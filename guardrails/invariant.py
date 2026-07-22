"""Invariant Guardrails — cross-call toxic-flow rule engine.

This module implements the *rule layer* of the guardrail: deterministic,
stateful pattern matching over the rolling window of MCP tool calls. It is the
complement to :mod:`guardrails.scanners` (the semantic content layer).

A rule is a :class:`ToxicFlowRule` describing an ordered *sequence* of tool
calls that, when observed within the sliding window, indicates a dangerous
agent behaviour — for example ``inbox_read`` followed by ``email_send`` to an
external recipient (data exfiltration via an email tool). Companion rule
shapes cover the non-sequential signatures: :class:`LoopRule` (identical-call
retry storms), :class:`RateLimitRule` (per-tool sliding time-window call
rate) and :class:`AggregateRule` (sliding time-window cumulative budget over
an argument field). ``FlowStep(negate=True)`` adds negative guards to
sequences ("A then C with no B between").

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
    ``negate``   — if True, the step is a *negative guard* instead of a
                   positive step: it never advances the sequence, but while
                   it is armed (between the previously matched positive step
                   and the next positive step) any trace entry matching it
                   VOIDS the whole match in progress. Use this for
                   "A then C, with no B in between" patterns (e.g.
                   inbox_read -> email_send with no approval call between).
                   Negate steps at the start of a rule guard from the
                   beginning of the window; trailing negate steps are armed
                   until the rule completes (which it does as soon as no
                   positive steps remain).
    """

    tool: ToolMatcher
    args: Mapping[str, ValueMatcher] = field(default_factory=dict)
    args_any: bool = False
    negate: bool = False
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

        Negate guards (``FlowStep(negate=True)``): while armed — between the
        previously matched positive step and the next positive step — an
        entry matching a negate step VOIDS the progress made so far: matching
        restarts from step 0 with the remaining trace (so a later clean
        sequence can still fire in the same pass). If nothing re-matches,
        ``(None, 0)`` results; because 0 < ``start_step`` the engine then
        also drops any parked sticky progress for this rule — a voided flow
        cannot resume from the negated prefix.
        """
        if not self.steps or start_step >= len(self.steps):
            return None, start_step
        step_idx = start_step
        for entry in trace:
            # Resolve the next positive step, collecting the negate guards
            # armed between the last matched positive step and it.
            pos = step_idx
            while pos < len(self.steps) and self.steps[pos].negate:
                pos += 1
            # Negate guards: a hit voids the progress made so far and
            # matching restarts from step 0 with the entries that follow.
            if any(
                self.steps[guard].matches(entry.tool, entry.args) for guard in range(step_idx, pos)
            ):
                step_idx = 0
                continue
            if pos >= len(self.steps):
                # Only trailing negate guards remain and none fired on this
                # entry: the flow completed when the last positive step
                # matched.
                return self.name, len(self.steps)
            step = self.steps[pos]
            if step.matches(entry.tool, entry.args):
                step_idx = pos + 1
                # Completion: no positive steps remain (trailing negate
                # guards stay armed only until this point).
                nxt = step_idx
                while nxt < len(self.steps) and self.steps[nxt].negate:
                    nxt += 1
                if nxt >= len(self.steps):
                    return self.name, len(self.steps)
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

    ``ts`` is the :func:`time.monotonic` timestamp of when the call was
    recorded, written by :meth:`InvariantEngine.record`. Time-windowed rules
    (:class:`RateLimitRule`, :class:`AggregateRule`) consume it. It defaults
    to ``0.0`` for backwards compatibility with hand-constructed entries;
    windowed rules treat a ``0.0`` timestamp as "now" (legacy entries count
    as inside the current window).
    """

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)
    fp: str = ""
    ts: float = 0.0

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


def _window_cutoff(now: float, window_s: float) -> float:
    return now - max(0.0, window_s)


def _entry_ts(entry: TraceEntry, now: float) -> float:
    """Effective timestamp: legacy entries (``ts == 0.0``) count as "now".

    Hand-constructed entries predate the ``ts`` field; treating them as
    current keeps old tests/packs meaningful under time-windowed rules.
    """
    return entry.ts if entry.ts > 0.0 else now


@dataclass
class RateLimitRule:
    """Sliding time-window rate limit, counted per tool name.

    Fires when, within the trace for one key, any single tool whose name
    matches ``tool`` is called more than ``max_calls`` times inside the last
    ``window_s`` seconds (by ``TraceEntry.ts``). Counting is grouped per
    concrete tool name, so with the wildcard matcher (``"*"`` — the only
    matcher treated as match-everything here) each tool gets its own budget
    rather than all tools sharing one.

    Unlike :class:`LoopRule` (identical args) this models volumetric abuse
    with *varying* args — e.g. a compromised agent enumerating records or
    spraying messages as fast as the gateway allows. Evaluation recomputes
    the window from entry timestamps on every call, so entries sliding out
    of the time window stop counting immediately (no persistent ledger).
    """

    name: str
    tool: ToolMatcher = "*"
    window_s: float = 60.0
    max_calls: int = 30
    description: str = ""
    _tool_fn: Callable[[str], bool] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_calls < 1:
            raise ValueError("RateLimitRule max_calls must be >= 1")
        if self.window_s <= 0:
            raise ValueError("RateLimitRule window_s must be > 0")
        if self.tool == "*":
            self._tool_fn = lambda _name: True
        else:
            self._tool_fn = _compile_tool(self.tool)

    def match(self, trace: Sequence[TraceEntry]) -> str | None:
        now = time.monotonic()
        cutoff = _window_cutoff(now, self.window_s)
        counts: dict[str, int] = {}
        for entry in trace:
            if not self._tool_fn(entry.tool):
                continue
            if _entry_ts(entry, now) < cutoff:
                continue
            counts[entry.tool] = counts.get(entry.tool, 0) + 1
            if counts[entry.tool] > self.max_calls:
                return self.name
        return None

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"RateLimitRule(name={self.name!r}, max_calls={self.max_calls}, "
            f"window_s={self.window_s})"
        )


@dataclass
class AggregateRule:
    """Sliding time-window SUM of a numeric argument field, per trace key.

    Fires when the sum of ``cast(args[field])`` over calls matching ``tool``
    within the last ``window_s`` seconds exceeds ``max_total``. Typical uses
    are cumulative-budget policies that a per-call rule cannot express:
    total bytes exfiltrated (``args.size``), total recipients contacted,
    total rows read — an agent staying under every per-call limit but
    bleeding the budget over many calls.

    The window is recomputed from entry timestamps on every evaluation
    (same approach as :class:`RateLimitRule`): contributions slide out of
    the time window exactly — decrementing is implicit, there is no
    persistent accumulator to drift or reset. This was chosen over a
    TTL-reset ledger because the semantics are trivially explainable
    ("sum over the last N seconds") and identical across restarts.

    ``cast`` converts the resolved field value to a number (default
    ``float``); entries whose field is missing, ``None``, or fails the cast
    contribute 0 (they do not fire the rule and are not errors).
    """

    name: str
    field: str
    max_total: float
    tool: ToolMatcher = "*"
    window_s: float = 3600.0
    cast: Callable[[Any], float] = float
    description: str = ""
    _tool_fn: Callable[[str], bool] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.field:
            raise ValueError("AggregateRule field must be non-empty")
        if self.max_total <= 0:
            raise ValueError("AggregateRule max_total must be > 0")
        if self.window_s <= 0:
            raise ValueError("AggregateRule window_s must be > 0")
        if self.tool == "*":
            self._tool_fn = lambda _name: True
        else:
            self._tool_fn = _compile_tool(self.tool)

    def match(self, trace: Sequence[TraceEntry]) -> str | None:
        now = time.monotonic()
        cutoff = _window_cutoff(now, self.window_s)
        total = 0.0
        for entry in trace:
            if not self._tool_fn(entry.tool):
                continue
            if _entry_ts(entry, now) < cutoff:
                continue
            value = _resolve_path(entry.args, self.field)
            if value is None:
                continue
            try:
                total += float(self.cast(value))
            except (TypeError, ValueError):
                continue
            if total > self.max_total:
                return self.name
        return None

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"AggregateRule(name={self.name!r}, field={self.field!r}, "
            f"max_total={self.max_total}, window_s={self.window_s})"
        )


# Any object exposing ``match(trace) -> Optional[str]`` and a ``name``.
Rule = ToxicFlowRule | LoopRule | RateLimitRule | AggregateRule


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
        rules: Iterable[Rule],
        window: int = 256,
        max_traces: int = 1024,
        args_max_bytes: int = 4 * 1024,
        sticky_ttl_s: float = 600.0,
    ):
        self._rules: list[Rule] = list(rules)
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
    def rules(self) -> tuple[Rule, ...]:
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

    def set_rules(self, rules: Iterable[Rule]) -> None:
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
        self._get_trace(key).append(TraceEntry(tool=tool, args=stored, fp=fp, ts=time.monotonic()))

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
                elif progress < start:
                    # A negate guard fired: match_from returns progress 0 to
                    # signal "void" — drop the parked sticky prefix too, so a
                    # negated flow cannot resume from the negated progress.
                    self._sticky.pop((key, rule.name), None)
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
