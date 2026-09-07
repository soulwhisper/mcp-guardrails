"""Trace-state backends for the Invariant engine (R-1).

The :class:`~guardrails.invariant.InvariantEngine` keeps a sliding window of
recent tool calls per trace key. Historically that state lived in-process,
so N replicas behind a load balancer each saw ~1/N of every trace — loop,
rate and aggregate rules weakened proportionally. This module abstracts the
state behind :class:`TraceStore` so deployments can share it:

- :class:`MemoryTraceStore` — the historical in-process default. Semantics
  are byte-identical to the pre-abstraction engine internals (one bounded
  deque per key in an LRU map).
- :class:`RedisTraceStore` — the same semantics backed by Redis, shared by
  every replica. Optional extra ``redis`` (package ``redis>=5,<8``, lazy
  import).

The engine appends via ``store.append(key, entry)`` and evaluates rules
against ``store.read(key)``; rule-evaluation semantics are identical
regardless of backend.

Consistency model (Redis backend): appends are linearised by Redis in
arrival order and each evaluation reads the latest linearised trace, so a
detection that fires on a single replica also fires on the shared store for
the same total order of calls. Under concurrent replicas a detection may lag
by one call (a replica can evaluate before a concurrent append lands), and
the append / LRU-index eviction pair is not transactional — transient
over/under-eviction around the ``max_traces`` bound self-heals on subsequent
appends. The store never fabricates entries and never strengthens detection
beyond what one replica seeing the same ordered stream would produce.

Timestamps: ``TraceEntry.ts`` is a :func:`time.monotonic` value, meaningful
only within one process. The Redis backend therefore persists each entry's
wall-clock record time and, on read, maps it back into the reader's monotonic
frame (``ts = monotonic_now - wall_age``), so time-windowed rules see the
same entry ages on every replica — up to NTP clock skew between hosts.

Errors: Redis command failures (e.g. connection loss after startup)
propagate to the caller — fail-closed, matching the sidecar's failClosed
posture: with a shared-state backend configured, evaluating against
unreadable state would silently weaken detection. Startup connectivity is
verified by :func:`make_trace_store` (PING), which raises when Redis is
unreachable.
"""

from __future__ import annotations

import json
import time
from collections import OrderedDict, deque
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    # Typing-only: invariant imports this module at runtime, so a runtime
    # import back would be circular. ``_entry_from_json`` does the real
    # import lazily at call time.
    from .invariant import TraceEntry

# Redis key layout: one list per trace key plus a sorted-set LRU index
# (member = trace key, score = last-append wall time) used to enforce the
# ``max_traces`` bound across replicas.
_KEY_PREFIX = "mcpg:trace:"
_INDEX_KEY = "mcpg:traces"

_DEFAULT_REDIS_URL = "redis://localhost:6379/0"
# Abandoned trace keys self-clean via TTL. Well beyond the largest rule
# window in the default pack (AggregateRule window_s defaults to 3600s) and
# the sticky-progress TTL (600s); refreshed on every append.
_DEFAULT_TTL_S = 86400.0


@runtime_checkable
class TraceStore(Protocol):
    """Minimal trace-state operations the InvariantEngine needs.

    Implementations own the sliding-window bound (``window`` entries per
    key) and the ``max_traces`` cardinality bound; both are constructor
    parameters, not per-call arguments.
    """

    def append(self, key: str, entry: TraceEntry) -> None:
        """Append ``entry`` to ``key``'s trace, pruning to the window and
        refreshing the key's LRU position (creating the trace if needed)."""
        ...

    def read(self, key: str) -> list[TraceEntry]:
        """Return the current window entries for ``key`` (oldest first).

        Does NOT refresh the key's LRU position — a read-only evaluation
        must not keep an otherwise-idle tenant trace alive.
        """
        ...

    def reset(self, key: str | None = None) -> None:
        """Drop one trace, or every trace when ``key`` is None."""
        ...


class MemoryTraceStore:
    """In-process trace store — the historical default (single replica).

    Byte-identical semantics to the pre-abstraction engine internals: one
    ``deque(maxlen=window)`` per key in an LRU map bounded by ``max_traces``
    (least-recently-used tenant evicted), so a key-flooding client cannot
    grow memory without limit.
    """

    def __init__(self, *, window: int = 256, max_traces: int = 1024):
        self._window = window
        self._max_traces = max(1, max_traces)
        self._traces: OrderedDict[str, deque[TraceEntry]] = OrderedDict()

    @property
    def window(self) -> int:
        return self._window

    @property
    def max_traces(self) -> int:
        return self._max_traces

    def append(self, key: str, entry: TraceEntry) -> None:
        trace = self._traces.get(key)
        if trace is None:
            if len(self._traces) >= self._max_traces:
                # Evict the least-recently-used tenant trace.
                self._traces.popitem(last=False)
            trace = deque(maxlen=self._window)
            self._traces[key] = trace
        else:
            self._traces.move_to_end(key)
        trace.append(entry)

    def read(self, key: str) -> list[TraceEntry]:
        trace = self._traces.get(key)
        return list(trace) if trace is not None else []

    def reset(self, key: str | None = None) -> None:
        if key is None:
            self._traces.clear()
        else:
            self._traces.pop(key, None)


def _text(value: Any) -> str:
    """Normalise a Redis response that may be bytes or str."""
    return value.decode() if isinstance(value, bytes) else value


def _entry_from_json(payload: str) -> TraceEntry:
    """Rebuild an entry, mapping its wall-clock record time back into this
    process's monotonic frame (see module docstring — Timestamps)."""
    from .invariant import TraceEntry

    data = json.loads(payload)
    wall_ts = float(data.get("ts") or 0.0)
    # wall_ts == 0.0 is the legacy marker: counts as "now" in windowed rules.
    ts = time.monotonic() - max(0.0, time.time() - wall_ts) if wall_ts > 0.0 else 0.0
    return TraceEntry(
        tool=str(data.get("tool", "")),
        args=data.get("args") or {},
        fp=str(data.get("fp", "")),
        ts=ts,
    )


class RedisTraceStore:
    """Redis-backed trace store shared by all replicas behind a LB (R-1).

    Each trace key is one Redis list (``mcpg:trace:<key>``) of JSON entries,
    trimmed to the newest ``window`` entries on every append; a sorted-set
    index (``mcpg:traces``, score = last-append wall time) enforces the same
    ``max_traces`` LRU bound as the in-memory store. Keys carry a TTL
    (``ttl_s``, refreshed per append) so abandoned traces self-clean.

    Entries are JSON, so argument values must be JSON-serialisable — in
    practice always true: MCP tool args arrive as JSON over the wire.
    Non-serialisable leaves fall back to ``str(value)`` (same convention as
    the loop fingerprint). Undecodable entries are skipped on read rather
    than failing evaluation.

    Redis errors are NOT swallowed — see the module docstring (Errors).
    """

    def __init__(
        self,
        url: str = _DEFAULT_REDIS_URL,
        *,
        client: Any = None,
        window: int = 256,
        max_traces: int = 1024,
        ttl_s: float = _DEFAULT_TTL_S,
    ):
        if client is None:
            try:
                import redis
            except ImportError as exc:
                raise ImportError(
                    "redis is not installed; install with "
                    "`pip install 'mcp-guardrails[redis]'` to enable the shared "
                    "invariant state backend, or set INVARIANT_STATE_BACKEND=memory"
                ) from exc
            client = redis.Redis.from_url(url)
        self._r = client
        self._window = window
        self._max_traces = max(1, max_traces)
        self._ttl_s = max(1, int(ttl_s))

    @property
    def window(self) -> int:
        return self._window

    @property
    def max_traces(self) -> int:
        return self._max_traces

    def ping(self) -> None:
        """Verify connectivity; raises on failure (fail-closed startup)."""
        self._r.ping()

    def append(self, key: str, entry: TraceEntry) -> None:
        wall_now = time.time()
        # Persist wall-clock record time: entry.ts is a process-local
        # monotonic value, meaningless to other replicas (module docstring).
        age = max(0.0, time.monotonic() - entry.ts) if entry.ts != 0.0 else 0.0
        payload = json.dumps(
            {"tool": entry.tool, "args": entry.args, "fp": entry.fp, "ts": wall_now - age},
            default=str,
        )
        rkey = _KEY_PREFIX + key
        pipe = self._r.pipeline()
        pipe.rpush(rkey, payload)
        pipe.ltrim(rkey, -self._window, -1)
        pipe.expire(rkey, self._ttl_s)
        pipe.zadd(_INDEX_KEY, {key: wall_now})
        pipe.execute()
        # Enforce the max_traces bound across replicas. Racy under
        # concurrency (two replicas may each evict) — transient and
        # self-healing; see the module docstring's consistency model.
        excess = self._r.zcard(_INDEX_KEY) - self._max_traces
        if excess > 0:
            evicted = self._r.zpopmin(_INDEX_KEY, excess)
            if evicted:
                self._r.delete(*[_KEY_PREFIX + _text(member) for member, _score in evicted])

    def read(self, key: str) -> list[TraceEntry]:
        raw = self._r.lrange(_KEY_PREFIX + key, 0, -1)
        entries: list[TraceEntry] = []
        for item in raw:
            try:
                entries.append(_entry_from_json(_text(item)))
            except ValueError:
                continue  # skip undecodable entries rather than fail evaluation
        return entries

    def reset(self, key: str | None = None) -> None:
        if key is not None:
            pipe = self._r.pipeline()
            pipe.delete(_KEY_PREFIX + key)
            pipe.zrem(_INDEX_KEY, key)
            pipe.execute()
            return
        members = self._r.zrange(_INDEX_KEY, 0, -1)
        pipe = self._r.pipeline()
        for member in members:
            pipe.delete(_KEY_PREFIX + _text(member))
        pipe.delete(_INDEX_KEY)
        pipe.execute()


def make_trace_store(
    backend: str = "memory",
    url: str | None = None,
    *,
    window: int = 256,
    max_traces: int = 1024,
    ttl_s: float = _DEFAULT_TTL_S,
) -> TraceStore:
    """Build a :class:`TraceStore` from config (``INVARIANT_STATE_BACKEND`` /
    ``REDIS_URL``).

    ``backend="memory"`` (default) keeps the historical in-process state.
    ``backend="redis"`` shares state across replicas; connectivity is
    verified NOW (PING) and an unreachable server raises — fail-closed at
    startup, so a misconfigured Redis never leaves replicas running with
    silently per-replica-weakened invariant state.
    """
    if backend == "memory":
        return MemoryTraceStore(window=window, max_traces=max_traces)
    if backend == "redis":
        store = RedisTraceStore(
            url or _DEFAULT_REDIS_URL,
            window=window,
            max_traces=max_traces,
            ttl_s=ttl_s,
        )
        store.ping()
        return store
    raise ValueError(f"Unknown invariant trace-state backend: {backend!r}")
