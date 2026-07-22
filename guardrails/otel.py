"""Observability — OpenTelemetry traces/metrics + structured audit log.

OTel is lazy-imported so the package runs without ``opentelemetry-sdk``
installed (the unit tests never need it). When ``OTEL_EXPORTER_OTLP_ENDPOINT``
is set and the SDK is importable, every guardrail decision becomes a span
carrying the method, tool, scanner outcomes and final decision; a counter
records allow/deny/mutate tallies. Otherwise the helpers degrade to the
audit-log-only path.

The audit log is always on (defaults to stdout when no path is configured) and
emits one JSON line per decision — this is the durable, GitOps-friendly record
that survives even when OTel collection is down.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import Any

from .models import Decision, McpCallContext

logger = logging.getLogger("mcp.guardrails")


class AuditSink:
    """Append-only JSONL audit sink. Thread-safe via the file's own locking."""

    def __init__(self, path: str | None = None):
        # None / "-" / "" -> stdout.
        self._path = path if path and path != "-" else None

    def emit(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, default=str, sort_keys=True)
        if self._path is None:
            print(line, flush=True)
        else:
            try:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:  # pragma: no cover - best effort
                logger.warning("audit log write failed: %s", exc)


class Observability:
    """Holds OTel handles (if available) + the audit sink."""

    def __init__(
        self,
        *,
        service_name: str = "mcp-guardrails",
        otel_endpoint: str | None = None,
        audit_path: str | None = None,
    ):
        self.service_name = service_name
        self.otel_endpoint = otel_endpoint
        self.audit = AuditSink(audit_path)
        self._tracer = None
        self._meter = None
        self._counters: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}
        self._otel_ok = False
        if otel_endpoint:
            self._init_otel(service_name, otel_endpoint)

    def _init_otel(self, service_name: str, endpoint: str) -> None:
        try:  # pragma: no cover - exercised only with otel installed + endpoint
            from opentelemetry import metrics, trace
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter,
            )
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create({"service.name": service_name})
            tp = TracerProvider(resource=resource)
            tp.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True))
            )
            trace.set_tracer_provider(tp)
            self._tracer = trace.get_tracer(service_name)

            reader = PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=endpoint, insecure=True),
                export_interval_millis=15000,
            )
            mp = MeterProvider(resource=resource, metric_readers=[reader])
            metrics.set_meter_provider(mp)
            self._meter = metrics.get_meter(service_name)
            self._init_instruments()
            self._otel_ok = True
            logger.info("OTel telemetry enabled, endpoint=%s", endpoint)
        except Exception as exc:  # pragma: no cover
            logger.warning("OTel init failed (falling back to audit-only): %s", exc)
            self._otel_ok = False

    def _init_instruments(self) -> None:
        """Create the OTel instruments on ``self._meter``.

        Factored out of :meth:`_init_otel` so tests can inject a fake meter
        (``obs._meter = fake; obs._init_instruments()``) and assert on
        instrument registration + label cardinality without a live OTLP
        collector.

        Label cardinality rule (A-P1-2): labels are restricted to
        low-cardinality enums — phase/outcome/method (bounded by the MCP
        method set), scanner name (bounded by the configured scanner list),
        invariant rule name (bounded by the loaded rule pack), reload result
        (success/error). NEVER label by ref/exchange_id, tool_name, caller,
        payload hash, or any other per-exchange value.
        """
        if self._meter is None:
            return
        self._counters = {
            "decisions": self._meter.create_counter(
                "mcp.guardrails.decisions",
                unit="1",
                description="Guardrail decisions by outcome",
            ),
            "scanner_results": self._meter.create_counter(
                "mcp.guardrails.scanner_results",
                unit="1",
                description="Scanner invocations by scanner name and outcome "
                "(allow/block/human_review/error/timeout)",
            ),
            "redactions": self._meter.create_counter(
                "mcp.guardrails.redactions",
                unit="1",
                description="Redaction substitutions applied by the mutation stage",
            ),
            "invariant_hits": self._meter.create_counter(
                "mcp.guardrails.invariant_hits",
                unit="1",
                description="Invariant rule hits by rule name",
            ),
            "rules_reload": self._meter.create_counter(
                "mcp.guardrails.rules_reload",
                unit="1",
                description="Rule-pack reload attempts by result (success/error)",
            ),
        }
        self._histograms = {
            "decision_duration": self._meter.create_histogram(
                "mcp.guardrails.decision_duration_ms",
                unit="ms",
                description="Guardrail decision latency by phase/outcome",
            ),
        }

    def record_redactions(self, n: int) -> None:
        """Bump the redactions counter (called by the engine mutation stage)."""
        if n <= 0:
            return
        counter = self._counters.get("redactions")
        if counter is not None:  # pragma: no cover - otel path
            with suppress(Exception):
                counter.add(n)

    def record_rules_reload(self, *, ok: bool) -> None:
        """Counter for rule-pack reload attempts (A-P1-3)."""
        counter = self._counters.get("rules_reload")
        if counter is not None:  # pragma: no cover - otel path
            with suppress(Exception):
                counter.add(1, {"result": "success" if ok else "error"})

    @property
    def otel_enabled(self) -> bool:
        return self._otel_ok

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[dict[str, Any]]:
        """Context manager that emits both an OTel span (if available) and an
        audit-log line on exit.

        Yields a mutable attribute dict the caller can enrich mid-flight.
        """
        attrs: dict[str, Any] = dict(attributes)
        start = time.perf_counter()
        span_ctx = None
        if self._tracer is not None:  # pragma: no cover - otel path
            span_ctx = self._tracer.start_as_current_span(name)
        try:
            if span_ctx is not None:  # pragma: no cover
                with span_ctx as span:
                    for k, v in attrs.items():
                        with suppress(Exception):
                            span.set_attribute(k, str(v))
                    yield attrs
            else:
                yield attrs
        finally:
            duration_ms = (time.perf_counter() - start) * 1000.0
            attrs["duration_ms"] = round(duration_ms, 3)
            attrs.setdefault("event", name)
            self.audit.emit(attrs)

    def record_decision(
        self,
        *,
        phase: str,
        method: str,
        tool_name: str,
        ctx: McpCallContext,
        decision: Decision,
        payload_sha256: str = "",
        rules_version: int | str = "",
        sidecar_version: str = "",
        duration_ms: float = 0.0,
    ) -> None:
        outcome = "deny" if decision.deny else ("mutated" if decision.is_mutated else "allow")
        if decision.human_review and not decision.deny:
            outcome = "human_review"
        # A-P0-1: exchange_id == decision.ref — one greppable correlation id
        # shared by the wire deny reason and both sides' audit lines.
        exchange_id = ctx.exchange_id or decision.ref
        record = {
            # A-P1-1 precision change: ``ts`` is now epoch MILLISECONDS as a
            # float (was epoch seconds as an int). Field name unchanged.
            "ts": round(time.time() * 1000.0, 3),
            "phase": phase,
            "method": method,
            "tool": tool_name,
            "outcome": outcome,
            "reason": decision.reason,
            "ref": decision.ref,
            "exchange_id": exchange_id,
            "caller": ctx.caller,
            "payload_sha256": payload_sha256,
            "rules_version": rules_version,
            "sidecar_version": sidecar_version,
            "duration_ms": round(duration_ms, 3),
            "truncated": ctx.truncated,
            "scanned_bytes": ctx.scanned_bytes,
            "total_bytes": ctx.total_bytes,
            "upstream_transport": ctx.upstream_transport,
            "route": ctx.route_name,
            "scanners": [asdict_scan(s) for s in decision.scanners],
        }
        if self._counters.get("decisions") is not None:  # pragma: no cover
            with suppress(Exception):
                self._counters["decisions"].add(
                    1, {"phase": phase, "outcome": outcome, "method": method}
                )
        hist = self._histograms.get("decision_duration")
        if hist is not None:  # pragma: no cover - otel path
            with suppress(Exception):
                hist.record(duration_ms, {"phase": phase, "outcome": outcome})
        scanner_results = self._counters.get("scanner_results")
        invariant_hits = self._counters.get("invariant_hits")
        for s in decision.scanners:
            name = getattr(s, "scanner", "")
            out = getattr(getattr(s, "outcome", None), "value", "")
            if scanner_results is not None and name:  # pragma: no cover
                with suppress(Exception):
                    scanner_results.add(1, {"scanner": name, "outcome": out})
            # invariant_hits{rule}: scanner name is "invariant:<rule>" on a
            # hit. Rule names come from the loaded rule pack (bounded, low
            # cardinality by construction).
            if (
                invariant_hits is not None
                and name.startswith("invariant:")
                and out == "block"
            ):  # pragma: no cover - otel path
                with suppress(Exception):
                    invariant_hits.add(1, {"rule": name.split(":", 1)[1]})
        self.audit.emit(record)

    def record_reload_audit(
        self,
        *,
        ok: bool,
        rules_version: int | str = "",
        rule_count: int = 0,
        error: str = "",
        sidecar_version: str = "",
    ) -> None:
        """Emit the ``rules_reload`` audit line + counter (A-P1-3).

        Both successful and failed SIGHUP reloads land in the audit log so a
        silent config regression is visible in the same durable record as the
        decisions it affects.
        """
        now = time.time()
        record = {
            "ts": int(now),
            "ts_ms": round(now * 1000.0, 3),
            "event": "rules_reload",
            "ok": ok,
            "rules_version": rules_version,
            "rule_count": rule_count,
            "error": error,
            "sidecar_version": sidecar_version,
        }
        self.record_rules_reload(ok=ok)
        self.audit.emit(record)


def asdict_scan(s: Any) -> dict[str, Any]:
    """Serialise a ScanResult to a JSON-safe dict (outcome is a str Enum)."""
    try:
        return {
            "scanner": s.scanner,
            "outcome": s.outcome.value,
            "reason": s.reason,
            "score": s.score,
        }
    except AttributeError:
        return {"scanner": str(s)}


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
        stream=sys.stderr,
    )
