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
            self._counters = {
                "decisions": self._meter.create_counter(
                    "mcp.guardrails.decisions",
                    unit="1",
                    description="Guardrail decisions by outcome",
                ),
            }
            self._otel_ok = True
            logger.info("OTel telemetry enabled, endpoint=%s", endpoint)
        except Exception as exc:  # pragma: no cover
            logger.warning("OTel init failed (falling back to audit-only): %s", exc)
            self._otel_ok = False

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
    ) -> None:
        outcome = "deny" if decision.deny else ("mutated" if decision.is_mutated else "allow")
        if decision.human_review and not decision.deny:
            outcome = "human_review"
        record = {
            "ts": int(time.time()),
            "phase": phase,
            "method": method,
            "tool": tool_name,
            "outcome": outcome,
            "reason": decision.reason,
            "ref": decision.ref,
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
