# Metrics

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set (and the OTel SDK is importable),
the sidecar exports traces and metrics over OTLP/gRPC with a 15s metric
export interval; otherwise it degrades to audit-log-only. The channel TLS
mode comes from `OTEL_EXPORTER_OTLP_INSECURE`, defaulting to the endpoint
scheme (`https://` → secure, `http://` or no scheme → insecure) — cluster
telemetry crossing the network should use TLS. Note the SDK's
`BatchSpanProcessor` swallows export failures: a dead collector only
surfaces as an SDK log line, so alert on the [audit stream](auditing.md),
not on spans arriving.

Setting `PROMETHEUS_LISTEN_ADDR` (e.g. `:9464`) additionally serves a
Prometheus `/metrics` pull endpoint (requires the
`opentelemetry-exporter-prometheus` package; a missing package or failed
bind logs a warning and OTLP is unaffected). Pull and push readers coexist
on the same `MeterProvider`.

Instruments are defined in `guardrails/otel.py`.

## Instruments

| Instrument | Type | Labels | Description |
| --- | --- | --- | --- |
| `mcp.guardrails.decisions` | counter | `phase`, `outcome`, `method` | Guardrail decisions by outcome (`allow` / `deny` / `mutated` / `human_review`). |
| `mcp.guardrails.decision_duration_ms` | histogram (ms) | `phase`, `outcome` | Decision latency. |
| `mcp.guardrails.scanner_results` | counter | `scanner`, `outcome` | Scanner invocations by scanner name and outcome (incl. `error` / `timeout`). |
| `mcp.guardrails.redactions` | counter | — | Redaction substitutions applied by the mutation stage. |
| `mcp.guardrails.invariant_hits` | counter | `rule` | Invariant rule hits by rule name. |
| `mcp.guardrails.rules_reload` | counter | `result` (`success` / `error`) | Rule-pack reload attempts. |

Every decision also becomes a span carrying method, tool, scanner outcomes
and the final decision.

## Label cardinality rule

Labels are restricted to **low-cardinality enums**: phase / outcome / method
(bounded by the MCP method set), scanner name (bounded by the configured
scanner list), invariant rule name (bounded by the loaded rule pack), reload
result. **Never** label by `ref` / `exchange_id`, tool name, caller, payload
hash, or any other per-exchange value — those belong in the
[audit log](auditing.md) only.

## Alerting suggestions

- `rate(mcp.guardrails.scanner_results{outcome=~"error|timeout"}[5m]) /
  rate(mcp.guardrails.scanner_results[5m]) > UNHEALTHY_SCANNER_ERROR_RATE` —
  scanner degradation (the gRPC health endpoint flips `NOT_SERVING` at the
  same threshold; alert on both).
- `increase(mcp.guardrails.rules_reload{result="error"}[15m]) > 0` — a SIGHUP
  rule reload failed; the previous pack is still active.
- `histogram_quantile(0.95, rate(mcp.guardrails.decision_duration_ms_bucket[5m]))`
  — decision-latency regression watch.
- Audit-side: alert on `truncated=true` and `scanned_bytes << total_bytes`
  (under-scanned payloads), and on ingestion gaps in the hash-chained audit
  stream.
- gRPC health `NOT_SERVING` after warmup — the Pod leaves Service endpoints;
  investigate scanner errors or a stuck model load.

## Upgrade note (redaction)

With redaction enabled, the decisions counter and audit `outcome` gain
`outcome="mutated"`. Dashboards counting "successful" decisions as
`outcome="allow"` should be widened to `outcome=~"allow|mutated"`.
