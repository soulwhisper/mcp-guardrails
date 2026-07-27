# Auditing

The audit log is **always on** — one JSON line per decision, written to
stdout (default) or `AUDIT_LOG_PATH`. It is the durable, GitOps-friendly
record that survives even when OTel collection is down. Implemented by
`AuditSink` / `Observability` in `guardrails/otel.py`.

## Decision record fields

| Field | Meaning |
| --- | --- |
| `ts` / `ts_ms` | Epoch **seconds** (int) and epoch **milliseconds** (float), sampled from the same `time.time()` call. |
| `phase` | `request` or `response`. |
| `method` | MCP method (`tools/call`, `tools/list`, …). |
| `tool` | Tool name (empty for non-tool methods). |
| `outcome` | `allow` / `deny` / `mutated` / `human_review`. |
| `reason` | Internal decision reason (scanner + fingerprint detail). |
| `ref` | Engine-minted random uuid8 per exchange. The wire deny reason's `ref` greps to this line. |
| `exchange_id` | Dataplane-supplied correlation id (from `metadata_context` / `x-request-id`, sanitised: control chars stripped, 64-char cap); falls back to `ref` for engine-direct callers. Request- and response-side lines of one exchange grep together. Never derived from the attacker-controlled payload. |
| `caller` | Value of the whitelisted header (`AUDIT_CALLER_HEADERS`, default `x-forwarded-user`). |
| `payload_sha256` | 12-hex SHA-256 prefix of the scanned text. |
| `rules_version` | Rule-pack version counter. |
| `sidecar_version` | Package `__version__` or `GUARDRAIL_VERSION`. |
| `duration_ms` | Decision latency. |
| `truncated` / `scanned_bytes` / `total_bytes` | Scan-coverage accounting. |
| `route` / `upstream_transport` | Route name; transport (`stdio` upstreams get an empty header set — do not rely on headers for authn there). |
| `scanners` | Per-scanner breakdown: name, outcome, reason, score. |

Scanner reasons never embed raw matches or LLM output — matches use
`match_len` / `match_sha256` / `match_hmac` fingerprints, AgentAlignment
verdicts record a length fingerprint only (see
[Regex scanner](../guardrails/regex-scanner.md#audit-fingerprints)).

Rule-pack reloads emit separate lines:
`{"event": "rules_reload", "ok": …, "rules_version": …, "rule_count": …}`.

## Hash chain (tamper evidence)

With `AUDIT_HASH_CHAIN=1` (default), every line carries:

- `prev_hash` — 16-hex SHA-256 prefix of the previous line's full raw JSON
  (`0000000000000000` genesis on the first line of a stream);
- `line_hash` — prefix of this line's JSON *without* the `line_hash` field.

Editing, dropping or reordering any line breaks the chain at the next line;
appending never invalidates earlier lines. Cost is two SHA-256 digests per
line — negligible, hence on by default.

!!! warning "Single-writer assumption"
    The chain cursor is per-process. Multiple replicas appending to ONE
    shared file interleave links and fail verification — run one replica,
    per-replica files, or ship stdout to a log collector. A restart begins a
    new chain at genesis, so a truncated file head followed by a fresh
    process is not distinguishable from a restart; alert on ingestion-side
    gaps. The chain is tamper-evident, not signed — an attacker who controls
    the live writer can forge a consistent chain, so WORM storage remains the
    primary integrity control (see [Compliance](../compliance.md)).

## Operator CLI

`scripts/guardrail_ctl.py`:

```bash
# Re-walk the hash chain; reports the first broken line, non-zero exit on any break
python3 scripts/guardrail_ctl.py audit verify audit.jsonl

# Offline outcome distribution, scanner/rule drill-down, exchange_id pairing
python3 scripts/guardrail_ctl.py decision replay audit.jsonl

# Validate + dry-run a rule pack (gates a GitOps pipeline)
python3 scripts/guardrail_ctl.py rules lint examples/rules.policy
```

## Best-effort write caveat

If `AUDIT_LOG_PATH` is set and the write fails (e.g. disk full), the sidecar
logs a warning and continues — it does not fail the exchange. The stdout path
is at the mercy of the container runtime's log driver. Treat anything not yet
in WORM storage as volatile.
