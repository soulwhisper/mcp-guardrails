# Compliance notes — mcp-guardrails

This document summarises what data the sidecar handles, how the audit
record should be retained and protected, and the known limitations of the
current audit design. It is guidance for operators, not a certification of
any kind — map each section to your own regulatory scope (GDPR, SOC 2,
internal policy, …) before relying on it.

## 1. Data classification

| Data element | Where it lives | Classification | Notes |
| --- | --- | --- | --- |
| **Payload content** (MCP `params` / `result` bodies) | Process memory only, for the duration of one exchange | **Confidential** — may carry user data, secrets, PII | Never written to disk or logs by the sidecar. Scanners see the extracted text; redaction rewrites secrets/PII in ALLOW-grade payloads before forwarding. Over-budget payloads are scanned via head/mid/tail windows — the middle of a giant payload is *not* inspected (bounded by `SCAN_MAX_PAYLOAD_BYTES`, which escalates to `HUMAN_REVIEW`). |
| **Audit log (JSONL)** | stdout or `AUDIT_LOG_PATH` | **Internal / restricted** | One JSON line per decision. Metadata-only by design: timestamps, phase, method, tool name, outcome, generalised reason, `ref` / `exchange_id`, `caller`, `payload_sha256` (12-hex prefix), rules/sidecar versions, scan coverage, per-scanner breakdown. Scanner reasons never embed raw matches — high-entropy matches record a SHA-256/HMAC digest, low-entropy ones (email, credit card) record `match_len` only, so the log is not an offline enumeration oracle. |
| **Fingerprints / digests** (`payload_sha256`, `match_hmac`) | Audit log | **Internal** | A 12-hex SHA-256 prefix lets an operator prove two lines saw the same payload without storing it. Set `AUDIT_HMAC_KEY` so digests are keyed — an unkeyed SHA-256 of a low-entropy match is brute-forceable. |
| **`caller` field** | Audit log | **Personal data (quasi-PII)** | Populated only from the `AUDIT_CALLER_HEADERS` whitelist (default `x-forwarded-user`). `x-session-id` is deliberately excluded by default — a session id is a quasi-credential. Anything you add to this whitelist lands in a durable log: treat it as personal data for retention/access purposes. |
| **`ref` / `exchange_id`** | Audit log + wire | **Internal** | `ref` is an engine-minted random uuid8 (unguessable); `exchange_id` comes from trusted dataplane channels only, is sanitised (control chars stripped, 64-char cap), and never derives from the attacker-controlled payload. |
| **Invariant trace window** | Process memory | **Confidential (transient)** | Rolling per-route/per-session window of recent tool names + size-bounded args copies (4KiB per entry, structure-preserving truncation). Lost on restart; never logged wholesale. |
| **Webhook bodies** (`REVIEW_WEBHOOK_URL`) | Egress to operator endpoint | **Internal** | Metadata-only (`outcome`/`reason`/`ref`/`exchange_id`/`ts`) — no payload content. Point this at an endpoint you control; see §4 for egress notes. |

## 2. Audit retention recommendations

The JSONL audit stream is the durable compliance record. Recommended
reference architecture:

1. **Ship, don't store locally.** The sidecar writes to stdout (default) or
   a file; a log shipper (Fluent Bit, Vector, the OTel collector filelog
   receiver) forwards lines to immutable storage. The container filesystem
   is ephemeral and must not be the system of record.
2. **WORM / object-lock storage.** Land the archive on an object store with
   retention locked — e.g. S3 Object Lock in *compliance* mode, GCS
   retention policy with bucket lock, or Azure immutable blobs. This gives
   you write-once-read-many semantics: neither an attacker who compromises
   the sidecar nor an operator can rewrite history.
3. **Suggested retention periods** (align with your scope):
   - Security-relevant decision lines (deny / human_review): **≥ 1 year**
     (SOC 2 CC7 typical; PCI DSS 10.7 requires 1 year with 3 months hot).
   - Full allow traffic: **90 days** hot / 1 year cold is a common homelab
     compromise; reduce if the `caller` field carries personal data and
     your privacy policy demands it.
   - `rules_reload` events: keep for the life of the deployment — they
     anchor which policy version produced a given decision.
4. **Integrity.** The audit stream is hash-chained by default
   (`AUDIT_HASH_CHAIN=1`, A-P0-3): each line carries `prev_hash` /
   `line_hash` (16-hex SHA-256 prefixes) and
   `guardrail_ctl audit verify <file>` re-walks the chain offline,
   reporting the first broken line. This detects post-hoc edits, drops and
   reorders — but it is NOT non-repudiation (an attacker who controls the
   writer from the start can forge a consistent chain), so still land the
   archive on WORM storage and record the store's object version IDs /
   retention markers in your change log.
5. **Clock.** Audit `ts`/`ts_ms` come from the sidecar's system clock. Run
   NTP on the nodes; without it, cross-log correlation drifts.

## 3. Access control recommendations

- **Audit log read access** should be limited to the security/ops group.
  The log contains tool names, caller identities, timestamps and policy
  verdicts — enough to profile user behaviour. Use the object store's IAM
  (bucket-level, read-only role) rather than sharing raw credentials.
- **`kubectl logs` / exec on the sidecar pods** exposes the live audit
  stream and (via `/proc`) env vars such as `LF_ALIGNMENT_API_KEY` and
  `AUDIT_HMAC_KEY`. Restrict with RBAC; mount secrets as files or via
  a secrets manager where possible.
- **Rule packs** (`INVARIANT_RULES_PATH`) are policy-as-code: review
  changes via Git PR (four-eyes), and gate the ConfigMap/manifests pipeline
  the same way as application code. A weakened rule is a silent control
  removal; `rules_reload` audit lines + the
  `mcp.guardrails.rules_reload{result}` counter make reloads visible.
- **The webhook endpoint** (`REVIEW_WEBHOOK_URL`) receives decision
  metadata; restrict it to the intended receiver (network policy +
  authentication at the receiver — the sidecar does not sign requests).

## 4. AgentAlignment data egress statement

When `ENABLE_AGENT_ALIGNMENT=1`, flagged response chunks are sent to an
external LLM API (default: Together AI; configurable via
`LF_ALIGNMENT_API_BASE`). Before egress the chunk is pre-redacted with an
extended pattern set (block-grade secrets/PII **plus** the review-grade
credential shapes — JWTs, connection strings, key=value credentials), so
cleartext credentials do not leave the deployment via this path. The only
other context sent is a metadata-only summary of the last 5 tool-call
names (`McpCallContext.trace_summary`) — no arguments, no payload.

**This is cross-border / third-party data transfer.** Enabling
AgentAlignment means (redacted) user content is processed by the LLM
provider under THEIR terms and retention policy. If your compliance scope
forbids that (data-residency requirements, regulated content), leave
`ENABLE_AGENT_ALIGNMENT=0` (the default) — `HUMAN_REVIEW` outcomes are
then resolved locally per `HUMAN_REVIEW_MODE`. The default
`HUMAN_REVIEW_MODE=pass` forwards with an audit warning; set
`HUMAN_REVIEW_MODE=deny` for a fully local, strict posture.

## 5. Known audit limitations

- **Hash chain is tamper-evident, not signed (implemented, A-P0-3).**
  With `AUDIT_HASH_CHAIN=1` (default) every line carries
  `prev_hash` / `line_hash` (16-hex SHA-256 prefixes), and
  `guardrail_ctl audit verify <file>` reports the first broken line —
  post-hoc edits, drops and reorders of the archived file are detectable.
  Residual limits: (a) the chain is keyed by nothing — an attacker who
  compromises the LIVE writer can simply emit a fresh consistent chain,
  so this is tamper-evidence for the archive, not non-repudiation (WORM
  storage remains the primary integrity control); (b) the chain cursor is
  per-process — multiple replicas appending to ONE shared file interleave
  links and fail verification (single replica, per-replica files, or
  stdout shipping); (c) a restart begins a new chain at the genesis
  `prev_hash`, so a truncation of the file head followed by a fresh
  process is not distinguishable from a restart — alert on ingestion-side
  gaps instead.
- **Best-effort local write.** If `AUDIT_LOG_PATH` is set and the write
  fails (disk full), the sidecar logs a warning and continues — it does
  not fail the exchange. The stdout path is at the mercy of the container
  runtime's log driver. For strict audit guarantees, treat anything not
  yet in WORM storage as volatile.
- **No at-rest encryption by the sidecar itself.** Encryption of the audit
  archive is the store's job (SSE-S3/SSE-KMS, GCS default encryption).
- **Clock trust.** Timestamps are node-local; there is no trusted
  timestamping. WORM ingestion time (store-side) is the stronger signal.
- **Coverage limits are explicit, not hidden.** Over-budget payloads are
  scanned head/mid/tail only; over-`REDACTION_MAX_BYTES` payloads skip
  redaction (`redaction_skipped=size` in the span); giant payloads
  (> `SCAN_MAX_PAYLOAD_BYTES`) get a `payload_size` review flag. Audit
  consumers should alert on `truncated=true` and
  `scanned_bytes << total_bytes` instead of assuming full coverage.
- **Webhook delivery is fire-and-forget.** A `REVIEW_WEBHOOK_URL` POST
  that fails is only logged (never retried, never blocking). The audit
  log remains the authoritative record of human_review decisions; the
  webhook is a convenience notification channel, not a control.
