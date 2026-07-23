# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Features

* **redaction:** the mutation stage (`guardrails/redaction.py`) masks
  secret/PII material in ALLOW-grade payloads with
  `[REDACTED:<TYPE>]` placeholders and forwards the rewritten payload via
  the proto `mutated` oneof. Response side on by default
  (`ENABLE_REDACTION=1`); request side opt-in (`REDACT_REQUEST_PARAMS=1`).
  Covers cloud/chat/LLM tokens (AWS, GitHub, GitLab, Slack, JWT, generic
  `sk-*`, private-key PEM blocks) plus PII (emails, credit cards). The
  structural walk (`redact_value`) preserves JSON shape — keys, list
  lengths and non-string types are unchanged, only string values with a
  match are replaced, so the mutated payload stays valid JSON.
* **redaction:** `REDACT_ON_REVIEW=1` (default) — HUMAN_REVIEW payloads
  are redacted too. The review verdict is preserved (the aggregator's
  `human_review` flag and audit outcome are untouched) and the mutated
  payload rides alongside via the `mutated` oneof, so review-grade PII is
  masked instead of passing through verbatim. `REDACT_ON_REVIEW=0`
  restores the legacy pass-unmutated behaviour.
* **redaction:** `REDACTION_MAX_BYTES` (default 256 KiB) bounds the
  payload handed to the regex sweep; over-cap payloads skip redaction and
  pass through unchanged with `redaction_skipped=size` in the audit span.
  Safe because scanner BLOCK decisions still apply upstream (block-grade
  secrets in an over-cap payload are denied by the RegexScanner on the
  head/mid/tail scan windows before redaction would run) — only
  best-effort masking of ALLOW-grade PII is skipped.
* **engine:** the redaction regex sweep runs via `asyncio.to_thread`, so a
  large (under-cap) payload cannot stall the event loop and starve
  concurrent exchanges.
* **scanning:** `scan_windows(text, max_content_bytes, scan_tail_bytes)`
  replaces head-only truncation: over-budget payloads now scan a UTF-8-safe
  head window PLUS a mid window (centred on the unscanned remainder) and a
  tail window (default 8 KiB each, `SCAN_TAIL_BYTES=0` disables). Closes
  the truncation bypass (padding the payload so an injection lands past the
  32 KiB head) and the mid-payload blind spot. The audit line gains
  `scanned_bytes` / `total_bytes` coverage fields alongside `truncated`.
* **scanning:** `SCAN_MAX_PAYLOAD_BYTES` (default 1 MiB) hard payload cap.
  Over-cap payloads are still scanned (head/mid/tail windows) AND flagged
  with a `payload_size` HUMAN_REVIEW result carrying scanned/total bytes;
  `HUMAN_REVIEW_MODE` decides pass+warn vs deny.
* **tool ACL:** `ALLOW_TOOLS` / `DENY_TOOLS` coarse tool-level ACL applied
  on the request side BEFORE content scanners. Comma-separated tool names,
  `prefix/*` wildcards; DENY wins, non-empty ALLOW is a whitelist. The
  wire deny reason is generalised (`denied by content policy`); the tool
  name is already an audit field so the audit reason carries it.
* **promptguard:** `PG_MAX_WINDOWS` (default 16) — adaptive sliding-window
  budget for long chunks. The window count grows with the payload's token
  length (`clamp(ceil(tokens/step)+1, 4, PG_MAX_WINDOWS)`), keeping the
  first N-1 strided windows plus a tail-aligned window; each extra window
  is one more 512-token inference, so the cap is the per-chunk latency
  bound. Replaces the fixed 4-window ceiling (long-payload coverage gap)
  while bounding worst-case scan latency.
* **invariant:** `RateLimitRule(tool, window_s, max_calls)` — sliding
  time-window call-rate limit counted per tool name (`"*"` wildcard gives
  every tool its own budget). Catches volumetric abuse with varying args
  (enumeration / spray) that LoopRule's identical-fingerprint check
  cannot see.
* **invariant:** `AggregateRule(field, max_total, tool, window_s, cast)` —
  sliding time-window budget: sums `cast(args[field])` (dotted path) over
  matching calls within the window and fires past `max_total`. Cumulative
  budgets (bytes exfiltrated, recipients contacted) a per-call rule cannot
  express. The window is recomputed from entry timestamps on every
  evaluation — no persistent accumulator to drift or reset.
* **invariant:** `TraceEntry` gains a `ts` field (`time.monotonic()`,
  stamped on `record`); hand-constructed entries default to `0.0` and are
  treated as "now" by the time-windowed rules (legacy two-field
  construction stays source-compatible).
* **invariant:** `INVARIANT_MAX_TRACES` (default 1024) LRU bound on the
  per-route trace map — a key-flooding client can no longer grow sidecar
  memory without bound; the oldest (LRU) tenant trace is evicted.
* **invariant:** `INVARIANT_ARGS_MAX_BYTES` (default 4 KiB) per-entry args
  cap in the trace window: oversized args keep their structure with long
  string values truncated (structure-preserving, so arg matchers keep
  working); the loop fingerprint is computed from the FULL args before
  truncation, so LoopRule behaviour is unchanged.
* **invariant:** sticky partial-match progress — a ToxicFlowRule that
  matched a PREFIX of its steps parks the progress keyed
  `(trace_key, rule_name)` with a TTL (`INVARIANT_STICKY_TTL_S`, default
  600 s) and the same LRU bound as the trace map, so a flow whose early
  steps slide out of the window still completes. A negate guard voiding a
  flow also drops the parked progress.
* **invariant:** `INVARIANT_TRACE_KEY_HEADERS` — comma-separated request
  headers (e.g. `x-session-id`) extend the trace key to
  `route|header=value` for per-session toxic-flow isolation. Missing
  header / unset -> legacy route-dimension key.
* **audit:** Wave-2 audit expansion — every decision line gains `ts_ms`
  (epoch milliseconds float alongside the seconds-int `ts`), `ref`
  (engine-minted random uuid8, matching the wire deny reason),
  `exchange_id` (dataplane-supplied correlation id from
  `metadata_context` exchange_id / request_id / x_request_id / trace_id
  or the `x-request-id` header; sanitised, control chars stripped,
  64-char cap; never derived from the attacker-controlled payload),
  `caller` (only from the `AUDIT_CALLER_HEADERS` whitelist, default
  `x-forwarded-user`; `x-session-id` deliberately excluded — it is a
  quasi-credential), `payload_sha256` (12-hex prefix of the scanned
  text), `rules_version`, `sidecar_version` (`GUARDRAIL_VERSION`
  override, else package version) and `duration_ms`.
* **audit:** rule-pack reloads emit `{"event": "rules_reload", "ok": …,
  "rules_version": …}` audit lines (success AND failure) and bump the
  `mcp.guardrails.rules_reload{result}` counter, so a broken SIGHUP
  reload is visible in the durable record, not just stderr.
* **metrics:** `mcp.guardrails.decision_duration_ms` histogram (ms,
  labelled `phase`/`outcome`), `mcp.guardrails.scanner_results` counter
  (`scanner`/`outcome`, incl. `error`/`timeout`),
  `mcp.guardrails.redactions` counter, `mcp.guardrails.invariant_hits`
  counter (`rule`). All labels are low-cardinality by construction
  (bounded enums only — no refs, tool names, callers or hashes).
* **health:** runtime degradation verdict — a sliding window of the last
  `UNHEALTHY_SCANNER_WINDOW` (default 100) scanner invocations flips gRPC
  health to NOT_SERVING once the error/timeout rate exceeds
  `UNHEALTHY_SCANNER_ERROR_RATE` (default 0.5, min
  `UNHEALTHY_SCANNER_MIN_SAMPLES` = 20 samples), recovering automatically.
  Tracked under failOpen too, so scanner degradation is visible even when
  exchanges still flow.
* **wire:** `AuthorizationError.mcp_error` now carries a structured
  JSON-RPC 2.0 error body (`code: -32001`) whose `data` adds a
  generalised policy `category` (content_policy / tool_policy /
  tool_flow / rate_limit / budget / engine_error) and a generic `remedy`
  hint — never pattern names or match detail.
* **wire:** `McpRequestResult.metadata` is populated on every
  request-side verdict with `guardrail.scan_score`,
  `guardrail.rules_hit`, `guardrail.redactions`, `guardrail.exchange_id`
  and `guardrail.outcome` (`allow` / `mutated` / `deny`) so the dataplane
  can log/route on guardrail verdicts without parsing the audit stream.
  `header_mutation` is deliberately unused (a caller-visible
  `x-guardrail-ref` header adds nothing over the wire `ref` in the deny
  reason).
* **tests:** `tests/test_redteam.py` red-team capability baseline —
  base64-encoded injection, zero-width/confusables, markdown-image exfil,
  `### SYSTEM` case variants, head/mid/tail padding bypasses, and
  window-flush sequences. Current gaps (confusable markers, markdown
  image exfil) are `xfail(strict=False)` with the residual documented.
* **notify:** `REVIEW_WEBHOOK_URL` — when set, every `human_review`
  decision POSTs a metadata-only JSON body
  (`outcome`/`reason`/`ref`/`exchange_id`/`ts`) to that endpoint
  (`guardrails/notify.py`). Fire-and-forget: a background asyncio task
  with a 2 s timeout over zero-dependency urllib; a slow/failing endpoint
  only logs and never blocks or alters the decision path. Unset
  (default) disables the notifier.
* **server:** graceful shutdown drain (A-P2-4) — on SIGTERM/SIGINT the
  gRPC health service flips to NOT_SERVING first (and the health watchdog
  is cancelled so it cannot flip back mid-drain), the sidecar waits
  `SHUTDOWN_DRAIN_S` (default 5.0) for readiness propagation, then
  `server.stop(grace)` drains in-flight RPCs. Ordered
  NOT_SERVING → propagation wait → drain replaces the previous
  immediate-stop behaviour that could cut in-flight exchanges at rollout.
* **tooling:** `scripts/guardrail_ctl.py` operator CLI —
  `rules lint [--path|--module]` loads a rule pack exactly like the
  runtime loader, validates rule structure (empty steps, unknown fields,
  negate placement, threshold/window legality, duplicate names) and
  dry-runs every rule against built-in sample traces (non-zero exit on an
  invalid pack, so it gates a GitOps pipeline);
  `decision replay <audit.jsonl>` gives an offline outcome distribution,
  per-scanner/rule drill-down and exchange_id request/response pairing
  over the JSONL audit log (tolerates malformed lines).
* **tests:** `tests/test_property.py` — hypothesis property tests over
  `scan_windows` (UTF-8-safe chunks, head/tail coverage, truncated flag),
  `extract_text` (never raises, always str), `_safe_json_loads` (never
  raises on arbitrary bytes) and `redact_value` (structure preserved,
  JSON-serialisable). The module `pytest.importorskip`s hypothesis, so
  the suite runs without the dev extra.
* **compliance:** `docs/compliance.md` — data classification table
  (payloads vs audit log vs fingerprints vs caller vs webhook bodies),
  audit-retention reference architecture (ship to WORM / object-lock
  storage, suggested retention periods), access-control recommendations,
  the AgentAlignment cross-border egress statement, and the known audit
  limitations (no hash-chaining, best-effort local write, clock trust).
* **supply chain:** `make audit` runs pip-audit against
  `requirements.txt` (accepted-risk CVEs whitelisted one-per-line in
  `scripts/pip-audit-ignore.txt`, justification required); `make sbom`
  runs `scripts/gen_sbom.sh` (syft → SPDX + CycloneDX into `sbom/`).
  Both tools are dev-extra dependencies, never runtime; CI wiring is
  intentionally left to the workflow owner (needs a token with
  release-asset scope).

### Bug Fixes

* **promptguard:** the `jailbreak` / `injection` label hint now correctly
  inverts a low-score binary classifier (`1 - score`) instead of
  returning the benign probability as the block score.
* **regex:** catastrophic-backtracking fixes in the PII/secret patterns
  (bounded quantifiers, no nested repeats); the email pattern no longer
  misses `+`-tagged addresses; credit-card matching tolerates spaces /
  dashes between digit groups.
* **regex:** match fingerprints are tiered by entropy — low-entropy
  patterns (email, credit card, key=value credentials, connection
  strings) record `match_len` only; high-entropy patterns record a
  SHA-256 digest, or HMAC-SHA256 when `AUDIT_HMAC_KEY` is set. Closes the
  offline enumeration oracle where an unkeyed digest of a low-entropy
  match could be brute-forced from the audit log.
* **extract_text:** hidden Unicode (zero-width, bidi controls, tag
  characters) in argument values survives to the regex scanner
  (`ensure_ascii=False`); previously `\uXXXX` escaping could hide
  `HIDDEN_ASCII` matches from the pattern layer.
* **servicer:** `exchange_id` from `metadata_context` / `x-request-id` is
  sanitised (CR/LF and control characters stripped, 64-char cap) before
  reaching the audit log — closes an audit-log line-injection vector.
* **servicer:** the JSON-RPC payload `id` is never used as the audit
  `ref`; refs are engine-minted uuid8 so the wire deny reason cannot be
  pre-computed or spoofed by the caller.
* **engine:** `scan_windows` mid/tail chunk boundaries are UTF-8-safe
  (previously a multi-byte character straddling the cut could produce
  mojibake in the scanned text).
* **docker:** the image healthcheck uses an inline Python gRPC health
  probe instead of `grpcurl` (not present in the slim runtime image), so
  `docker inspect` health works out of the box.
