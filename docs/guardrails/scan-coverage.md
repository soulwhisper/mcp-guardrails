# Scan coverage

What the scanners actually see — and, just as importantly, what they do not.
The coverage model is deliberately explicit: every gap is bounded by a knob
and surfaced in the audit record.

## Text extraction

`extract_text` (`guardrails/scanners.py`) flattens the MCP payload into one
scan string:

- `tools/call` result — `content[].text` items joined (non-text items like
  images fall back to their JSON dump so embedded instruction strings stay
  visible).
- `resources/read` result — `contents[]` text, and base64 `blob` items
  **decoded** (capped at 256KiB decoded bytes) so file contents are scanned,
  not just their base64 wrapping.
- `prompts/get` result — `messages[]` content flattened.
- `tools/list` result — every tool's `description` plus its `inputSchema`
  JSON (tool-poisoning surface).
- Fallback — a JSON dump with `ensure_ascii=False`, so hidden control /
  zero-width characters are **not** `\u`-escaped away before the regex
  scanner sees them.

## Byte windows (balanced head / mid / tail samples)

`scan_windows(text, MAX_CONTENT_BYTES, SCAN_TAIL_BYTES)` decides which parts
of an over-budget payload are scanned. `SCAN_TAIL_BYTES` defaults to 11KiB;
each window is capped by `min(MAX_CONTENT_BYTES, SCAN_TAIL_BYTES)`.

| Payload after the 32KiB threshold | Windows | Coverage |
| --- | --- | --- |
| Fits within four windows | Up to four contiguous, balanced chunks | Complete payload, with no duplicate scanning. |
| Larger than four windows | Prefix, a midpoint window, one window on the largest remaining gap, suffix | Four bounded head/mid/tail samples; regions between them remain unscanned. |

Balanced windows keep every scanner call within its deadline instead of
letting one 32KiB head monopolise it. All windows are UTF-8-safe (truncated on
character boundaries). `SCAN_TAIL_BYTES=0` restores legacy head-only
behaviour. Decisions on truncated payloads are flagged `truncated=true` in
the audit record, with `scanned_bytes` / `total_bytes`.

## Payload hard cap

Payloads whose extracted text exceeds `SCAN_MAX_PAYLOAD_BYTES` (default
1MiB) are still scanned via the bounded windows **and** gain a `payload_size`
`HUMAN_REVIEW` result carrying the scanned/total byte counts —
`HUMAN_REVIEW_MODE=deny` turns it into a hard deny. This bounds the
unscanned fraction of giant payloads.

## PromptGuard token windows

Within each scanned chunk, PromptGuard scores 512-token sliding windows
(stride 64) with an adaptive budget `clamp(ceil(tokens/step)+1, 4,
PG_MAX_WINDOWS)` — the first `budget-1` strided windows plus a tail-aligned
window, MAX score wins (see [PromptGuard](promptguard.md)).

## Coverage matrix

| Payload size | Regex scanner | PromptGuard | Notes |
| --- | --- | --- | --- |
| ≤ 32KiB | Full text | Up to 4 windows (adaptive budget floor); short payloads usually scored whole | Full coverage. |
| 32KiB – 1MiB | Balanced windows | Each scanned chunk gets up to `PG_MAX_WINDOWS` (16) token windows (~7.7K tokens per chunk) | Complete coverage with up to four windows when the payload fits; otherwise four samples with regions **between** them unscanned. Within each chunk, tokens past the window budget are unscanned. |
| > 1MiB | Same bounded windows | Same per-chunk budget | Plus a `payload_size` `HUMAN_REVIEW` flag so the under-scan is a decision-level event, not a silent gap. |

## Known residual gaps (honest list)

- **Unscanned middle regions.** Between the byte windows (and beyond the
  per-chunk token budget) an injection can hide. This is a bounded,
  documented trade-off: raise `SCAN_TAIL_BYTES` / `PG_MAX_WINDOWS` for more
  coverage at higher latency, or set `HUMAN_REVIEW_MODE=deny` +
  lower `SCAN_MAX_PAYLOAD_BYTES` for a stricter posture.
- **Multi-chunk split attacks.** An injection split across a window boundary
  may score below threshold in both halves (the 64-token stride mitigates
  but does not eliminate this).
- **Non-text semantics.** Scanners see extracted text, not rendered meaning —
  a payload that is only dangerous after the agent *acts* on it is the
  [Invariant rules](invariant-rules.md) layer's job, not the content
  scanners'.
- **Redaction coverage.** Redaction runs on the full untruncated payload but
  is skipped entirely beyond `REDACTION_MAX_BYTES` (256KiB) — flagged
  `redaction_skipped=size`. Block-grade secrets in such payloads are still
  caught by the scanner windows; only best-effort masking of ALLOW-grade PII
  is skipped.

**Audit-driven detection:** alert on `truncated=true` and
`scanned_bytes << total_bytes` instead of assuming full coverage (see
[Metrics](../operations/metrics.md)).
