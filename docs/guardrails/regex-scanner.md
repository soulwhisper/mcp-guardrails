# Regex scanner

The `RegexScanner` (`guardrails/scanners.py`) is the deterministic pattern
layer — hidden ASCII, instruction-format markers, secrets and PII. It has zero
ML dependencies and runs on both the request side (`tools/call` params) and
the response side (tool output / tool descriptions).

## Matching model

**First-match wins.** Patterns are evaluated in list order, so the built-in
list is a priority chain: `BLOCK` patterns first, then `HUMAN_REVIEW`, then
`ALLOW`. A single scan returns at most one result per pass.

**Two-pass matching.** Pass 1 evaluates every pattern against the *original*
text. Unless pass 1 already produced a `BLOCK` (the strongest verdict) or the
text is pure ASCII, pass 2 re-evaluates every pattern against a
detection-only **normalized view** of the text, and the more severe of the
two hits wins. The severity comparison closes a downgrade evasion: an
attacker cannot neutralise an obfuscated `BLOCK` marker by adding a benign
string that trips a low-grade pass-1 pattern.

### Normalized view

`normalized_view(text)` is a **matching-only** transform — it never rewrites
the payload (redaction, forwarding and `payload_sha256` all operate on the
original text):

1. **NFKC fold** — collapses full-width forms, compatibility ligatures,
   circled/squared letters, etc.
2. **Cf strip** — removes Unicode format characters (category Cf): zero-width
   spaces/joiners, bidi controls, soft hyphens, word joiners.
3. **Homoglyph fold** — maps common Cyrillic and Greek lookalikes of ASCII
   letters (e.g. Cyrillic `Ѕ`/`Ε`/`Μ` in a `### SYSTEM` marker) to their ASCII
   equivalents. The map is deliberately limited to unambiguous lookalikes, not
   a full Unicode confusables table.

Pass 2 is skipped when it cannot change the verdict: pass 1 already `BLOCK`ed,
the text is pure ASCII (the view is provably identical), or the computed view
equals the original. A normalized-view hit's audit reason is suffixed
`[normalized-view match]` and fingerprints the *original* chunk
(`orig_sha256` / `orig_hmac`); `match_len` is the match length in the view.

## Built-in pattern set

From `default_patterns()` in `guardrails/scanners.py`, in evaluation order:

| # | Name | Outcome | Detects | Example shape | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | `hidden_ascii` | BLOCK | Control characters (except tab/newline/CR), Unicode control pictures, RTL overrides, zero-width chars used to hide instructions | `\x00`–`\x1f`, U+200B–U+200F, U+202A–U+202E, U+2060–U+206F, U+FEFF | Score 0.9. Hidden-instruction carrier. |
| 2 | `format_injection` | BLOCK | ChatML / instruction-format tokens used to escape the conversation role | `[SYSTEM]`, `[INST]`, `[/INST]`, `[ASSISTANT]`, `<|im_start|>`, `<|im_end|>`, `<|endoftext|>`, `### system/instruction/override/ignore` | Score 0.98. **Case-insensitive** (`re.IGNORECASE`) — casing variants like `### System` or `<|IM_START|>` still hit. PromptGuard-2 (trained on the Llama tokenizer) does not recognise ChatML tokens, so this is the deterministic backstop. |
| 3 | `private_key` | BLOCK | PEM private key material | `-----BEGIN (RSA|EC|OPENSSH|DSA)? PRIVATE KEY-----` | Score 0.99. |
| 4 | `aws_access_key` | BLOCK | AWS access key id | `AKIA[0-9A-Z]{16}` | Score 0.95. |
| 5 | `aws_temp_key` | BLOCK | AWS temporary security credential (STS / IAM role) | `ASIA[0-9A-Z]{16}` | Score 0.95. |
| 6 | `google_api_key` | BLOCK | Google API key | `AIza` + 35 chars (39 total) | Score 0.95. |
| 7 | `github_pat` | BLOCK | GitHub personal access token | `gh[pousr]_` + ≥36 chars | Score 0.95. |
| 8 | `gitlab_pat` | BLOCK | GitLab personal access token | `glpat-` + 20 chars | Score 0.95. |
| 9 | `slack_token` | BLOCK | Slack token | `xox[baprs]-` + ≥10 chars | Score 0.95. |
| 10 | `llm_api_key` | BLOCK | OpenAI / Anthropic / common LLM API keys — `sk-<key>`, `sk-proj-`, `sk-svcacct-`, `sk-ant-api03-` | `sk-` + ≥20 chars | Score 0.95. The ≥20-char requirement avoids false positives. |
| 11 | `jwt` | HUMAN_REVIEW | JSON Web Token (three base64url segments, header starts `eyJ`) | `eyJ….….` (signature ≥4 chars) | Score 0.80. Review grade — JWTs appear in benign contexts too. |
| 12 | `connection_string` | HUMAN_REVIEW | Connection strings with embedded credentials | `mongodb(+srv)://…`, `postgres(ql)://…`, `mysql://…`, `redis://…`, `amqp(s)://…` (≥10 chars after scheme) | Score 0.75. Low-entropy fingerprint tier: audit records `match_len` only (no digest) because the match embeds the password itself. |
| 13 | `key_value_credential` | HUMAN_REVIEW | Inline `key=value` credentials | `password=…`, `passwd:`, `secret=`, `token=`, `api_key=`, `access-key:`, `private_key=`, `bearer=` + ≥8 chars | Score 0.70. Review grade because "password"/"secret" appear in benign docs and code. Low-entropy tier (length only). |
| 14 | `md_image_exfil` | HUMAN_REVIEW | Markdown image exfiltration: `![alt](https://host/path?k=<value>)` with a single query value of ≥32 chars from a base64/url-ish alphabet | `![x](https://evil.example/i.png?d=QUJD…≥32)` | Score 0.65. Review grade, not BLOCK: signed CDN image URLs with long token params (`?sig=…`, `?token=…`) are a legitimate false-positive source. Pure-exfil payloads usually also trip `high_entropy_blob` or a key pattern, which still BLOCKs. |
| 15 | `high_entropy_blob` | HUMAN_REVIEW | Generic high-entropy blob (possible secret) | `[A-Za-z0-9+/]{40,}={0,2}` | Score 0.60. |
| 16 | `credit_card` | HUMAN_REVIEW | Possible credit-card number | 13–16 digits with optional spaces/dashes | Score 0.70. Low-entropy tier: length only, so the audit log is not an offline enumeration oracle. |
| 17 | `email` | ALLOW | Email address (PII — redact downstream) | `user@example.com` | Score 0.20. ALLOW verdict; masking is the [redaction stage](redaction.md)'s job. Low-entropy tier. |

## Audit fingerprints

Scanner reasons never embed raw match text (they are copied verbatim into
audit logs and OTel spans). Each reason carries a non-reversible fingerprint:

- **High-entropy patterns** (tokens, keys): `match_len` plus a 12-hex-char
  digest — HMAC-SHA256 keyed with `AUDIT_HMAC_KEY` when set (recommended), or
  plain SHA-256 otherwise.
- **Low-entropy patterns** (`email`, `credit_card`, `connection_string`,
  `key_value_credential`): `match_len` only, no digest — a plain hash of a
  brute-forceable value would make the audit log an offline enumeration
  oracle.

## Configuration

| Knob | Default | Effect |
| --- | --- | --- |
| `ENABLE_REGEX_SCANNER` | `true` | Master switch for the scanner. |
| `MAX_CONTENT_BYTES` | `32768` | Head window fed to the scanner (see [Scan coverage](scan-coverage.md)). |
| `SCAN_TAIL_BYTES` | `8192` | Mid/tail windows on over-budget payloads. |

Custom pattern lists can be injected by constructing `RegexScanner(patterns=[...])`
with your own `Pattern(name, regex, outcome, reason, score)` entries —
remember the list is a priority chain (first match wins).
