# Redaction (mutation pipeline)

The `RedactionScanner` (`guardrails/redaction.py`) is the mutation-producing
stage. Unlike the content scanners it returns no verdict — it is a pure
**transformer** that rewrites secret/PII material in otherwise-allowed
payloads, replacing each match with a fixed `[REDACTED:<TYPE>]` placeholder.
The rewritten payload is forwarded via the proto `mutated` oneof.

Redaction runs only when no scanner `BLOCK`ed the exchange (a BLOCK always
wins). It is the defence-in-depth layer for material scanners deliberately do
not hard-deny (emails are `ALLOW`, credit cards are review-pass by default),
plus a second chance to mask block-grade secrets when the regex scanner is
disabled.

## Structural replacement semantics

The engine applies redaction **structurally** (`redact_value`): it walks the
params / result JSON tree and rewrites only *string values*, so the mutated
payload is guaranteed valid JSON with the same shape as the original:

- Mappings and sequences are rebuilt only when something changed; scalars
  pass through untouched.
- Substitutions are counted and reported; the count lands in metrics
  (`mcp.guardrails.redactions`) and the decision metadata.

**Known limitations (deliberate):**

- **Mapping keys are not redacted** — only values. Rewriting keys could
  collide or break downstream lookups.
- **Tuples become lists** — sequences are rebuilt as `list` (correct for
  JSON-shaped payloads).
- **String-encoded `params.arguments`** (some MCP clients encode arguments as
  a JSON *string*) are redacted as plain text; an unquoted numeric secret
  inside them can invalidate the *inner* JSON document. The outer payload
  stays valid. Such deployments should rely on the RegexScanner verdict.
- **The PEM-header fallback is best-effort** — it masks a truncated
  private-key block; with the RegexScanner enabled, any BEGIN marker is
  already BLOCKed upstream, so this path only fires when the regex scanner
  is disabled.

## Default redaction set

From `default_redaction_patterns()`, most-specific first:

| Pattern | Replaces | Placeholder |
| --- | --- | --- |
| `private_key` (block) | Full PEM block (BEGIN…END, any of RSA/EC/OPENSSH/DSA/none) | `[REDACTED:PRIVATE_KEY]` |
| `private_key` (header) | Truncated PEM block (BEGIN marker only) | `[REDACTED:PRIVATE_KEY]` |
| `aws_access_key` | `AKIA…` | `[REDACTED:AWS_ACCESS_KEY]` |
| `aws_temp_key` | `ASIA…` | `[REDACTED:AWS_TEMP_KEY]` |
| `google_api_key` | `AIza…` | `[REDACTED:GOOGLE_API_KEY]` |
| `github_pat` | `gh[pousr]_…` | `[REDACTED:GITHUB_PAT]` |
| `gitlab_pat` | `glpat-…` | `[REDACTED:GITLAB_PAT]` |
| `slack_token` | `xox[baprs]-…` | `[REDACTED:SLACK_TOKEN]` |
| `llm_api_key` | `sk-…` (≥20 chars) | `[REDACTED:LLM_API_KEY]` |
| `email` | Email addresses | `[REDACTED:EMAIL]` |
| `credit_card` | 13–16 digit card-shaped numbers | `[REDACTED:CREDIT_CARD]` |

Patterns unsuitable for substitution are deliberately excluded and remain
scanner verdicts: `hidden_ascii` (no meaningful replacement for a zero-width
character) and the review-grade shapes (`key_value_credential`,
`high_entropy_blob`, `connection_string`, `jwt`) which are too
false-positive-prone to rewrite blindly on the wire path.

The **egress set** (`egress_redaction_patterns()`, used only for the
[AgentAlignment](agent-alignment.md) external LLM call) adds `jwt`,
`connection_string` and `key_value_credential` on top of the default set —
exactly the shapes whose review verdict feeds the second-stage gate.

## Behaviour knobs

| Env var | Default | Effect |
| --- | --- | --- |
| `ENABLE_REDACTION` | `true` | Master switch. |
| `REDACT_ON_REVIEW` | `true` | `HUMAN_REVIEW` payloads are *also* redacted: the review verdict is kept (pass+warn or deny per `HUMAN_REVIEW_MODE`) and the mutated payload rides along, so review-grade PII is masked instead of passing verbatim. Under `failOpen` this means a scanner exception no longer forwards secrets in cleartext. `false` restores the legacy pass-unmutated behaviour. |
| `REDACT_REQUEST_PARAMS` | `false` | Request-side opt-in. Off by default: a secret in tool-call params is a signal to BLOCK (the RegexScanner already does), not to silently rewrite the caller's request. Enable only where rewritten arguments are deliberately tolerated. |
| `REDACTION_MAX_BYTES` | `262144` (256KiB) | Payload byte cap for the redaction sweep (~11 regexes over the *untruncated* payload). Over-cap payloads skip redaction, pass unchanged, and are flagged `redaction_skipped=size` in the audit span. Safe trade-off: block-grade secrets in over-cap payloads are still denied by the RegexScanner's head/mid/tail windows; only best-effort masking of ALLOW-grade PII is skipped. |

The redaction sweep is offloaded to a worker thread (`asyncio.to_thread`) so
it never stalls the event loop.

## Upgrade note

With redaction enabled, the decisions counter and audit `outcome` field gain
an `outcome="mutated"` value. Dashboards/alerts counting "successful"
decisions as `outcome="allow"` should be widened to `outcome=~"allow|mutated"`.
