# Agent alignment (second-stage LLM)

The `AgentAlignmentScanner` (`guardrails/scanners.py`) is an **opt-in,
LLM-based second stage** that deep-inspects responses the first stage was
unsure about. It is adapted from LlamaFirewall's `AlignmentCheckScanner`: an
external LLM judges whether the agent's current action has diverged from the
user's original intent — the signature of a successful indirect prompt
injection.

## Trigger condition (gating)

Running an LLM on every response would dominate sidecar latency and homelab
cost, so the scanner is:

1. **Off by default** — enable with `ENABLE_AGENT_ALIGNMENT=1`.
2. **Gated** — the engine only invokes it when a first-stage scanner
   (PromptGuard) flags a response `HUMAN_REVIEW`, i.e. a score in the
   `[PG_REVIEW_THRESHOLD, LF_PROMPTGUARD_BLOCK_THRESHOLD)` grey zone
   (default `[0.5, 0.9)`). Clean and hard-blocked exchanges never pay for an
   LLM call.

The LLM returns a JSON verdict `{"observation", "thought", "conclusion"}`;
`conclusion: true` maps to `BLOCK` (score 0.95), `false` to `ALLOW`, and
unparseable output conservatively maps to `HUMAN_REVIEW` (resolved per
`HUMAN_REVIEW_MODE`). A missing API key or an LLM API failure also yields
`HUMAN_REVIEW` (fail-soft) — the reason records only the exception *type*,
never SDK text that could embed request content or credentials.

## Egress safety

The scanned content is attacker-influenced, so two protections apply before
anything leaves the process:

- **Pre-egress redaction.** The flagged chunk is masked with an **extended**
  `RedactionScanner` pattern set — the full block-grade secret/PII set
  **plus** the review-grade credential shapes (JWT, connection strings,
  key=value credentials) whose `HUMAN_REVIEW` verdict is exactly what feeds
  this gate. Cleartext credentials never reach the external LLM. This is
  masking, not a verdict — the alignment decision itself is unaffected.
  (On the wire path these review-grade shapes are too false-positive-prone
  to rewrite blindly; on the egress path a false positive merely degrades one
  alignment prompt.)
- **Audit discipline (A-P0-2).** The LLM's free-text `observation` is derived
  from attacker-influenced content and is **never written to the audit log**;
  the recorded reason carries the verdict plus a length-only fingerprint.
  The same applies to unparseable LLM output.

## Trajectory context

The engine folds a **metadata-only trace summary** — the last 5 tool-call
names from the Invariant trace, no arguments, no payload — into the prompt,
so the LLM judges the flagged chunk against the agent's recent behaviour
rather than in isolation. That is where cross-call injections become visible.

## Data egress statement

Enabling AgentAlignment means (redacted) user content is processed by an
external LLM provider under **their** terms and retention policy — a
cross-border / third-party data transfer. If your compliance scope forbids
that, leave `ENABLE_AGENT_ALIGNMENT=0` (the default): `HUMAN_REVIEW`
outcomes are then resolved locally per `HUMAN_REVIEW_MODE`. See
[Compliance](../compliance.md) for the full statement.

## Configuration

Any OpenAI-compatible API works (Together AI, OpenAI, Azure, vLLM, Ollama).

| Env var | Default | Description |
| --- | --- | --- |
| `ENABLE_AGENT_ALIGNMENT` | `false` | Enable the second-stage gate. |
| `LF_ALIGNMENT_MODEL` | `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8` | LLM model name (default: Llama-4-Maverick hosted by Together AI). |
| `LF_ALIGNMENT_API_BASE` | `https://api.together.xyz/v1` | OpenAI-compatible API base URL. |
| `LF_ALIGNMENT_API_KEY` | _(unset)_ | Provider API key; the scanner reads it directly from this env var. Required when enabled. |

The `openai` package is imported lazily — it is only needed when the feature
is enabled. Calls run at `temperature=0.0`, `max_tokens=512`, with content
truncated to the first 4000 characters (the LLM only needs the head of the
chunk to assess compromise), bridged to a worker thread so the event loop is
never blocked.

```bash
# Example: enable with OpenAI instead of the default Together AI
docker run --rm -p 9001:9001 \
  -e ENABLE_AGENT_ALIGNMENT=1 \
  -e LF_ALIGNMENT_MODEL=gpt-4o \
  -e LF_ALIGNMENT_API_BASE=https://api.openai.com/v1 \
  -e LF_ALIGNMENT_API_KEY=sk-xxx \
  ghcr.io/soulwhisper/mcp-guardrails:0.4.0
```
