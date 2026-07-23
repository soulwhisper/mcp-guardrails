# MCP Guardrails

An **agentgateway ExtMcp guardrail sidecar** that wraps an ONNX-based
PromptGuard-2 scanner (prompt-injection detection via the ONNX
[gravitee-io/Llama-Prompt-Guard-2-86M-onnx] model, Llama 4 Community
License) and an Invariant Guardrails-style rule engine (cross-call
toxic-flow / loop detection) behind the agentgateway ExtMcp gRPC contract.
The sidecar is **fail-closed by default**, listens on plaintext HTTP/2 (`h2c`) gRPC on `:9001`, and is driven
by agentgateway's `mcp-guardrails` processor on both sides of every MCP
exchange — request params scanned as the `TOOL` role, tool output scanned as
the `ASSISTANT` role (the indirect-injection frontline), with optional
cost-bounded AgentAlignment LLM as a second stage gated on first-stage
`HUMAN_REVIEW`.

---

## Table of contents

- [Architecture](#architecture)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Rule packs](#rule-packs)
- [Deployment](#deployment)
- [Testing](#testing)
- [Project scope and trust assumptions](#project-scope-and-trust-assumptions)
- [Security model and failure modes](#security-model-and-failure-modes)
- [Project layout](#project-layout)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Architecture

```mermaid
sequenceDiagram
    autonumber
    participant Agent as MCP Agent (LLM)
    participant GW as agentgateway
    participant Sidecar as ExtMcp Guardrail (sidecar)
    participant PG as PromptGuard ONNX
    participant INV as Invariant Engine
    participant MCP as Upstream MCP Server

    Agent->>GW: tools/call (JSON-RPC)
    GW->>Sidecar: CheckRequest(McpRequest)
    Sidecar->>PG: scan(params, role=TOOL)
    Sidecar->>INV: record(tool, args) + evaluate()
    PG-->>Sidecar: ScanDecision
    INV-->>Sidecar: ScanResult
    Sidecar-->>GW: McpRequestResult{pass|mutated|error}
    alt allowed / mutated
        GW->>MCP: forward JSON-RPC
        MCP-->>GW: result
        GW->>Sidecar: CheckResponse(McpResponse)
        Sidecar->>PG: scan(result, role=ASSISTANT)
        PG-->>Sidecar: ScanDecision
        Sidecar-->>GW: McpResponseResult{pass|mutated|error}
        alt allowed / mutated
            GW-->>Agent: result
        else error
            GW-->>Agent: JSON-RPC -32001
        end
    else error
        GW-->>Agent: JSON-RPC -32001
    end
```

Container-internal flow (every gRPC call traverses this pipeline):

```mermaid
flowchart TD
    subgraph Server
        GRPC[grpc.aio server<br/>:9001 h2c]
        SVC[ExtMcpServicer<br/>CheckRequest / CheckResponse]
        GRPC --> SVC
        SVC --> ENG[GuardrailEngine]
    end

    subgraph Engine
        ENG --> EXT["extract_text + scan_windows (head/mid/tail)"]
        EXT --> RX[RegexScanner<br/>hidden-ascii / PII / secrets]
        EXT --> PG[OnnxPromptGuardScanner<br/>PromptGuard-2]
        EXT --> INV[InvariantEngine<br/>trace record + evaluate]
        RX --> AGG
        PG --> AGG
        INV --> AGG
        AGG[DecisionAggregator<br/>fail-closed]
    end

    subgraph Response-only
        AGG -. second stage .-> AA[AgentAlignment<br/>only when first stage<br/>flagged HUMAN_REVIEW]
    end

    AGG --> DEC[Decision]
    DEC --> SVC
    SVC --> GRPC
```

## How it works

agentgateway invokes the sidecar twice per MCP exchange through the
`ExtMcp` gRPC service:

| RPC             | When agentgateway calls it                          | Sidecar's job                                                                 |
| --------------- | --------------------------------------------------- | ----------------------------------------------------------------------------- |
| `CheckRequest`  | Before forwarding the agent's request upstream      | Scan params as `TOOL` role; record + evaluate the toxic-flow trace            |
| `CheckResponse` | Before returning the upstream response to the agent | Scan tool output / tool descriptions as `ASSISTANT` role (indirect injection) |

Both RPCs return one of three states via a protobuf `oneof`:

- **`pass` (`Pass`)** — forward the payload unchanged.
- **`mutated` (`bytes`)** — replace the payload with the supplied raw JSON
  bytes. Emitted by the redaction stage (see
  [Response-side redaction](#response-side-redaction-mutation)) when it masks
  secrets/PII in an otherwise-allowed payload.
- **`error` (`AuthorizationError`)** — deny. agentgateway surfaces this to
  the agent as a JSON-RPC error.

> **Upstream contract note.** `proto/ext_mcp.proto` is vendored from
> `agentgateway/agentgateway` (`crates/protos/proto/ext_mcp.proto`). The
> "forward unchanged" oneof member is named `pass`; the Python servicer sets
> it via `getattr(result, "pass")` because `pass` is a Python keyword. See
> [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full proto contract.

### Fail-closed by default

`FAILURE_MODE=failClosed` is the only safe default for write-capable agents.
When a scanner raises or exceeds `SCANNER_TIMEOUT_MS`, the sidecar translates
the exception to a `BLOCK` outcome, the aggregator denies the exchange, and
agentgateway returns `-32001`. Switch to `failOpen` only for read-only agents
where a guardrail outage is judged less harmful than blocking the agent.

### Request-side double duty

On `CheckRequest` for `tools/call`, the engine does two things in parallel:

1. **Semantic scan**: extracts text from the JSON-RPC `params` object
   (`extract_text`), truncates to `MAX_CONTENT_BYTES` on a UTF-8 boundary,
   then runs the configured content scanners (`RegexScanner` for hidden
   ASCII / PII / secrets, `OnnxPromptGuardScanner` for PromptGuard-2)
   against the text with role `TOOL`.
2. **Invariant trace**: appends `(tool, args, ts)` to a bounded sliding
   window (`INVARIANT_WINDOW` calls, default 256) and evaluates every rule
   (`ToxicFlowRule`, `LoopRule`, `RateLimitRule`, `AggregateRule`) against
   the resulting trace. First-match wins.

A `BLOCK` from either path is fail-closed by the `DecisionAggregator`; the
decision maps to the `error` oneof on the wire.

### Response-side indirect-injection defense

On `CheckResponse`, the engine scans the upstream's result text
(`content[].text` from `tools/call`, `tools[].description` from `tools/list`,
prompt bodies from `prompts/get`, etc.) as the `ASSISTANT` role. This is the
**primary defence against indirect prompt injection**: a tool that returns
attacker-controlled text (a web page, a file, a database row) is exactly
where instructions-to-the-LLM sneak back into the agent's context.

### Response-side redaction (mutation)

When every content scanner ALLOWs a response, the redaction stage
structurally rewrites secret/PII material in the result (e.g. emails,
credit cards, API tokens that scanners deliberately do not hard-deny),
replacing each match with a `[REDACTED:<TYPE>]` placeholder and returning
the rewritten payload via the `mutated` oneof. A BLOCK always wins.
`HUMAN_REVIEW` payloads are **also redacted by default**
(`REDACT_ON_REVIEW=1`): the review verdict is preserved (pass+warn or deny
per `HUMAN_REVIEW_MODE`, recorded in the audit log) and the mutated payload
rides along via the `mutated` oneof, so review-grade PII/credentials are
masked instead of passing through verbatim — under `failOpen` that means a
scanner exception (HUMAN_REVIEW) no longer forwards secrets in cleartext.
Set `REDACT_ON_REVIEW=0` to restore the legacy behaviour (review payloads
pass unmutated; see
[Security model and failure modes](#security-model-and-failure-modes)).
Request-side redaction of `params.arguments` is opt-in
(`REDACT_REQUEST_PARAMS`).

Redaction runs the full regex sweep over the *untruncated* payload, so two
guards keep it off the request hot path: the sweep is offloaded to a worker
thread (`asyncio.to_thread`, no event-loop stall), and payloads larger than
`REDACTION_MAX_BYTES` (default 256KiB) skip redaction entirely — they pass
through unchanged with `redaction_skipped=size` in the audit span. This is
a safe trade-off, not a blocking gap: over-cap payloads are still scanned
by the RegexScanner head/mid/tail `scan_windows`, so block-grade secrets
(private keys, tokens) are BLOCKed upstream; only best-effort masking of
ALLOW-grade PII (emails, credit cards) is skipped.

### Optional AgentAlignment second stage

`AgentAlignment` is LLM-based (~300-800ms per call). Running it on every
response would dominate sidecar latency and homelab cost, so it is **opt-in**
(`ENABLE_AGENT_ALIGNMENT=1`) and **gated**: the engine only invokes the
second-stage alignment check when a first-stage scanner (PromptGuard) flags
the response as `HUMAN_REVIEW`. This bounds the alignment cost to suspicious
responses only — the cost-control knob from the original design.

Two egress-safety / quality measures apply to the second-stage call:

- **Pre-egress redaction** — the flagged chunk is masked with the standard
  `RedactionScanner` patterns (`[REDACTED:<TYPE>]` placeholders) BEFORE it
  leaves for the external LLM, so review-grade secrets/PII never reach the
  LLM provider in cleartext.
- **Trajectory context** — the engine folds the last 5 tool-call names from
  the Invariant trace (metadata only, no args) into the prompt, so the LLM
  judges the flagged chunk against the agent's recent behaviour.

The grey zone that feeds this gate is tunable: PromptGuard scores in
`[PG_REVIEW_THRESHOLD, LF_PROMPTGUARD_BLOCK_THRESHOLD)` (default `[0.5, 0.9)`)
flag `HUMAN_REVIEW` instead of ALLOW.

## Quick start

Prerequisites: Python 3.10+ and `pip`. The pure-Python policy core
(models, aggregator, invariant engine, regex scanner) runs without the ML
stack; the ONNX PromptGuard scanner is imported lazily.

```bash
# 1. Clone
git clone https://github.com/soulwhisper/mcp-guardrails.git
cd mcp-guardrails

# 2. Regenerate gRPC stubs (only needed if proto/ext_mcp.proto changes;
#    committed stubs are checked in so this is a no-op on a fresh clone).
make proto

# 3. Install dev/test deps (no torch / transformers — fast local iteration)
make dev

# 4. Run the unit suite (~0.3s)
make test

# 5. Build the container image
make docker

# 6. Run the server locally (regex-only; onnxruntime absent is graceful)
make run
```

### Docker one-liner

```bash
docker run --rm -p 9001:9001 \
  --env-file examples/docker-run.env \
  -v $(pwd)/examples/rules.policy:/etc/guardrails/rules.policy:ro \
  ghcr.io/soulwhisper/mcp-guardrails:0.3.4
```

Note: the head+tail `scan_windows` / per-route trace hardening and the
redaction pipeline (PRs #61 / #62) are merged into `main` but are **not**
included in the `0.3.4` image — wait for the next release or build locally
with `make docker`.

### PromptGuard-2 model (ONNX, Llama 4 Community License)

The `PROMPT_GUARD` scanner uses the ONNX model
[`gravitee-io/Llama-Prompt-Guard-2-86M-onnx`](https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-86M-onnx)
via ONNX Runtime (CPU inference). The model repo is public and non-gated,
but the **model weights are licensed under the Llama 4 Community License**
— users of the Docker image must comply with that license. See [NOTICE](NOTICE).

The `.onnx` graph is loaded with `onnxruntime` directly (no `optimum`,
no `torch`) — `onnxruntime` (~15MB) + `transformers` (tokenizer-only)
is the full ML dependency surface, so the image stays small (~600MB).

```bash
# Pre-baked model in the image — just run:
docker run --rm -p 9001:9001 \
  -e ENABLE_REGEX_SCANNER=1 \
  -e ENABLE_PROMPTGUARD=1 \
  ghcr.io/soulwhisper/mcp-guardrails:latest
```

> **HF_TOKEN recommended.** The model repo is public, but unauthenticated
> HF API calls from shared IPs (GHA runners, cloud VMs) may hit rate limits
> (HTTP 429). Set `HF_TOKEN` if downloading the model outside the pre-built
> Docker image.

#### AgentAlignment LLM (second-stage, opt-in)

When `ENABLE_AGENT_ALIGNMENT=1`, the `AgentAlignmentScanner` calls an external
LLM API to do a "second-stage" deep inspection whenever PromptGuard flags
`HUMAN_REVIEW`. The LLM endpoint is fully configurable via `LF_ALIGNMENT_*`
env vars — any OpenAI-compatible API works (OpenAI, Azure, Together AI, vLLM,
Ollama, etc.).

```bash
# Enable AgentAlignment with OpenAI instead of the default Together AI:
docker run --rm -p 9001:9001 \
  -e ENABLE_AGENT_ALIGNMENT=1 \
  -e LF_ALIGNMENT_MODEL=gpt-4o \
  -e LF_ALIGNMENT_API_BASE=https://api.openai.com/v1 \
  -e LF_ALIGNMENT_API_KEY=sk-xxx \
  ghcr.io/soulwhisper/mcp-guardrails:latest
```

| Env var                 | Default                                             | Description                                                                         |
| ----------------------- | --------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `LF_ALIGNMENT_MODEL`    | `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8` | LLM model name                                                                      |
| `LF_ALIGNMENT_API_BASE` | `https://api.together.xyz/v1`                       | LLM API base URL (OpenAI-compatible)                                                |
| `LF_ALIGNMENT_API_KEY`  | _(unset)_                                           | API key for the LLM provider. The scanner reads the key directly from this env var. |

#### Fallback: regex-only mode

If `onnxruntime`/`transformers` is not installed, the build still succeeds
(models stage skipped) and the sidecar boots in **regex-only mode** — the ONNX
scanner import fails gracefully and only the `RegexScanner` + `InvariantEngine`
are active. This is the default for CI (the test job doesn't install onnxruntime).

### Dry-run mode

`GUARDRAIL_DRY_RUN=1` swaps every real scanner for an allow-stub, so you can
verify wiring (agentgateway -> sidecar -> upstream) without loading any ML
models:

```bash
docker run --rm -p 9001:9001 \
  -e GUARDRAIL_DRY_RUN=1 \
  -e ENABLE_REGEX_SCANNER=0 \
  -e ENABLE_PROMPTGUARD=0 \
  ghcr.io/soulwhisper/mcp-guardrails:latest
```

### End-to-end smoke test

```bash
python3 tests/e2e_smoke.py
```

Boots a live server in a subprocess (regex-only) and exercises the full
ExtMcp gRPC surface: health check, `CheckRequest` allow + deny (hidden
Unicode), `CheckResponse` deny (private key), malformed-payload
`INVALID`.

## Configuration

Every knob is environment-variable driven so the same image serves dev,
homelab, and (with resource bumps) production. Defaults encode the
"single-user homelab" tradeoffs: PromptGuard always on, AgentAlignment
opt-in second stage, fail-closed, 32KiB content budget, 500ms scanner
deadline.

| Group          | Env var                          | Default                                  | Description                                                                                                                                    |
| -------------- | -------------------------------- | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Policy         | `FAILURE_MODE`                   | `failClosed`                             | `failClosed` denies on scanner failure/timeout (recommended for write-capable agents). `failOpen` allows with a review flag.                   |
| Policy         | `HUMAN_REVIEW_MODE`              | `pass`                                   | How `HUMAN_REVIEW` outcomes are resolved. `pass` forwards + emits an audit warning; `deny` escalates to a hard deny.                           |
| Scanners       | `MAX_CONTENT_BYTES`              | `32768`                                  | Max bytes of the head window fed to any scanner. Beyond this the payload is truncated (UTF-8-safe) and the decision is flagged `truncated=true` in audit. |
| Scanners       | `SCAN_TAIL_BYTES`                | `8192`                                   | Extra bytes scanned from the MID and TAIL of an over-budget payload, closing the truncation bypass (padding cannot hide an injection past the scanned head, nor between the head and tail windows). `0` disables. |
| Scanners       | `SCAN_MAX_PAYLOAD_BYTES`         | `1048576`                                | Hard payload cap (1MiB). Over-cap payloads are still scanned (head/mid/tail) AND flagged with a `payload_size` `HUMAN_REVIEW` (scanned/total bytes in the reason + audit `scanned_bytes`/`total_bytes` fields); `HUMAN_REVIEW_MODE` decides pass+warn vs deny. |
| Scanners       | `ENABLE_REGEX_SCANNER`           | `true`                                   | Deterministic pattern scanner (hidden ASCII / PII / secrets). Zero ML deps.                                                                    |
| Scanners       | `ENABLE_PROMPTGUARD`             | `true`                                   | ONNX PromptGuard semantic scanner. Falls back to regex-only if `onnxruntime`/`transformers` is absent.                                         |
| Scanners       | `ENABLE_AGENT_ALIGNMENT`         | `false`                                  | LLM-based AgentAlignment. Off by default; only triggered as a second stage when PromptGuard flags `HUMAN_REVIEW` on a response.                |
| Redaction      | `ENABLE_REDACTION`               | `true`                                   | Structural secret/PII redaction on allowed payloads (`[REDACTED:<TYPE>]` placeholders, forwarded via the `mutated` oneof). Runs whenever no scanner BLOCKs (see `REDACT_ON_REVIEW` for the review path). |
| Redaction      | `REDACT_ON_REVIEW`               | `true`                                   | Also redact `HUMAN_REVIEW` payloads: the review verdict is kept and the mutated payload rides along, so review-grade PII is masked instead of passing through verbatim. `false` restores the legacy pass-unmutated behaviour. |
| Redaction      | `REDACT_REQUEST_PARAMS`          | `false`                                  | Also redact inside `params.arguments` on the request side. Off by default — secrets in requests should BLOCK (RegexScanner), not be rewritten. |
| Redaction      | `REDACTION_MAX_BYTES`            | `262144`                                 | Payload byte cap for redaction (256KiB). Over-cap payloads skip redaction entirely and pass through unchanged with `redaction_skipped=size` in the audit span; they are still scanned by the head/mid/tail `scan_windows`. |
| PromptGuard    | `LF_ONNX_FILE`                   | `model.onnx`                             | Which `.onnx` file to load. Defaults to the full-precision `model.onnx`. |
| PromptGuard    | `LF_ONNX_MODEL`                  | `gravitee-io/...-onnx`                   | ONNX model repo ID. Public, non-gated; model weights under Llama 4 Community License (see NOTICE).                                          |
| PromptGuard    | `LF_PROMPTGUARD_BLOCK_THRESHOLD` | `0.9`                                    | Block threshold (0.0-1.0). PromptGuard score >= threshold -> BLOCK.                                                                            |
| PromptGuard    | `PG_MAX_WINDOWS`                 | `16`                                     | Cap on PromptGuard sliding-window inference per chunk. The window budget adapts to the payload's token length (`clamp(ceil(tokens/step)+1, 4, PG_MAX_WINDOWS)`); each extra window is one more 512-token inference, so this is the per-chunk latency bound. Raise for better long-payload coverage, lower for tighter P95. |
| PromptGuard    | `LF_ONNX_LOCAL_DIR`              | _(unset)_                                | Local directory of a pre-baked model (the container pre-downloads to `/models/hf/pg2`). When set and present, the tokenizer + `.onnx` load from disk — no HF hub access at runtime (air-gappable). Unset -> resolve via the HF hub cache (honouring `LF_ONNX_REVISION`). |
| PromptGuard    | `LF_ONNX_REVISION`               | `45a05fbd…`                              | Supply-chain pin: HF commit sha for runtime hub fetches (only used when `LF_ONNX_LOCAL_DIR` is unset). Matches the Dockerfile `PG2_REVISION` build-arg. Override together with `LF_ONNX_MODEL`. |
| PromptGuard    | `PG_REVIEW_THRESHOLD`            | `0.5`                                    | Review (grey-zone) threshold (0.0-1.0). Score >= `LF_PROMPTGUARD_BLOCK_THRESHOLD` -> BLOCK; score in `[PG_REVIEW_THRESHOLD, block)` -> `HUMAN_REVIEW` (routed to the second-stage AgentAlignment gate when enabled, else resolved per `HUMAN_REVIEW_MODE`); below -> ALLOW. Must be <= the block threshold. |
| AgentAlignment | `LF_ALIGNMENT_MODEL`             | `meta-llama/...-FP8`                     | LLM model name for AgentAlignment (only when `ENABLE_AGENT_ALIGNMENT=true`). Default: Llama-4-Maverick via Together AI.                        |
| AgentAlignment | `LF_ALIGNMENT_API_BASE`          | `https://api.together.xyz/v1`            | LLM API base URL (OpenAI-compatible). Override for OpenAI, Azure, vLLM, Ollama, etc.                                                           |
| AgentAlignment | `LF_ALIGNMENT_API_KEY`           | _(unset)_                                | API key for the LLM provider. The scanner reads the key directly from this env var. Only needed when `ENABLE_AGENT_ALIGNMENT=true`.            |
| HF cache       | `HF_HOME`                        | `/models/hf`                             | HuggingFace cache directory. Set in Dockerfile; the ONNX scanner loads the model from here.                                                    |
| Tokenizers     | `TOKENIZERS_PARALLELISM`         | _(unset)_                                | Set to `true` for parallel tokenization (the sidecar is single-process async, so unset is fine).                                               |
| Invariant      | `INVARIANT_WINDOW`               | `256`                                    | Sliding-window size for the cross-call toxic-flow trace. Covers long multi-step plans. Memory bound: window x `INVARIANT_ARGS_MAX_BYTES` (4KiB) x `INVARIANT_MAX_TRACES` (1024) ≈ 1GiB theoretical worst case; realistic entries are far below the per-entry cap, so the practical footprint is tens of MiB. |
| Invariant      | `INVARIANT_MAX_TRACES`           | `1024`                                   | Max distinct per-route trace windows (traces are isolated per route name / first service name). Oldest (LRU) tenant trace is evicted beyond this bound. |
| Invariant      | `INVARIANT_ARGS_MAX_BYTES`       | `4096`                                   | Per-entry args cap in the trace window: oversized args keep their structure with long string values truncated (matchers keep working); the loop fingerprint is computed from the full args. |
| Invariant      | `INVARIANT_TRACE_KEY_HEADERS`    | _(unset)_                                | Comma-separated request headers (case-insensitive, e.g. `x-session-id`) whose value extends the Invariant trace key (`route|header=value`) for per-session isolation. Missing header / unset -> legacy route-dimension key. See the multi-replica note below. |
| Invariant      | `INVARIANT_STICKY_TTL_S`         | `600`                                    | TTL (seconds) for sticky partial-match progress: ToxicFlowRule prefix matches survive sliding out of the trace window for this long. The sticky map is LRU-bounded like the trace map (`INVARIANT_MAX_TRACES`). |
| Policy         | `ALLOW_TOOLS`                    | _(unset)_                                | Comma-separated tool allowlist (`prefix/*` wildcards). Non-empty -> any tool not matching is denied before scanners run (audit `tool_acl`). |
| Policy         | `DENY_TOOLS`                     | _(unset)_                                | Comma-separated tool denylist (`prefix/*` wildcards). DENY wins over `ALLOW_TOOLS`. |
| Invariant      | `INVARIANT_RULES_PATH`           | _(unset)_                                | Filesystem path to a rule pack (`.py` / `.policy`). Hot-reloadable via `SIGHUP`. Takes precedence over `INVARIANT_RULES_MODULE`.               |
| Invariant      | `INVARIANT_RULES_MODULE`         | `guardrails.rules.default`               | Dotted Python module path to a rule pack. Used when `INVARIANT_RULES_PATH` is unset.                                                           |
| Timing         | `SCANNER_TIMEOUT_MS`             | `500`                                    | Per-scanner deadline in milliseconds. Exceeded -> treated per `FAILURE_MODE`. Keep sidecar < gateway so the sidecar decides first.             |
| Networking     | `LISTEN_ADDR`                    | `[::]:9001`                              | gRPC bind address. `127.0.0.1:9001` for loopback-only (e.g. sidecar-on-localhost).                                                             |
| Networking     | `SERVER_MAX_WORKERS`             | `8`                                      | `grpc.aio` ThreadPoolExecutor size. Each in-flight RPC occupies one worker; raise for high-concurrency deployments.                            |
| Networking     | `GRPC_MAX_RECV_BYTES`            | `8388608`                                | gRPC max receive/send message size (8MiB). Bounds memory per call.                                                                             |
| Networking     | `GRPC_MAX_CONCURRENT_RPCS`       | `128`                                    | Max in-flight RPCs (DoS bound); excess calls queue at the HTTP/2 layer.                                                                       |
| Networking     | `SHUTDOWN_DRAIN_S`               | `5.0`                                    | Graceful shutdown (A-P2-4): on SIGTERM/SIGINT the health service flips to `NOT_SERVING` first, then the sidecar waits this many seconds for readiness propagation before draining with `server.stop(grace)`. `0` skips the wait. |
| Observability  | `OTEL_EXPORTER_OTLP_ENDPOINT`    | _(unset)_                                | OTLP/gRPC endpoint (e.g. `http://otel-collector.observability.svc:4317`). When unset or OTel SDK absent, the sidecar degrades to audit-only.   |
| Observability  | `OTEL_SERVICE_NAME`              | `mcp-guardrails`                         | Service name reported on OTel spans/metrics.                                                                                                   |
| Observability  | `AUDIT_LOG_PATH`                 | _(unset)_                                | Append-only JSONL audit log path. `-` or unset -> stdout. Always on; survives OTel outages.                                                    |
| Observability  | `AUDIT_HMAC_KEY`                 | _(unset)_                                | When set, high-entropy match fingerprints in scanner reasons use keyed HMAC-SHA256 instead of plain SHA-256. Low-entropy patterns (email, credit card) always record length only (no digest) so the audit log cannot be used as an offline enumeration oracle. |
| Observability  | `AUDIT_CALLER_HEADERS`           | `x-forwarded-user`                       | Comma-separated whitelist of request headers (case-insensitive, first match wins) copied into the audit line's `caller` field. Only whitelisted headers ever reach the audit log. ⚠️ Think twice before adding `x-session-id`: a session id is a quasi-credential — persisting it to the durable audit log enables session hijacking from log access and cross-system correlation. |
| Observability  | `GUARDRAIL_VERSION`              | _(package version)_                      | Override for the `sidecar_version` field stamped on every audit line. Defaults to the package `__version__`.                                                                                |
| Observability  | `REVIEW_WEBHOOK_URL`             | _(unset)_                                | When set, every `human_review` decision POSTs a metadata-only JSON body (`outcome`/`reason`/`ref`/`exchange_id`/`ts`) to this URL. Fire-and-forget (background task, 2s timeout); failures only log and never block the decision path. |
| Health         | `UNHEALTHY_SCANNER_ERROR_RATE`   | `0.5`                                    | Sliding-window scanner error/timeout rate above which gRPC health flips to `NOT_SERVING` (recovers automatically). Tracked under `failOpen` too.                                            |
| Health         | `UNHEALTHY_SCANNER_WINDOW`       | `100`                                    | Number of recent scanner invocations kept in the health sliding window.                                                                                                                      |
| Health         | `UNHEALTHY_SCANNER_MIN_SAMPLES`  | `20`                                     | Minimum windowed invocations before the error-rate verdict applies (avoids flapping on the first few calls).                                                                                |
| Misc           | `GUARDRAIL_DRY_RUN`              | `false`                                  | Replace all real scanners with allow-stubs. Use to validate wiring without loading ML models.                                                  |
| Misc           | `LOG_LEVEL`                      | `INFO`                                   | Python logging level (`DEBUG` / `INFO` / `WARNING` / `ERROR`).                                                                                 |

> The table above is the source of truth for runtime configuration and is
> kept in sync with `guardrails/config.py`. (The two `INVARIANT_RULES_*`
> vars are resolved by `guardrails/rules/__init__.py`.)

> **Multi-replica note (Invariant traces).** Trace windows live in sidecar
> memory, so a toxic flow whose calls land on DIFFERENT replicas cannot be
> detected. For multi-replica deployments, have agentgateway inject a
> session header (e.g. `x-session-id`) and route stickily on it — set
> `INVARIANT_TRACE_KEY_HEADERS=x-session-id` so each session gets an
> isolated trace, and configure sticky/session-affinity routing on the
> agentgateway side (see the agentgateway docs:
> <https://agentgateway.dev/docs/>). Sticky routing itself is the
> deployer's responsibility; the sidecar only consumes the header.

> **Observability note for upgrades.** With redaction enabled, the
> `mcp.guardrails.decisions` counter (and the audit `outcome` field) gains a
> new `outcome="mutated"` value for exchanges forwarded with a rewritten
> payload. Dashboards or alerts that count "successful" decisions as
> `outcome="allow"` should be widened to `outcome=~"allow|mutated"`.

### Audit record (JSONL)

One JSON line per decision, always on. Key fields: `ts` (epoch
**seconds**, int) and `ts_ms` (epoch **milliseconds**, float), `phase`,
`method`, `tool`, `outcome`, `reason`, `ref` / `exchange_id` (two
independent correlation ids: `ref` is an engine-minted random uuid8 — the
wire deny reason's `ref` greps to this line; `exchange_id` is the
dataplane-supplied correlation id from `metadata_context` /
`x-request-id`, so the request- and response-side lines of one exchange
grep together. The attacker-controlled payload is never consulted for
either id), `caller` (whitelisted
header, see `AUDIT_CALLER_HEADERS`), `payload_sha256` (12-hex prefix of
the scanned text), `rules_version`, `sidecar_version`, `duration_ms`,
`truncated` / `scanned_bytes` / `total_bytes`, `route`, and the per-scanner
breakdown. Rule-pack reloads emit `{"event": "rules_reload", "ok": …}`
lines. Scanner reasons never embed raw matches or LLM output — matches use
`match_len` / `match_sha256|match_hmac` fingerprints, and AgentAlignment
verdicts record a length fingerprint only.

### Metrics

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, the following instruments are
exported (15s interval):

| Instrument | Type | Labels |
|---|---|---|
| `mcp.guardrails.decisions` | counter | `phase`, `outcome`, `method` |
| `mcp.guardrails.decision_duration_ms` | histogram (ms) | `phase`, `outcome` |
| `mcp.guardrails.scanner_results` | counter | `scanner`, `outcome` (incl. `error` / `timeout`) |
| `mcp.guardrails.redactions` | counter | — |
| `mcp.guardrails.invariant_hits` | counter | `rule` |
| `mcp.guardrails.rules_reload` | counter | `result` (`success` / `error`) |

**Label cardinality is deliberately low.** Labels are bounded enums only
(phase/outcome/method, configured scanner names, rule-pack rule names,
reload result). Per-exchange values — `ref` / `exchange_id`, tool names,
callers, payload hashes — must NEVER be added as metric labels; they
belong in the audit log only.

**Alerting suggestions:**

- `rate(mcp.guardrails.scanner_results{outcome=~"error|timeout"}[5m])` /
  `rate(mcp.guardrails.scanner_results[5m])` > `UNHEALTHY_SCANNER_ERROR_RATE`
  — scanner degradation (the gRPC health endpoint flips `NOT_SERVING` at
  the same threshold; alert on both).
- `increase(mcp.guardrails.rules_reload{result="error"}[15m])` > 0 — a
  SIGHUP rule reload failed; the previous pack is still active.
- `histogram_quantile(0.95, rate(mcp.guardrails.decision_duration_ms_bucket[5m]))`
  — decision latency regression watch.
- gRPC health `NOT_SERVING` after warmup — the Pod leaves Service
  endpoints; investigate scanner errors or a stuck model load.

## Rule packs

The Invariant rule layer is a plain Python module exposing a module-level
`RULES = [...]` list. Each entry is a `ToxicFlowRule` (an ordered
subsequence of tool calls within the trace window), a `LoopRule` (fires
when the same `(tool, args)` fingerprint repeats `threshold` times), a
`RateLimitRule` (per-tool sliding time-window call-rate limit), or an
`AggregateRule` (sliding time-window SUM of a numeric argument field).

### ToxicFlowRule vs LoopRule vs RateLimitRule vs AggregateRule

- **`ToxicFlowRule`** — _ordered subsequence_ matcher. Steps need not be
  contiguous in the trace; intervening calls are allowed. Use for
  "X then Y" exfiltration / escalation patterns
  (e.g. `inbox_read` -> `email_send` to an external recipient).
  A step with `negate=True` is a _negative guard_: it never advances the
  sequence, but any entry matching it while armed (between the surrounding
  positive steps) **voids** the in-progress match — including parked
  sticky progress — and matching restarts from step 0. Use for
  "A then C with no B between" (e.g. inbox read -> external send with no
  approval call in between).
- **`LoopRule`** — _fingerprint repetition_ matcher. The fingerprint is
  `tool + sorted_args_json`, so a parameterised search (args differ each
  call) does **not** fire — only an identical retry loop does. Use for
  prompt-injection retry storms hammering a denied tool.
- **`RateLimitRule`** — _sliding time-window rate limit_, counted **per
  tool name**: fires when one tool is called more than `max_calls` times
  within the trailing `window_s` seconds (uses the `ts` the engine stamps
  on every recorded call). Catches volumetric abuse with *varying* args
  (enumeration / spray) that LoopRule's identical-fingerprint check
  cannot see. The `"*"` matcher covers every tool without pooling them
  into one shared budget.
- **`AggregateRule`** — _sliding time-window budget_: sums
  `cast(args[field])` (dotted path) over matching calls within the
  trailing `window_s` and fires when the total exceeds `max_total`. Use
  for cumulative budgets — bytes exfiltrated, recipients contacted — where
  every single call stays under the per-call limits. The window is
  recomputed from entry timestamps on every evaluation, so contributions
  slide out exactly (no persistent accumulator to drift).

### Arg matchers and dotted paths

A `FlowStep` carries a `tool` matcher (exact string, regex string,
compiled `re.Pattern`, or callable) and an optional `args` mapping of
**dotted-path** -> value matcher:

```python
FlowStep(
    tool=re.compile(r"(http|curl|fetch).*post", re.IGNORECASE),
    args={
        # Dotted path: resolves args["request"]["url"] through nested
        # dict / list structures. Integer segments are list indices
        # (e.g. "recipients.0.address").
        "request.url": _EXTERNAL_URL,
        "request.method": re.compile(r"^(POST|PUT|PATCH)$", re.IGNORECASE),
    },
)
```

Value matchers follow the same regex-vs-literal heuristic as tool matchers
(strings containing regex meta-characters are compiled and `.search()`ed;
other strings use literal `==`; callables are invoked).

### Loading

Resolution order (first non-empty wins):

1. `INVARIANT_RULES_PATH=/etc/guardrails/rules.policy` — a Python file on
   disk. **Hot-reloadable via `SIGHUP`**: send `kill -HUP 1` (or the sidecar
   PID) and the `RulePack` swaps the active rule tuple atomically behind a
   `RLock`. In-flight evaluations see the old tuple to completion.
2. `INVARIANT_RULES_MODULE=my_org.rules.production` — a dotted Python import
   path. Useful for tests / bundled packs.
3. `guardrails.rules.default` — the bundled homelab starter pack.

See [`examples/rules.policy`](examples/rules.policy) for a richer, well-commented
pack covering nine patterns (inbox -> external email, secret-read -> HTTP
exfil, shell -> privileged k8s apply, db-dump -> external upload, file-read
-> webhook exfil, an unapproved-send flow using a `negate` guard step, a
`RateLimitRule` per-tool rate limit, an `AggregateRule` hourly read-volume
budget, and a `LoopRule` retry storm).

## Deployment

### Kubernetes

The `deploy/k8s/` directory contains manifests for a Deployment + Service +
ConfigMap rule pack + an `AgentgatewayPolicy` CRD wiring the sidecar into
agentgateway. Key points:

- **`appProtocol: kubernetes.io/h2c`** on the Service port is what tells
  agentgateway this is plaintext-HTTP/2 gRPC; the sidecar binds an insecure
  port (no TLS) because the gateway handles transport security.
- **ConfigMap rule pack**: mount the rule pack at
  `/etc/guardrails/rules.policy` and set
  `INVARIANT_RULES_PATH=/etc/guardrail/rules.policy`. Reload without
  restarting the Pod by `kill -HUP 1` inside the container (the SIGHUP
  handler in `server.py` swaps the rule tuple atomically).
- **`AgentgatewayPolicy` CRD**: wire `tools/call` to `Full` (Request +
  Response double gate — the indirect-injection frontline lives on the
  Response side). `tools/list`, `prompts/get`, `resources/read` to
  `Response`. `ping` / `initialize` to `None`.
- **`failureMode: FailClosed`**: the only safe default for write-capable
  agents. If the sidecar Pod is unreachable, agentgateway returns
  JSON-RPC `-32001` to the agent rather than forwarding unguarded.
- **Readiness probe**: the gRPC `grpc.health.v1` check goes `SERVING` only
  after the engine warms up (PromptGuard-2 model load). This keeps the Pod
  out of the Service endpoints during cold start.
- **Resources**: 2Gi memory budget covers onnxruntime CPU + PromptGuard-2-86M
  (~350MB weights). Bump to 4Gi for `ENABLE_AGENT_ALIGNMENT=1` (LLM-based
  alignment holds an extra model in memory).

See [`examples/agentgateway.standalone.yaml`](examples/agentgateway.standalone.yaml)
for a non-K8s, standalone agentgateway config pointing at `localhost:9001`,
and [`scripts/e2e_agentgateway.sh`](scripts/e2e_agentgateway.sh) for the
driver script that exercises it end-to-end against a real agentgateway
binary (both verified in practice).

## Testing

```bash
# Unit suite (~1.5s) — pure-Python policy core, no ML deps required
make test

# With coverage
make test-cov

# Lint
make lint

# Live end-to-end smoke (boots a real server in a subprocess)
python3 tests/e2e_smoke.py

# Real agentgateway interoperability e2e (optional; needs an agentgateway binary)
AGENTGATEWAY_BIN=/path/to/agentgateway ./scripts/e2e_agentgateway.sh

# Full field test with ONNX model (requires onnxruntime + model cache)
python3 tests/field_test.py

# Latency / throughput benchmark (ONNX model required)
python3 tests/load_test.py
```

The unit suite covers the aggregator (fail-closed table), invariant engine
(ordered subsequence matching, negate guards, LoopRule fingerprinting,
RateLimitRule / AggregateRule time windows, dotted-path resolution),
scanners (regex patterns, PromptGuard grey-zone thresholds, AgentAlignment
pre-egress redaction, truncation, `extract_text` hidden Unicode
preservation), the engine (timeout / exception handling, second-stage
gating, HUMAN_REVIEW webhook notification), the gRPC servicer (in-process
round-trip + wire mapping), the rule loader, the graceful-shutdown drain
ordering, the `guardrail_ctl` operator CLI, hypothesis property tests over
`scan_windows` / `extract_text` / `_safe_json_loads` / `redact_value`
(`tests/test_property.py`, skips gracefully when hypothesis is absent), and
a red-team capability baseline (`tests/test_redteam.py`, with
xfail-marked residual gaps). The e2e smoke boots a live server, exercises health +
`CheckRequest` (allow + deny on hidden Unicode) + `CheckResponse` (deny on
private key) + malformed `INVALID`, and exits non-zero on any
mismatch.

All 320+ unit tests (including the hypothesis property tests and the
red-team capability baseline, with 2
xfail-marked residual gaps) and the e2e smoke are green on a fresh clone.

### Real agentgateway interoperability e2e

`scripts/e2e_agentgateway.sh` stands up the full production topology against
a **real agentgateway binary** (verified with v1.3.1, standalone YAML):

```
client(curl) -> agentgateway :3000 (mcpGuardrails processor, failClosed)
             -> ExtMcp sidecar gRPC :9001 (ENABLE_PROMPTGUARD=0, regex-only)
             -> stdio MCP upstream (examples/mcp_pii_upstream.py)
```

Prerequisites: `python3` with `-r requirements.txt` installed (no ONNX model
download needed — the script runs the sidecar with `ENABLE_PROMPTGUARD=0`), a
python interpreter with the `mcp` package for the stdio upstream
(`UPSTREAM_PYTHON`, defaults to `python3`), and an agentgateway binary via
`AGENTGATEWAY_BIN` or `PATH`. If no binary is found the script prints a skip
notice and exits 0, so CI can wire it in as an optional job.

The script drives the official Streamable-HTTP MCP handshake
(`initialize` -> `mcp-session-id` -> `notifications/initialized`) and asserts:

| Case | Expected |
|---|---|
| `tools/call echo` (benign) | pass-through, echo returned |
| `tools/call pii_leak` | response **mutated**: `jdoe@example.com` -> `[REDACTED:EMAIL]` |
| `tools/call echo` with `-----BEGIN RSA PRIVATE KEY-----` arg | deny, JSON-RPC `-32001` |
| same tool+args x4 | 3rd+ call denied (`invariant:denied-tool-retry-loop`) |
| sidecar killed, then `tools/call` | failClosed: JSON-RPC `-32603` |
| sidecar audit log | `outcome="mutated"` / `outcome="deny"` JSONL lines |

The gateway config it consumes is
[`examples/agentgateway.standalone.yaml`](examples/agentgateway.standalone.yaml)
(the `binds`/`mcpGuardrails` schema; `@PLACEHOLDER@` tokens are substituted by
the script). All processes are cleaned up by PID on exit.

### ONNX model class layout

The `gravitee-io/Llama-Prompt-Guard-2-86M-onnx` export produces a **2-class**
model `[benign, malicious]`.  The code always takes the **last** class
as the block score.

### Latency (CPU, single client)

| Operation | Mean | P50 | P90 | P99 |
|---|---|---|---|---|
| CheckRequest (minimal) | 35.9ms | 34.3ms | 44.7ms | 64.1ms |
| CheckRequest (content) | 43.5ms | 42.6ms | 51.1ms | 58.4ms |
| CheckResponse (content) | 36.1ms | 35.2ms | 41.7ms | 61.4ms |

Measured on NixOS, Python 3.13, ONNX Runtime 1.27 CPU, PromptGuard-2-86M
full-precision ONNX (~1.1GB).  First inference cold-start is ~8-10s (model
load); the readiness probe absorbs this.

CI runs the unit suite with coverage on every push/PR. The coverage
percentage is published as a [job summary](https://github.com/soulwhisper/mcp-guardrails/actions/workflows/ci.yml)
markdown table.

## Project scope and trust assumptions

This project is a **pure guardrail**: detection, blocking/mutation verdicts,
and audit. Deliberately out of scope:

* **Rewriting / normalisation policies** (canonicalisation, paraphrasing,
  content transformation as a policy primitive) are the job of other
  agentgateway modules. The one exception is the existing **redaction**
  capability, which masks secrets/PII in otherwise-forwarded payloads.
* **Network isolation is the deployer's responsibility.** The sidecar binds
  plaintext h2c on `:9001` with no authentication of its own; protecting the
  gateway↔sidecar path (Kubernetes `NetworkPolicy`, mTLS via a service mesh,
  namespace segmentation) belongs to the platform, not this repo.

Trust assumption that follows from the above: **without network isolation,
any workload in the same cluster can talk to the sidecar directly** —
bypassing the gateway, replaying or probing exchanges. In that posture the
integrity of the Invariant trace windows and of individual scan verdicts
must not be relied upon for cross-tenant guarantees; deploy a
`NetworkPolicy` (or mesh mTLS) that restricts `:9001` to agentgateway before
treating audit verdicts as authoritative.

## Security model and failure modes

| Failure                                       | Behaviour                                                                                                                                                              |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Scanner raises / exceeds `SCANNER_TIMEOUT_MS` | `failClosed` -> `BLOCK` -> aggregator denies -> `error` oneof -> agentgateway returns JSON-RPC `-32001`. `failOpen` -> `HUMAN_REVIEW` -> forwarded with audit warning. |
| Sidecar Pod unreachable                       | agentgateway's mcp-guardrails processor fails closed -> MCP exchange denied -> JSON-RPC `-32001` returned to the agent.                                                |
| Model load failure (PromptGuard-2)            | Pod readiness probe stays `NOT_SERVING`; the Pod is removed from the Service endpoints. No traffic reaches a half-initialised sidecar.                                 |
| Malformed JSON-RPC payload                    | Servicer returns `AuthorizationError{INVALID}` (fail-closed on parse failure).                                                                                |
| Tool output > `MAX_CONTENT_BYTES`             | Head (32KiB) + mid + tail (`SCAN_TAIL_BYTES`, 8KiB each) windows are scanned; the decision is flagged `truncated=true` in the audit span. Padding cannot hide an injection at the head, tail, or the centre of the remainder; regions between the windows remain unscanned (bounded by `SCAN_MAX_PAYLOAD_BYTES`, below). |
| PromptGuard token-window coverage             | Within each scanned chunk, PromptGuard scores 512-token sliding windows (stride 64). The window budget adapts to the chunk's token length — `clamp(ceil(tokens/step)+1, 4, PG_MAX_WINDOWS)` — keeping the first N-1 strided windows plus a tail-aligned window, and takes the MAX window score. **Latency trade-off:** each window is one extra inference; `PG_MAX_WINDOWS` (default 16) is the per-chunk latency bound. **Coverage ceiling:** chunks beyond ~`PG_MAX_WINDOWS*448 + 512` tokens (≈7.7K tokens at the default) still have unscanned middle regions — an injection padded past the scored windows can be missed. Defence-in-depth for such payloads is the byte-level head/mid/tail split plus the `payload_size` hard cap above. |
| Payload > `SCAN_MAX_PAYLOAD_BYTES` (1MiB)     | Still scanned via the three windows, plus a `payload_size` `HUMAN_REVIEW` result carrying scanned/total bytes — `HUMAN_REVIEW_MODE=deny` turns it into a hard deny. The audit record carries `scanned_bytes` / `total_bytes` so under-scanned payloads are visible. |
| stdio upstream                                | agentgateway forwards an empty header set for stdio upstreams. Do **not** rely on headers for authn/authz when `metadata_context.upstream_transport == "stdio"`.       |

**failOpen × redaction.** Under `FAILURE_MODE=failOpen` a scanner exception
becomes `HUMAN_REVIEW`. With the default `REDACT_ON_REVIEW=1` the payload is
still redacted before forwarding, so a degraded sidecar no longer leaks
maskable secrets — failOpen trades away the block layer but keeps the
masking layer. With `REDACT_ON_REVIEW=0` (legacy) review semantics suppress
redaction and the payload is forwarded **in cleartext** (with the audit
warning), trading both the block *and* the masking layer away for
availability.

**Deny-reason generalisation.** Wire-visible deny reasons are fixed generic
strings (`denied by content policy` / `denied by response policy`, plus a
short correlation ref; `engine_error` for internal failures) so a caller
cannot iterate a payload against scanner/pattern feedback. The full internal
reason — scanner, pattern, match fingerprint — is only in the audit log.
The correlation ref is minted by the engine per exchange and recorded in the
same audit decision line (`ref` field), so a tenant-reported ref always
greps to the full internal record. Match fingerprints are tiered:
low-entropy patterns (email, credit card, key=value credentials, connection
strings) record length only, high-entropy patterns record a SHA-256 digest
(or HMAC-SHA256 when `AUDIT_HMAC_KEY` is set).

The fail-closed posture is deliberate: an agent that can call real tools
(write files, send email, apply k8s manifests) is far more dangerous when a
guardrail outage is silent than when it is loud. `-32001` is loud.

### Supply chain & operator tooling

- **Dependency audit:** `make audit` runs [pip-audit](https://pypi.org/project/pip-audit/)
  against `requirements.txt` (the locked runtime surface). Accepted-risk
  CVEs are whitelisted one-per-line in `scripts/pip-audit-ignore.txt`
  (passed as `--ignore-vuln`); every entry needs a written justification.
  pip-audit is a dev-extra dependency, never a runtime one.
- **SBOM:** `make sbom` (or `IMAGE=<image> bash scripts/gen_sbom.sh`) generates
  SPDX + CycloneDX SBOMs with [syft](https://github.com/anchore/syft) into
  `sbom/`. CI wiring (generate on release, attach as release assets, sign)
  is intentionally left to the workflow owner — it needs a token with
  release-asset scope; the script is the CI-ready entrypoint.
- **Compliance notes:** [docs/compliance.md](docs/compliance.md) covers data
  classification, audit retention (WORM / object lock), access control, the
  AgentAlignment data-egress statement, and known audit limitations.
- **Operator CLI:** `scripts/guardrail_ctl.py` — `rules lint` validates a
  rule pack (structure, thresholds, negate placement) and dry-runs it
  against built-in sample traces (non-zero exit on an invalid pack, so it
  gates a GitOps pipeline); `decision replay <audit.jsonl>` gives an
  offline outcome distribution, scanner/rule drill-down and exchange_id
  request/response pairing over the JSONL audit log.

### Structured deny contract

On deny, `AuthorizationError.mcp_error` carries a JSON-RPC 2.0 error body
(`code: -32001`) whose `message` is the same generalised string as the wire
`reason` and whose `data` adds a generalised policy `category` (e.g.
`content_policy`, `tool_policy`, `tool_flow`) and a generic `remedy` hint
(e.g. "remove credentials, PII or instruction markers from tool arguments")
— never pattern names, rule internals or match detail. The request side
also populates `McpRequestResult.metadata` with `guardrail.scan_score`,
`guardrail.rules_hit`, `guardrail.redactions`, `guardrail.exchange_id` and
`guardrail.outcome` so the dataplane can log/route on guardrail verdicts
without parsing the audit stream. (`McpResponseResult` has no `metadata`
field in the proto — response-side metadata is not emitted;
`header_mutation` is deliberately unused.)

### Known limitations (method coverage)

The sidecar only sees the MCP methods agentgateway forwards to it. The
default agentgateway methods mapping covers `tools/call`, `tools/list`,
`prompts/get` and `resources/read`. **Reverse-channel / other MCP methods
— `sampling/createMessage`, `elicitation/create`, `completion/complete`,
`roots/list`, notifications — are NOT covered** unless the deployment's
methods mapping is extended to forward them (coverage depends on
agentgateway's ExtMcp methods support; see the upstream docs:
<https://agentgateway.dev/docs/>). If your threat model includes indirect
injection via server-initiated sampling/elicitation, extend the methods
mapping accordingly and treat this sidecar as one layer of a broader
policy. The Invariant trace only records `tools/call` requests with a
non-empty tool name; other methods are scanned for content but do not
advance toxic-flow state.

## Project layout

```
mcp-guardrails/
├── proto/                        # ext_mcp.proto + generated pb2 stubs (committed)
│   ├── ext_mcp.proto             # ExtMcp gRPC contract (agentgateway v1alpha1)
│   ├── ext_mcp_pb2.py            # generated (do not edit; regen via `make proto`)
│   └── ext_mcp_pb2_grpc.py       # generated (do not edit; regen via `make proto`)
├── guardrails/                   # the sidecar library
│   ├── __init__.py               # public re-exports + __version__
│   ├── models.py                 # Decision, ScanResult, ScanOutcome, FailureMode, ...
│   ├── aggregator.py             # fail-closed DecisionAggregator
│   ├── invariant.py              # FlowStep, ToxicFlowRule, LoopRule, RateLimitRule, AggregateRule, InvariantEngine
│   ├── scanners.py               # Scanner protocol, RegexScanner, OnnxPromptGuardScanner, Stub
│   ├── engine.py                 # GuardrailEngine orchestrator (request + response paths)
│   ├── servicer.py               # ExtMcpServicer (gRPC wire mapping)
│   ├── config.py                 # GuardrailConfig.from_env()
│   ├── otel.py                   # OTel spans/metrics + always-on JSONL audit
│   ├── redaction.py              # RedactionScanner (secret/PII masking, [REDACTED:<TYPE>] mutation)
│   ├── notify.py                 # HUMAN_REVIEW webhook notifier (fire-and-forget, urllib)
│   ├── proto_bridge.py           # sys.path bridge for the generated stubs
│   └── rules/
│       ├── __init__.py           # RulePack loader (path / module / env, SIGHUP reload)
│       └── default.py            # bundled homelab starter rule pack
├── tests/                        # 320+ unit tests (incl. hypothesis property tests) + e2e_smoke.py
├── scripts/                      # proto_check.py, version_check.py, guardrail_ctl.py (rules lint /
│                               #   decision replay), gen_sbom.sh, pip-audit-ignore.txt, e2e_agentgateway.sh
├── deploy/k8s/                   # K8s manifests (Deployment, Service, ConfigMap, CRD)
├── examples/                     # rule pack, env file, standalone agentgateway config, PII demo upstream
├── .github/workflows/            # CI + release workflows
├── docs/compliance.md            # data classification, audit retention, access control, egress statement
├── server.py                     # grpc.aio entrypoint (SIGHUP reload, SIGTERM drain)
├── Dockerfile                    # multi-stage (base/builder/models/runtime), nonroot 65532
├── Makefile                      # proto / dev / test / lint / docker / run / ci
├── pyproject.toml                # package metadata + pytest/ruff config
├── requirements.txt              # runtime deps (grpc stack pinned, ML stack pinned)
├── README.md                     # this file
├── ARCHITECTURE.md               # deep dive
├── CONTRIBUTING.md               # dev workflow
├── CHANGELOG.md                  # release history
└── LICENSE                       # Apache-2.0
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the dev workflow, the
proto-stub sync rule, how to add a scanner, how to add an Invariant rule,
the DCO/signoff note, and the release process.

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).

## Acknowledgements

- [agentgateway](https://github.com/agentgateway/agentgateway) — the
  MCP-aware gateway whose `ExtMcp` contract this sidecar implements.
- [Prompt Guard](https://github.com/meta-llama/Prompt-Guard) (Meta) — the
  PromptGuard-2 classifier, converted to ONNX by
  [Gravitee.io](https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-86M-onnx).
- [ONNX Runtime](https://onnxruntime.ai/) — CPU inference engine for the
  PromptGuard-2 model (no torch dependency).
- [Invariant Labs](https://invariantlabs.ai/) — the toxic-flow / agent-loop
  detection research that informed the `ToxicFlowRule` / `LoopRule` shapes.
