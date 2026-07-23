# Configuration

Every knob is environment-variable driven (`GuardrailConfig.from_env()` in
`guardrails/config.py`), so the same image serves dev, homelab, and (with
resource bumps) production. Defaults encode the single-user-homelab
tradeoffs: PromptGuard always on, AgentAlignment opt-in, fail-closed, 32KiB
content budget, 500ms scanner deadline, 2Gi memory budget.

The table below mirrors `config.py` and is kept in sync with the README
env-var table by project contract.

| Group | Env var | Default | Description |
| --- | --- | --- | --- |
| Policy | `FAILURE_MODE` | `failClosed` | `failClosed` denies on scanner failure/timeout (recommended for write-capable agents). `failOpen` allows with a review flag. |
| Policy | `HUMAN_REVIEW_MODE` | `pass` | How `HUMAN_REVIEW` outcomes resolve. `pass` forwards + audit warning; `deny` escalates to a hard deny. |
| Policy | `ALLOW_TOOLS` | _(unset)_ | Comma-separated tool allowlist (`prefix/*` wildcards). Non-empty → any tool not matching is denied before scanners run. See [Tool ACL](guardrails/tool-acl.md). |
| Policy | `DENY_TOOLS` | _(unset)_ | Comma-separated tool denylist (`prefix/*` wildcards). DENY wins over `ALLOW_TOOLS`. |
| Scanners | `MAX_CONTENT_BYTES` | `32768` | Max bytes of the head window fed to any scanner. Beyond this the payload is truncated (UTF-8-safe) and flagged `truncated=true` in audit. |
| Scanners | `SCAN_TAIL_BYTES` | `8192` | Extra bytes scanned from the MID and TAIL of an over-budget payload, closing the truncation bypass. `0` disables. |
| Scanners | `SCAN_MAX_PAYLOAD_BYTES` | `1048576` | Hard payload cap (1MiB). Over-cap payloads are still scanned (head/mid/tail) AND flagged `payload_size` `HUMAN_REVIEW`; `HUMAN_REVIEW_MODE` decides pass+warn vs deny. |
| Scanners | `ENABLE_REGEX_SCANNER` | `true` | Deterministic pattern scanner (hidden ASCII / PII / secrets). Zero ML deps. |
| Scanners | `ENABLE_PROMPTGUARD` | `true` | ONNX PromptGuard semantic scanner. Falls back to regex-only if `onnxruntime`/`transformers` is absent. |
| Scanners | `ENABLE_AGENT_ALIGNMENT` | `false` | LLM-based second stage; only triggered when PromptGuard flags `HUMAN_REVIEW` on a response. |
| Redaction | `ENABLE_REDACTION` | `true` | Structural secret/PII redaction on allowed payloads (`[REDACTED:<TYPE>]`, forwarded via the `mutated` oneof). |
| Redaction | `REDACT_ON_REVIEW` | `true` | Also redact `HUMAN_REVIEW` payloads (verdict kept, mutated payload rides along). `false` restores legacy pass-unmutated. |
| Redaction | `REDACT_REQUEST_PARAMS` | `false` | Also redact `params.arguments` on the request side. Off by default — request-side secrets should BLOCK, not be rewritten. |
| Redaction | `REDACTION_MAX_BYTES` | `262144` | Payload byte cap for redaction (256KiB). Over-cap → skip + `redaction_skipped=size` in the audit span. |
| PromptGuard | `LF_ONNX_MODEL` | `gravitee-io/Llama-Prompt-Guard-2-86M-onnx` | ONNX model repo ID. Public, non-gated; weights under the Llama 4 Community License (see NOTICE). |
| PromptGuard | `LF_ONNX_FILE` | `model.onnx` | Which `.onnx` file to load (`model.onnx` full-precision ~350MB / `model.quant.onnx` quantized ~90MB). |
| PromptGuard | `LF_ONNX_LOCAL_DIR` | _(unset)_ | Pre-baked model dir (image: `/models/hf/pg2`); loads from disk, no HF hub access at runtime (air-gappable). |
| PromptGuard | `LF_ONNX_REVISION` | `45a05fbd…` | Supply-chain pin: HF commit sha for hub fetches (only when `LF_ONNX_LOCAL_DIR` is unset). Matches the Dockerfile `PG2_REVISION` build-arg. Override together with `LF_ONNX_MODEL`. |
| PromptGuard | `LF_PROMPTGUARD_BLOCK_THRESHOLD` | `0.9` | Block threshold (0.0–1.0). Score ≥ threshold → `BLOCK`. |
| PromptGuard | `PG_REVIEW_THRESHOLD` | `0.5` | Grey-zone review threshold. Score in `[review, block)` → `HUMAN_REVIEW`; below → `ALLOW`. Clamped to the block threshold; `0` disables. |
| PromptGuard | `PG_MAX_WINDOWS` | `16` | Hard cap on PromptGuard sliding-window inference per chunk; the per-chunk latency bound. Raise for long-payload coverage, lower for tighter P95. |
| AgentAlignment | `LF_ALIGNMENT_MODEL` | `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8` | LLM model name (only when `ENABLE_AGENT_ALIGNMENT=true`). |
| AgentAlignment | `LF_ALIGNMENT_API_BASE` | `https://api.together.xyz/v1` | LLM API base URL (OpenAI-compatible). Override for OpenAI, Azure, vLLM, Ollama, etc. |
| AgentAlignment | `LF_ALIGNMENT_API_KEY` | _(unset)_ | API key for the LLM provider, read directly from this env var. |
| HF cache | `HF_HOME` | `/models/hf` | HuggingFace cache directory (set in the Dockerfile). |
| HF cache | `HF_TOKEN` | _(unset)_ | NOT required for the default public ONNX model; needed only for gated repos (or to dodge unauthenticated rate limits). |
| Tokenizers | `TOKENIZERS_PARALLELISM` | _(unset)_ | Set `true` for parallel tokenization (single-process async sidecar; unset is fine). |
| Invariant | `INVARIANT_WINDOW` | `256` | Sliding-window size for the cross-call toxic-flow trace. Memory bound: `window × INVARIANT_ARGS_MAX_BYTES × INVARIANT_MAX_TRACES`. |
| Invariant | `INVARIANT_MAX_TRACES` | `1024` | Max distinct trace windows before the least-recently-used tenant trace is evicted. |
| Invariant | `INVARIANT_ARGS_MAX_BYTES` | `4096` | Per-entry args cap in the trace window; oversized args keep structure with long strings truncated. Loop fingerprints use the full args. |
| Invariant | `INVARIANT_TRACE_KEY_HEADERS` | _(unset)_ | Comma-separated request headers (case-insensitive) whose value extends the trace key (`route\|header:value`) for per-session isolation. |
| Invariant | `INVARIANT_STICKY_TTL_S` | `600` | TTL (seconds) for sticky partial-match progress; ToxicFlowRule prefix matches survive sliding out of the window this long. |
| Invariant | `INVARIANT_RULES_PATH` | _(unset)_ | Filesystem path to a rule pack (`.py` / `.policy`). Hot-reloadable via `SIGHUP`. Takes precedence over `INVARIANT_RULES_MODULE`. |
| Invariant | `INVARIANT_RULES_MODULE` | `guardrails.rules.default` | Dotted Python module path to a rule pack (used when `INVARIANT_RULES_PATH` is unset). |
| Timing | `SCANNER_TIMEOUT_MS` | `500` | Per-scanner deadline in milliseconds. Exceeded → treated per `FAILURE_MODE`. Keep sidecar < gateway so the sidecar decides first. |
| Networking | `LISTEN_ADDR` | `[::]:9001` | gRPC bind address. Use `127.0.0.1:9001` for loopback-only. |
| Networking | `SERVER_MAX_WORKERS` | `8` | `grpc.aio` ThreadPoolExecutor size; each in-flight RPC occupies one worker. |
| Networking | `GRPC_MAX_RECV_BYTES` | `8388608` | gRPC max receive/send message size (8MiB). Bounds memory per call. |
| Networking | `GRPC_MAX_CONCURRENT_RPCS` | `128` | Max in-flight RPCs (DoS bound); excess calls queue at the HTTP/2 layer. |
| Networking | `SHUTDOWN_DRAIN_S` | `5.0` | On SIGTERM/SIGINT the health service flips `NOT_SERVING` first, then waits this long for readiness propagation before draining. `0` skips the wait. |
| Observability | `OTEL_EXPORTER_OTLP_ENDPOINT` | _(unset)_ | OTLP/gRPC endpoint (e.g. `http://otel-collector.observability.svc:4317`). Unset or SDK absent → audit-only. |
| Observability | `OTEL_SERVICE_NAME` | `mcp-guardrails` | Service name on OTel spans/metrics. |
| Observability | `AUDIT_LOG_PATH` | _(unset)_ | Append-only JSONL audit path. `-` or unset → stdout. Always on. |
| Observability | `AUDIT_HMAC_KEY` | _(unset)_ | When set, high-entropy match fingerprints use keyed HMAC-SHA256 instead of plain SHA-256 (recommended). |
| Observability | `AUDIT_HASH_CHAIN` | `1` | Tamper-evident audit hash chain (`prev_hash` / `line_hash` per line; verify with `guardrail_ctl audit verify`). Single-writer assumption — one replica, per-replica files, or stdout shipping. |
| Observability | `AUDIT_CALLER_HEADERS` | `x-forwarded-user` | Comma-separated whitelist of request headers copied into the audit `caller` field. `x-session-id` is deliberately excluded by default (quasi-credential). |
| Observability | `GUARDRAIL_VERSION` | _(package version)_ | Override for the `sidecar_version` stamped on every audit line. |
| Observability | `REVIEW_WEBHOOK_URL` | _(unset)_ | Every `human_review` decision POSTs a metadata-only JSON body to this URL. Fire-and-forget; failures only log. |
| Health | `UNHEALTHY_SCANNER_ERROR_RATE` | `0.5` | Sliding-window scanner error/timeout rate above which gRPC health flips `NOT_SERVING` (recovers automatically). Tracked under `failOpen` too. |
| Health | `UNHEALTHY_SCANNER_WINDOW` | `100` | Number of recent scanner invocations kept in the health sliding window. |
| Health | `UNHEALTHY_SCANNER_MIN_SAMPLES` | `20` | Minimum windowed invocations before the error-rate verdict applies. |
| Misc | `GUARDRAIL_DRY_RUN` | `false` | Replace all real scanners with allow-stubs — validate wiring without loading ML models. |
| Misc | `LOG_LEVEL` | `INFO` | Python logging level (`DEBUG` / `INFO` / `WARNING` / `ERROR`). |

## docker-run.env

[`examples/docker-run.env`](https://github.com/soulwhisper/mcp-guardrails/blob/main/examples/docker-run.env)
is a fully commented starter env file that mirrors the `config.py` defaults —
uncomment and edit the lines you want to override:

```bash
docker run --rm -p 9001:9001 \
  --env-file examples/docker-run.env \
  -v $(pwd)/examples/rules.policy:/etc/guardrails/rules.policy:ro \
  ghcr.io/soulwhisper/mcp-guardrails:0.4.0
```

## Dry-run mode

`GUARDRAIL_DRY_RUN=1` swaps every real scanner for an allow-stub, so you can
verify wiring (agentgateway → sidecar → upstream) without loading any ML
models:

```bash
docker run --rm -p 9001:9001 \
  -e GUARDRAIL_DRY_RUN=1 -e ENABLE_REGEX_SCANNER=0 -e ENABLE_PROMPTGUARD=0 \
  ghcr.io/soulwhisper/mcp-guardrails:0.4.0
```
