"""Runtime configuration, environment-driven with sane homelab defaults.

All knobs are environment-variable configurable so the same image serves dev,
homelab and (with resource bumps) production. Defaults encode the design's
"single-user Homelab" tradeoffs: ONNX PromptGuard always on, AgentAlignment as
an opt-in LLM second stage, fail-closed, 2Gi memory budget.

PromptGuard (ONNX, always on)
=============================

The PROMPT_GUARD scanner uses the **public, non-gated** ONNX model
``gravitee-io/Llama-Prompt-Guard-2-86M-onnx`` via ONNX Runtime (CPU). No
HuggingFace token is required — the model repo is public and non-gated. This
replaces the gated ``meta-llama/Llama-Prompt-Guard-2-86M`` torch model that
LlamaFirewall ships with, avoiding the 401 Unauthorized build failure.

  LF_ONNX_MODEL                ONNX model repo ID. Default:
                               "gravitee-io/Llama-Prompt-Guard-2-86M-onnx"
  LF_ONNX_FILE                 Which .onnx file to load. Default: "model.onnx"
                               (full-precision, ~350MB, accuracy 98.01%).
  LF_PROMPTGUARD_BLOCK_THRESHOLD  Block threshold (0.0-1.0). Score >= threshold
                               -> BLOCK. Default: 0.9.
  PG_REVIEW_THRESHOLD          Review (grey-zone) threshold (0.0-1.0). Scores in
                               [review, block) -> HUMAN_REVIEW (second-stage
                               AgentAlignment gate, else HUMAN_REVIEW_MODE);
                               below -> ALLOW. Default: 0.5; 0 disables.
  LF_ONNX_LOCAL_DIR            Local directory of a pre-baked model. When set
                               (the container pre-downloads to /models/hf/pg2),
                               the scanner loads the tokenizer + .onnx from
                               disk — no HF hub access at runtime. Default:
                               unset (resolve via the HF hub cache).
  HF_HOME                      HuggingFace cache directory. Default: /models/hf
                               (set in Dockerfile).
  HF_TOKEN                     HuggingFace token. NOT required for the ONNX
                               model (public). Only needed if you point
                               LF_ONNX_MODEL at a gated repo.
  TOKENIZERS_PARALLELISM       Set to "true" for parallel tokenization (the
                               sidecar is single-process async, unset is fine).

AgentAlignment LLM (second-stage, opt-in)
=========================================

When ENABLE_AGENT_ALIGNMENT=1, the AlignmentCheckScanner calls an external LLM
API to do a "second-stage" deep inspection whenever PromptGuard flags
HUMAN_REVIEW. The LLM endpoint is fully configurable via LF_ALIGNMENT_* env
vars so you can use any OpenAI-compatible API.

  LF_ALIGNMENT_MODEL           LLM model name. Default:
                               "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8"
                               (Together AI's hosted Llama-4-Maverick).
  LF_ALIGNMENT_API_BASE        LLM API base URL (OpenAI-compatible). Default:
                               "https://api.together.xyz/v1"
                               Override for OpenAI (https://api.openai.com/v1),
                               Azure, vLLM, Ollama, etc.
  LF_ALIGNMENT_API_KEY         API key for the LLM provider. Default: *(unset)*.
                               Set this to your provider API key (e.g. the
                               Together AI key, an OpenAI key, etc.). The
                               scanner reads the key directly from this env var.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .models import FailureMode, HumanReviewMode


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return float(raw)


@dataclass(frozen=True)
class GuardrailConfig:
    """Full runtime configuration for :class:`GuardrailEngine`."""

    # --- Failure / aggregation policy ---
    failure_mode: FailureMode = FailureMode.FAIL_CLOSED
    human_review_mode: HumanReviewMode = HumanReviewMode.PASS

    # --- Content budget ---
    max_content_bytes: int = 32 * 1024
    # Extra bytes scanned from the MID and TAIL of an over-budget payload,
    # closing the truncation bypass (an attacker padding a payload so the
    # injection lands beyond the scanned head — or between the head and
    # tail windows). 0 disables mid/tail scanning.
    scan_tail_bytes: int = 8 * 1024
    # Hard payload cap (S-H2). Payloads whose extracted text exceeds this are
    # still scanned (head/mid/tail windows) but the engine additionally flags
    # a HUMAN_REVIEW "payload_size" result — HUMAN_REVIEW_MODE then decides
    # pass+warn vs deny. Bounds the unscanned fraction of giant payloads.
    scan_max_payload_bytes: int = 1024 * 1024

    # --- Scanner enable flags ---
    enable_regex_scanner: bool = True
    enable_promptguard: bool = True
    enable_agent_alignment: bool = False

    # --- Redaction (mutation pipeline) ---
    # When enabled, the engine structurally rewrites secret/PII material in
    # otherwise-allowed payloads, replacing each match with a fixed
    # `[REDACTED:<TYPE>]` placeholder and forwarding the result via the
    # proto `mutated` oneof. Runs only when no scanner BLOCKed the exchange
    # (a BLOCK always wins). HUMAN_REVIEW payloads are also redacted by
    # default (see redact_on_review).
    enable_redaction: bool = True
    # S-H3: when True (default), HUMAN_REVIEW payloads still flow through the
    # redaction transformer — the exchange keeps its review verdict (pass+warn
    # or deny per HUMAN_REVIEW_MODE) AND carries the mutated payload, so a
    # review-grade credit card / key=value credential is masked in what the
    # upstream sees instead of passing through verbatim. False restores the
    # legacy behaviour (review payloads pass unmutated).
    redact_on_review: bool = True
    # Request-side redaction is OFF by default: a secret in tool-call params
    # is a signal to BLOCK (the RegexScanner already does), not to silently
    # rewrite the caller's request. Enable only for deployments that
    # deliberately tolerate rewritten arguments.
    redact_request_params: bool = False
    # Byte-size cap on the payload handed to the redaction transformer.
    # Redaction runs ~11 regexes over the full (untruncated) payload, so
    # without a cap a multi-MB payload would burn hundreds of ms of CPU per
    # call. Payloads beyond the cap skip redaction and pass through
    # unchanged, flagged `redaction_skipped=size` in the audit span. This is
    # a safe trade-off: scanner BLOCK decisions still apply (they run on the
    # head/mid/tail scan_windows), so block-grade secrets in an over-cap payload
    # are still denied by the RegexScanner upstream — only the best-effort
    # masking of ALLOW-grade PII is skipped.
    redaction_max_bytes: int = 256 * 1024

    # --- PromptGuard (ONNX, always on) ---
    # The ONNX model is public + non-gated, so HF_TOKEN is NOT required.
    # Default: model.onnx (full-precision, ~350MB, accuracy 98.01%).
    lf_onnx_model: str = "gravitee-io/Llama-Prompt-Guard-2-86M-onnx"
    lf_onnx_file: str = "model.onnx"
    # Local directory of a pre-baked model (Dockerfile pre-downloads to
    # /models/hf/pg2). When set, the scanner loads the tokenizer + .onnx from
    # this dir instead of hitting the HF hub — enables air-gapped runs and
    # skips the runtime download. None -> resolve via the HF hub cache.
    lf_onnx_local_dir: str | None = None
    lf_promptguard_block_threshold: float = 0.9
    # Grey-zone review threshold (PG_REVIEW_THRESHOLD, default 0.5). Dual-
    # threshold policy: score >= block -> BLOCK; review <= score < block ->
    # HUMAN_REVIEW (routed to the second-stage AgentAlignment gate when
    # enabled, else resolved per HUMAN_REVIEW_MODE); score < review -> ALLOW.
    # Values above the block threshold are clamped down to it at load.
    pg_review_threshold: float = 0.5
    # PromptGuard sliding-window cap (PG_MAX_WINDOWS). The window budget is
    # adaptive — it grows with the payload's token length
    # (clamp(ceil(tokens/step)+1, 4, pg_max_windows)) — and this value is the
    # hard cap, i.e. the per-chunk latency bound. Default 16: at 512-token
    # windows / 64-token stride this covers ~7.7K tokens per chunk; larger
    # payloads still rely on the byte-level head/mid/tail split.
    pg_max_windows: int = 16
    # Supply-chain pin (S-M6): HF revision (commit sha) for runtime hub
    # fetches when LF_ONNX_LOCAL_DIR is unset. The image pre-bakes the model
    # at build time pinned via the PG2_REVISION build-arg; from_env pins the
    # same default commit here. If you override LF_ONNX_MODEL you MUST also
    # set LF_ONNX_REVISION (or "" for latest main, which re-opens the
    # re-tagging risk).
    lf_onnx_revision: str | None = None

    # --- AgentAlignment LLM (second-stage, opt-in) ---
    # The LLM client reads the API key directly from lf_alignment_api_key.
    lf_alignment_model: str = "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8"
    lf_alignment_api_base: str = "https://api.together.xyz/v1"
    lf_alignment_api_key: str | None = None

    # --- Tool ACL (F-P1-5) ---
    # Coarse tool-level access control applied on the request side BEFORE any
    # content scanner runs. Comma-separated tool names; ``prefix/*`` wildcards
    # match any tool under the prefix. DENY wins over ALLOW. When
    # ``allow_tools`` is non-empty it acts as a whitelist: any tool not
    # matching it is denied. Both empty -> every tool is allowed (default).
    allow_tools: tuple[str, ...] = ()
    deny_tools: tuple[str, ...] = ()

    # --- Invariant ---
    # Sliding-window size for the cross-call toxic-flow trace. Raised from 64
    # to 256 (S-H4): long agent plans with many intermediate calls previously
    # pushed the head of a toxic flow out of the window before the tail
    # arrived. Memory bound: 256 entries x INVARIANT_ARGS_MAX_BYTES (4KiB)
    # x INVARIANT_MAX_TRACES (1024 keys) <= ~1GiB worst case; realistic
    # entries are far below the 4KiB per-entry cap (structure-preserving
    # truncation), so the practical footprint stays in the tens of MiB.
    invariant_window: int = 256
    # Max distinct per-route trace windows kept by the InvariantEngine before
    # the least-recently-used tenant trace is evicted. Bounds memory against
    # trace-key flooding.
    invariant_max_traces: int = 1024
    # DoS bound (S-M4): per-entry cap on the arguments copy stored in the
    # Invariant trace window. Entries whose serialised args exceed this keep
    # their structure but have long string values truncated, so toxic-flow
    # arg matchers keep working while a multi-MB argument cannot bloat the
    # rolling window. The full-args fingerprint is computed BEFORE
    # truncation, so loop detection is unaffected.
    invariant_args_max_bytes: int = 4 * 1024
    # S-H5/F-P0-1(b): comma-separated request-header names (case-insensitive)
    # whose value extends the Invariant trace key
    # (``route_name | header:value``). Isolates toxic-flow traces per caller
    # session beyond the route dimension — two sessions on the same route can
    # no longer assemble a cross-session toxic flow or trip each other's loop
    # rules. Missing header / empty list -> legacy route-only key.
    invariant_trace_key_headers: tuple[str, ...] = ()
    # S-H4 follow-up: TTL (seconds) for sticky partial-match progress kept for
    # ToxicFlowRule steps that matched a prefix of the trace but slid out of
    # the window. Progress older than this is dropped (a flow spread over
    # longer than the TTL is treated as abandoned).
    invariant_sticky_ttl_s: int = 600

    # --- Timing ---
    scanner_timeout_ms: int = 500

    # --- Networking ---
    listen_addr: str = "[::]:9001"
    server_max_workers: int = 8
    # gRPC hardening (S-M4): bound message size and in-flight RPCs so a
    # single runaway caller cannot exhaust memory / starve the event loop.
    grpc_max_recv_bytes: int = 8 * 1024 * 1024
    grpc_max_concurrent_rpcs: int = 128

    # --- Observability ---
    otel_endpoint: str | None = None
    otel_service_name: str = "mcp-guardrails"
    audit_log_path: str | None = None
    # A-P1-1: whitelist of request headers (case-insensitive, first match
    # wins) whose value is copied into the audit line's ``caller`` field.
    # Anything NOT in this list never reaches the audit log (headers may
    # carry bearer tokens / cookies). The default deliberately excludes
    # ``x-session-id``: a session id is a quasi-credential (session
    # hijacking / cross-log correlation) and must not land in the durable
    # audit log unless an operator explicitly opts in.
    audit_caller_headers: tuple[str, ...] = ("x-forwarded-user",)
    # Sidecar version string recorded in every audit line
    # (``sidecar_version``). Defaults to the package ``__version__``; the env
    # override exists for builds that stamp a different release identity
    # (e.g. an internal fork tag).
    sidecar_version: str = ""

    # --- HUMAN_REVIEW webhook notification ---
    # Optional HTTP(S) endpoint POSTed a small JSON body
    # (outcome/reason/ref/exchange_id/ts) whenever a decision carries the
    # human_review flag. Empty (default) disables the notifier. Delivery is
    # fire-and-forget: a background asyncio task with a 2s timeout; a failed
    # or slow endpoint only logs a warning and NEVER blocks or alters the
    # decision path. The body is metadata-only (no payload content).
    review_webhook_url: str = ""

    # --- Graceful shutdown (A-P2-4) ---
    # Seconds to wait after flipping the gRPC health service to NOT_SERVING
    # before draining connections, giving the readiness probe / dataplane
    # time to observe the transition and stop routing new exchanges to this
    # replica. 0 disables the propagation wait (immediate drain).
    shutdown_drain_s: float = 5.0

    # --- Runtime health degradation (A-P0-4) ---
    # Sliding-window scanner error/timeout rate: when the rate over the last
    # ``unhealthy_scanner_window`` scan invocations exceeds
    # ``unhealthy_scanner_error_rate`` (and at least
    # ``unhealthy_scanner_min_samples`` invocations were seen), the engine
    # reports unhealthy and the gRPC health service flips to NOT_SERVING
    # (recovering automatically once the rate drops below the threshold).
    # Tracked regardless of FAILURE_MODE — failOpen still surfaces the
    # degradation via health/metrics.
    unhealthy_scanner_error_rate: float = 0.5
    unhealthy_scanner_window: int = 100
    unhealthy_scanner_min_samples: int = 20

    # --- Misc ---
    dry_run: bool = False
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> GuardrailConfig:
        fm = os.environ.get("FAILURE_MODE", "failClosed")
        try:
            failure_mode = FailureMode(fm)
        except ValueError:
            failure_mode = FailureMode.FAIL_CLOSED

        hr = os.environ.get("HUMAN_REVIEW_MODE", "pass")
        try:
            human_review_mode = HumanReviewMode(hr)
        except ValueError:
            human_review_mode = HumanReviewMode.PASS

        otel = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or None

        return cls(
            failure_mode=failure_mode,
            human_review_mode=human_review_mode,
            max_content_bytes=_env_int("MAX_CONTENT_BYTES", 32 * 1024),
            scan_tail_bytes=_env_int("SCAN_TAIL_BYTES", 8 * 1024),
            scan_max_payload_bytes=_env_int("SCAN_MAX_PAYLOAD_BYTES", 1024 * 1024),
            enable_regex_scanner=_env_bool("ENABLE_REGEX_SCANNER", True),
            enable_promptguard=_env_bool("ENABLE_PROMPTGUARD", True),
            enable_agent_alignment=_env_bool("ENABLE_AGENT_ALIGNMENT", False),
            enable_redaction=_env_bool("ENABLE_REDACTION", True),
            redact_request_params=_env_bool("REDACT_REQUEST_PARAMS", False),
            redact_on_review=_env_bool("REDACT_ON_REVIEW", True),
            redaction_max_bytes=_env_int("REDACTION_MAX_BYTES", 256 * 1024),
            lf_onnx_model=os.environ.get(
                "LF_ONNX_MODEL", "gravitee-io/Llama-Prompt-Guard-2-86M-onnx"
            ),
            lf_onnx_file=os.environ.get("LF_ONNX_FILE", "model.onnx"),
            lf_onnx_local_dir=os.environ.get("LF_ONNX_LOCAL_DIR") or None,
            lf_promptguard_block_threshold=_env_float("LF_PROMPTGUARD_BLOCK_THRESHOLD", 0.9),
            pg_review_threshold=min(
                _env_float("PG_REVIEW_THRESHOLD", 0.5),
                _env_float("LF_PROMPTGUARD_BLOCK_THRESHOLD", 0.9),
            ),
            pg_max_windows=_env_int("PG_MAX_WINDOWS", 16),
            # Default pin matches the Dockerfile PG2_REVISION build-arg.
            lf_onnx_revision=os.environ.get(
                "LF_ONNX_REVISION", "45a05fbd5337a864edc608f994911f009c37ca57"
            )
            or None,
            lf_alignment_model=os.environ.get(
                "LF_ALIGNMENT_MODEL",
                "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
            ),
            lf_alignment_api_base=os.environ.get(
                "LF_ALIGNMENT_API_BASE", "https://api.together.xyz/v1"
            ),
            lf_alignment_api_key=os.environ.get("LF_ALIGNMENT_API_KEY") or None,
            allow_tools=tuple(
                t.strip() for t in os.environ.get("ALLOW_TOOLS", "").split(",") if t.strip()
            ),
            deny_tools=tuple(
                t.strip() for t in os.environ.get("DENY_TOOLS", "").split(",") if t.strip()
            ),
            invariant_window=_env_int("INVARIANT_WINDOW", 256),
            invariant_max_traces=_env_int("INVARIANT_MAX_TRACES", 1024),
            invariant_args_max_bytes=_env_int("INVARIANT_ARGS_MAX_BYTES", 4 * 1024),
            invariant_trace_key_headers=tuple(
                h.strip().lower()
                for h in os.environ.get("INVARIANT_TRACE_KEY_HEADERS", "").split(",")
                if h.strip()
            ),
            invariant_sticky_ttl_s=_env_int("INVARIANT_STICKY_TTL_S", 600),
            scanner_timeout_ms=_env_int("SCANNER_TIMEOUT_MS", 500),
            listen_addr=os.environ.get("LISTEN_ADDR", "[::]:9001"),
            server_max_workers=_env_int("SERVER_MAX_WORKERS", 8),
            grpc_max_recv_bytes=_env_int("GRPC_MAX_RECV_BYTES", 8 * 1024 * 1024),
            grpc_max_concurrent_rpcs=_env_int("GRPC_MAX_CONCURRENT_RPCS", 128),
            otel_endpoint=otel,
            otel_service_name=os.environ.get("OTEL_SERVICE_NAME", "mcp-guardrails"),
            audit_log_path=os.environ.get("AUDIT_LOG_PATH") or None,
            audit_caller_headers=tuple(
                h.strip().lower()
                for h in os.environ.get("AUDIT_CALLER_HEADERS", "x-forwarded-user").split(",")
                if h.strip()
            ),
            review_webhook_url=os.environ.get("REVIEW_WEBHOOK_URL", "").strip(),
            shutdown_drain_s=_env_float("SHUTDOWN_DRAIN_S", 5.0),
            sidecar_version=os.environ.get("GUARDRAIL_VERSION", ""),
            unhealthy_scanner_error_rate=_env_float("UNHEALTHY_SCANNER_ERROR_RATE", 0.5),
            unhealthy_scanner_window=_env_int("UNHEALTHY_SCANNER_WINDOW", 100),
            unhealthy_scanner_min_samples=_env_int("UNHEALTHY_SCANNER_MIN_SAMPLES", 20),
            dry_run=_env_bool("GUARDRAIL_DRY_RUN", False),
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        )
