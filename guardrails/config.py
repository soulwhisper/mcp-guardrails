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
                               (full-precision, ~350MB, accuracy 98.01%). The
                               repo also has "model.quant.onnx" (quantized,
                               ~90MB, accuracy 89.89%) if you want a smaller
                               image at the cost of recall.
  LF_PROMPTGUARD_BLOCK_THRESHOLD  Block threshold (0.0-1.0). Score >= threshold
                               -> BLOCK. Default: 0.9.
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

    # --- Scanner enable flags ---
    enable_regex_scanner: bool = True
    enable_promptguard: bool = True
    enable_agent_alignment: bool = False

    # --- PromptGuard (ONNX, always on) ---
    # The ONNX model is public + non-gated, so HF_TOKEN is NOT required.
    # Default: model.onnx (full-precision, ~350MB, accuracy 98.01%).
    lf_onnx_model: str = "gravitee-io/Llama-Prompt-Guard-2-86M-onnx"
    lf_onnx_file: str = "model.onnx"
    lf_promptguard_block_threshold: float = 0.9

    # --- AgentAlignment LLM (second-stage, opt-in) ---
    # The LLM client reads the API key directly from lf_alignment_api_key.
    lf_alignment_model: str = "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8"
    lf_alignment_api_base: str = "https://api.together.xyz/v1"
    lf_alignment_api_key: str | None = None

    # --- Invariant ---
    invariant_window: int = 64

    # --- Timing ---
    scanner_timeout_ms: int = 500

    # --- Networking ---
    listen_addr: str = "[::]:9001"
    server_max_workers: int = 8

    # --- Observability ---
    otel_endpoint: str | None = None
    otel_service_name: str = "mcp-guardrails"
    audit_log_path: str | None = None

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
            enable_regex_scanner=_env_bool("ENABLE_REGEX_SCANNER", True),
            enable_promptguard=_env_bool("ENABLE_PROMPTGUARD", True),
            enable_agent_alignment=_env_bool("ENABLE_AGENT_ALIGNMENT", False),
            lf_onnx_model=os.environ.get(
                "LF_ONNX_MODEL", "gravitee-io/Llama-Prompt-Guard-2-86M-onnx"
            ),
            lf_onnx_file=os.environ.get("LF_ONNX_FILE", "model.onnx"),
            lf_promptguard_block_threshold=_env_float(
                "LF_PROMPTGUARD_BLOCK_THRESHOLD", 0.9
            ),
            lf_alignment_model=os.environ.get(
                "LF_ALIGNMENT_MODEL",
                "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
            ),
            lf_alignment_api_base=os.environ.get(
                "LF_ALIGNMENT_API_BASE", "https://api.together.xyz/v1"
            ),
            lf_alignment_api_key=os.environ.get("LF_ALIGNMENT_API_KEY") or None,
            invariant_window=_env_int("INVARIANT_WINDOW", 64),
            scanner_timeout_ms=_env_int("SCANNER_TIMEOUT_MS", 500),
            listen_addr=os.environ.get("LISTEN_ADDR", "[::]:9001"),
            server_max_workers=_env_int("SERVER_MAX_WORKERS", 8),
            otel_endpoint=otel,
            otel_service_name=os.environ.get("OTEL_SERVICE_NAME", "mcp-guardrails"),
            audit_log_path=os.environ.get("AUDIT_LOG_PATH") or None,
            dry_run=_env_bool("GUARDRAIL_DRY_RUN", False),
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        )
