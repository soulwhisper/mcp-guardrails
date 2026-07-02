"""The :class:`GuardrailEngine` — orchestrates scanners + invariant rules.

This is the heart of the sidecar. For each MCP exchange it:

1. Normalises the protobuf payload into an :class:`McpCallContext`.
2. Runs the configured content scanners against the extracted text, with a
   per-call deadline and failure-mode-aware exception handling.
3. (Request side only) records the call into the Invariant trace window and
   evaluates toxic-flow rules.
4. (Response side only) optionally runs a second-stage scanner (AgentAlignment)
   when a first-stage scanner flagged HUMAN_REVIEW — the design's cost-control
   for the LLM-based alignment check.
5. Hands all results to the :class:`DecisionAggregator` (fail-closed by
   default) and returns a :class:`Decision`.

The engine is concurrency-safe: the invariant trace is guarded by the
``RulePack`` lock on swap and a dedicated lock on append/evaluate.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from .aggregator import DecisionAggregator
from .config import GuardrailConfig
from .invariant import InvariantEngine
from .models import (
    Decision,
    FailureMode,
    McpCallContext,
    ScanOutcome,
    ScanResult,
)
from .otel import Observability, configure_logging
from .rules import RulePack
from .scanners import (
    AgentAlignmentScanner,
    OnnxPromptGuardScanner,
    RegexScanner,
    Scanner,
    StubScanner,
    extract_text,
    truncate,
)

logger = logging.getLogger("mcp.guardrails.engine")


@dataclass
class EngineComponents:
    """Pluggable component bag for :class:`GuardrailEngine`.

    Kept as a dataclass so tests can construct an engine with stub scanners
    and an in-memory rule pack without touching env / ML models.
    """

    request_scanners: list[Scanner] = field(default_factory=list)
    response_scanners: list[Scanner] = field(default_factory=list)
    second_stage_scanners: list[Scanner] = field(default_factory=list)
    invariant: InvariantEngine | None = None
    aggregator: DecisionAggregator = field(default_factory=lambda: DecisionAggregator())
    observability: Observability | None = None


class GuardrailEngine:
    """Async guardrail orchestrator."""

    def __init__(self, config: GuardrailConfig, components: EngineComponents):
        self._cfg = config
        self._c = components
        self._trace_lock = asyncio.Lock()
        if components.observability is None:
            components.observability = Observability()
        self._obs: Observability = components.observability
        self._ready = False

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> GuardrailEngine:
        return cls.from_config(GuardrailConfig.from_env())

    @classmethod
    def from_config(cls, config: GuardrailConfig) -> GuardrailEngine:
        configure_logging(config.log_level)

        request_scanners: list[Scanner] = []
        response_scanners: list[Scanner] = []
        second_stage: list[Scanner] = []

        if config.dry_run:
            request_scanners.append(StubScanner("stub.request"))
            response_scanners.append(StubScanner("stub.response"))
        else:
            if config.enable_regex_scanner:
                request_scanners.append(RegexScanner())
                response_scanners.append(RegexScanner())
            if config.enable_promptguard:
                # ONNX PromptGuard — public, non-gated model. No HF_TOKEN needed.
                # Loads the .onnx graph with onnxruntime directly (no optimum,
                # no torch). When lf_onnx_local_dir is set (container pre-bakes
                # the model there), the scanner loads from disk — air-gappable.
                try:
                    onnx_scanner = OnnxPromptGuardScanner(
                        model_id=config.lf_onnx_model,
                        file_name=config.lf_onnx_file,
                        block_threshold=config.lf_promptguard_block_threshold,
                        local_dir=config.lf_onnx_local_dir,
                    )
                    request_scanners.append(onnx_scanner)
                    response_scanners.append(onnx_scanner)
                    logger.info(
                        "ONNX PromptGuard enabled (model=%s, file=%s, local_dir=%s, "
                        "threshold=%.2f) — public model, no HF_TOKEN required",
                        config.lf_onnx_model,
                        config.lf_onnx_file,
                        config.lf_onnx_local_dir or "(hub)",
                        config.lf_promptguard_block_threshold,
                    )
                except ImportError as exc:
                    logger.warning(
                        "ONNX PromptGuard unavailable (%s); continuing with regex-only. "
                        "Install with: pip install onnxruntime transformers",
                        exc,
                    )
            if config.enable_agent_alignment:
                # AgentAlignment (LLM-based second stage). The LLM client reads
                # the API key directly from LF_ALIGNMENT_API_KEY. Configured via
                # LF_ALIGNMENT_MODEL / LF_ALIGNMENT_API_BASE / LF_ALIGNMENT_API_KEY.
                # Only triggered when PromptGuard flags HUMAN_REVIEW on a response.
                second_stage.append(
                    AgentAlignmentScanner(
                        model=config.lf_alignment_model,
                        api_base=config.lf_alignment_api_base,
                        api_key=config.lf_alignment_api_key,
                    )
                )
                logger.info(
                    "AgentAlignment LLM enabled (model=%s, api_base=%s, key=%s) — "
                    "second-stage, triggered on HUMAN_REVIEW",
                    config.lf_alignment_model,
                    config.lf_alignment_api_base,
                    "set" if config.lf_alignment_api_key else "UNSET",
                )

        rule_pack = RulePack.from_env()
        invariant = InvariantEngine(rule_pack.rules, window=config.invariant_window)

        aggregator = DecisionAggregator(human_review_mode=config.human_review_mode)

        obs = Observability(
            service_name=config.otel_service_name,
            otel_endpoint=config.otel_endpoint,
            audit_path=config.audit_log_path,
        )

        components = EngineComponents(
            request_scanners=request_scanners,
            response_scanners=response_scanners,
            second_stage_scanners=second_stage,
            invariant=invariant,
            aggregator=aggregator,
            observability=obs,
        )
        return cls(config, components)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def awarm(self) -> None:
        """Preload model weights / warm caches so the first request is fast.

        For the ONNX PromptGuard-backed engine this triggers the ONNX model
        load (PromptGuard-2-86M, ~350MB full-precision ONNX).
        With dry-run / regex-only configs this is a no-op.
        """
        # Touch each scanner once to force lazy init in a thread.
        for scanner in self._c.request_scanners + self._c.response_scanners:
            try:
                await asyncio.wait_for(
                    scanner.scan("", "tool"),
                    timeout=30.0,
                )
            except Exception as exc:  # pragma: no cover - warmup best-effort
                logger.warning(
                    "warmup of scanner %s failed: %s", getattr(scanner, "name", scanner), exc
                )
        self._ready = True
        logger.info("guardrail engine warmed up (ready=%s)", self._ready)

    @property
    def ready(self) -> bool:
        return self._ready

    def reload_rules(self) -> int:
        """Hot-reload the Invariant rule pack (SIGHUP handler).

        Re-resolves the rule pack from the configured source (env-driven, see
        :func:`guardrails.rules.load_rules`) and atomically swaps it into the
        invariant engine. Returns the new rule count, or 0 if no invariant
        engine is configured. Safe to call while requests are in flight:
        :meth:`InvariantEngine.set_rules` replaces the rule-list reference, so
        an evaluation already in progress keeps iterating the old list.
        """
        if self._c.invariant is None:
            return 0
        fresh = RulePack.from_env()
        self._c.invariant.set_rules(fresh.rules)
        logger.info("invariant rules reloaded (v%s, %d rules)", fresh.version, len(fresh.rules))
        return len(fresh.rules)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check_request(
        self,
        *,
        method: str,
        service_names: Sequence[str],
        tool_name: str,
        params: Mapping[str, Any],
        headers: Mapping[str, str],
        upstream_transport: str = "",
        route_name: str = "",
    ) -> Decision:
        ctx = McpCallContext(
            method=method,
            service_names=tuple(service_names),
            tool_name=tool_name,
            params=dict(params),
            headers=dict(headers),
            upstream_transport=upstream_transport,
            route_name=route_name,
        )
        text, truncated = truncate(extract_text(params), self._cfg.max_content_bytes)
        ctx_with_trunc = _with_truncated(ctx, truncated)

        with self._obs.span(
            "guardrail.check_request",
            method=method,
            tool=tool_name,
            transport=upstream_transport,
        ) as attrs:
            results: list[ScanResult] = []

            # Content scanners on the params text.
            scan_results = await self._run_scanners(text, "tool", self._c.request_scanners)
            results.extend(scan_results)

            # Invariant: record + evaluate toxic flow. Trace mutation must be
            # serialised so concurrent requests can't interleave half-calls.
            inv_result: ScanResult | None = None
            if self._c.invariant is not None:
                async with self._trace_lock:
                    self._c.invariant.record(tool_name, params.get("arguments", {}))
                    inv_result = self._c.invariant.evaluate_or_allow()
                results.append(inv_result)

            decision = self._c.aggregator.aggregate(results)
            attrs["outcome"] = (
                "deny" if decision.deny else ("mutated" if decision.is_mutated else "allow")
            )
            attrs["reason"] = decision.reason
            self._obs.record_decision(
                phase="request",
                method=method,
                tool_name=tool_name,
                ctx=ctx_with_trunc,
                decision=decision,
            )
            return decision

    async def check_response(
        self,
        *,
        method: str,
        service_names: Sequence[str],
        result: Any,
        upstream_transport: str = "",
        route_name: str = "",
    ) -> Decision:
        ctx = McpCallContext(
            method=method,
            service_names=tuple(service_names),
            result=result,
            upstream_transport=upstream_transport,
            route_name=route_name,
        )
        text, truncated = truncate(extract_text(result), self._cfg.max_content_bytes)
        ctx_with_trunc = _with_truncated(ctx, truncated)

        with self._obs.span(
            "guardrail.check_response",
            method=method,
            transport=upstream_transport,
        ) as attrs:
            results: list[ScanResult] = []
            first_stage = await self._run_scanners(text, "assistant", self._c.response_scanners)
            results.extend(first_stage)

            # Second stage: only when a first-stage scanner flagged HUMAN_REVIEW
            # and a second-stage (AgentAlignment) is configured. This bounds the
            # LLM-based alignment cost to suspicious responses only.
            if self._c.second_stage_scanners and any(
                r.outcome is ScanOutcome.HUMAN_REVIEW for r in first_stage
            ):
                second = await self._run_scanners(text, "assistant", self._c.second_stage_scanners)
                results.extend(second)
                attrs["second_stage"] = True

            # No Invariant on the response side; toxic-flow is a request-time
            # property. Response-side is purely content (indirect injection).
            decision = self._c.aggregator.aggregate(results)
            attrs["outcome"] = (
                "deny" if decision.deny else ("mutated" if decision.is_mutated else "allow")
            )
            attrs["reason"] = decision.reason
            self._obs.record_decision(
                phase="response",
                method=method,
                tool_name="",
                ctx=ctx_with_trunc,
                decision=decision,
            )
            return decision

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _run_scanners(
        self,
        content: str,
        role: str,
        scanners: Sequence[Scanner],
    ) -> list[ScanResult]:
        """Run all scanners concurrently, each with its own deadline.

        Scanners are independent (same input, no shared mutable state), so
        :func:`asyncio.gather` runs them in parallel.  Each scanner gets its
        own :func:`asyncio.wait_for` deadline and failure-mode handling, so a
        slow or failing scanner never blocks the others.
        """
        timeout = self._cfg.scanner_timeout_ms / 1000.0

        async def _scan_one(scanner: Scanner) -> ScanResult:
            name = getattr(scanner, "name", repr(scanner))
            with self._obs.span(
                f"scanner.{name}", scanner=name, role=role
            ) as attrs:
                attrs["outcome"] = "unknown"
                try:
                    result = await asyncio.wait_for(
                        scanner.scan(content, role),
                        timeout=timeout,
                    )
                    attrs["outcome"] = result.outcome.value
                    return result
                except asyncio.TimeoutError:
                    attrs["outcome"] = "timeout"
                    return self._failure_result(
                        name, f"timeout>{self._cfg.scanner_timeout_ms}ms"
                    )
                except Exception as exc:
                    attrs["outcome"] = "error"
                    attrs["error"] = f"{type(exc).__name__}:{exc}"
                    return self._failure_result(name, f"error:{type(exc).__name__}:{exc}")

        return list(await asyncio.gather(*(_scan_one(s) for s in scanners)))

    def _failure_result(self, scanner_name: str, reason: str) -> ScanResult:
        """Translate a scanner exception per the configured failure mode.

        ``failClosed`` -> BLOCK (deny). ``failOpen`` -> ALLOW (with a review
        flag so the audit log still records the degradation).
        """
        if self._cfg.failure_mode is FailureMode.FAIL_CLOSED:
            return ScanResult.block(scanner_name, reason, score=1.0)
        return ScanResult.review(scanner_name, f"failopen:{reason}")


def _with_truncated(ctx: McpCallContext, truncated: bool) -> McpCallContext:
    if not truncated:
        return ctx
    return replace(ctx, truncated=True)
