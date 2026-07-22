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
   default). When nothing blocked and no review is pending, the redaction
   transformer structurally masks secrets/PII and attaches the rewritten
   payload as ``Decision.mutated`` (the proto ``mutated`` oneof).
6. Returns the :class:`Decision`.

The engine is concurrency-safe: invariant traces are isolated per route
(route name / first service name), guarded by the ``RulePack`` lock on swap
and a dedicated lock on append/evaluate.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from collections import deque
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
from .redaction import RedactionScanner
from .rules import RulePack
from .scanners import (
    AgentAlignmentScanner,
    OnnxPromptGuardScanner,
    RegexScanner,
    Scanner,
    StubScanner,
    extract_text,
    scan_windows,
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
    # Mutation-stage transformer. None -> the engine builds a default
    # RedactionScanner when config.enable_redaction is set; supply a stub in
    # tests to control substitutions deterministically.
    redactor: RedactionScanner | None = None
    invariant: InvariantEngine | None = None
    # The rule pack the invariant engine was built from; tracked so the audit
    # record can carry ``rules_version`` (A-P1-1). None -> version omitted.
    rule_pack: RulePack | None = None
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
        self._redactor: RedactionScanner | None = None
        if config.enable_redaction:
            self._redactor = components.redactor or RedactionScanner()
        self._ready = False
        # A-P1-1: rules_version surfaced in every audit line. reload_rules
        # swaps in a FRESH RulePack (whose internal version restarts at 0),
        # so the engine keeps a monotonic version: the pack's version at
        # construction plus one per successful reload.
        self._rules_version: int | str = (
            components.rule_pack.version if components.rule_pack is not None else ""
        )
        # A-P1-1: sidecar version for the audit line (env override via
        # GUARDRAIL_VERSION, else the package __version__).
        self._sidecar_version = config.sidecar_version or _package_version()
        # A-P0-4: sliding window of recent scan outcomes (True = ok,
        # False = error/timeout) feeding the runtime health verdict.
        self._scan_health: deque[bool] = deque(
            maxlen=max(1, config.unhealthy_scanner_window)
        )

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
                        review_threshold=config.pg_review_threshold,
                        local_dir=config.lf_onnx_local_dir,
                        revision=config.lf_onnx_revision,
                        max_windows=config.pg_max_windows,
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
        invariant = InvariantEngine(
            rule_pack.rules,
            window=config.invariant_window,
            max_traces=config.invariant_max_traces,
            args_max_bytes=config.invariant_args_max_bytes,
            sticky_ttl_s=config.invariant_sticky_ttl_s,
        )

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
            rule_pack=rule_pack,
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
        for scanner in list(self._c.request_scanners + self._c.response_scanners):
            try:
                await asyncio.wait_for(
                    scanner.scan("", "tool"),
                    timeout=30.0,
                )
            except ImportError as exc:
                # Optional dependency not installed (e.g. onnxruntime /
                # transformers missing): the scanner can NEVER work in this
                # process, so keeping it would make every scan raise and —
                # under failClosed — deny all traffic. Drop it and continue
                # with the remaining scanners (regex-only fallback), which is
                # what from_config's ImportError guard always promised.
                # Distinct from a model-load failure (deps present, weights
                # broken), which stays fail-closed below.
                self._drop_scanner(scanner)
                logger.warning(
                    "scanner %s unavailable (%s); removed from the scan chain — "
                    "continuing with the remaining scanners. Install the missing "
                    "dependency and restart to re-enable it.",
                    getattr(scanner, "name", scanner),
                    exc,
                )
            except Exception as exc:  # pragma: no cover - warmup best-effort
                logger.warning(
                    "warmup of scanner %s failed: %s", getattr(scanner, "name", scanner), exc
                )
        self._ready = True
        logger.info("guardrail engine warmed up (ready=%s)", self._ready)

    def _drop_scanner(self, scanner: Scanner) -> None:
        """Remove ``scanner`` from every phase list (identity match).

        Shared instance objects may sit in both the request and response
        lists, so filter by identity from all of them.
        """
        for lst in (
            self._c.request_scanners,
            self._c.response_scanners,
            self._c.second_stage_scanners,
        ):
            lst[:] = [s for s in lst if s is not scanner]

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def healthy(self) -> bool:
        """Runtime health verdict (A-P0-4), driving gRPC health.

        False when (a) warmup has not completed (``awarm`` still running —
        the server must stay out of rotation), or (b) the sliding-window
        scanner error/timeout rate exceeds
        ``config.unhealthy_scanner_error_rate`` once at least
        ``config.unhealthy_scanner_min_samples`` scan invocations were
        recorded. The verdict recovers automatically as old failures age out
        of the window. Tracked independently of ``FAILURE_MODE``: under
        ``failOpen`` exchanges still flow, but the degradation flips health
        to NOT_SERVING so the dataplane/orchestrator can see it.
        """
        if not self._ready:
            return False
        samples = len(self._scan_health)
        if samples < max(1, self._cfg.unhealthy_scanner_min_samples):
            return True
        errors = sum(1 for ok in self._scan_health if not ok)
        return (errors / samples) <= self._cfg.unhealthy_scanner_error_rate

    def reload_rules(self) -> int:
        """Hot-reload the Invariant rule pack (SIGHUP handler).

        Re-resolves the rule pack from the configured source (env-driven, see
        :func:`guardrails.rules.load_rules`) and atomically swaps it into the
        invariant engine. Returns the new rule count, or 0 if no invariant
        engine is configured. Safe to call while requests are in flight:
        :meth:`InvariantEngine.set_rules` replaces the rule-list reference, so
        an evaluation already in progress keeps iterating the old list.

        A-P1-3: success AND failure both emit a ``rules_reload`` audit line
        (with the new ``rules_version`` / error detail) and bump the
        ``mcp.guardrails.rules_reload{result}`` counter, so a broken reload
        is visible in the durable audit record — not just stderr.
        """
        if self._c.invariant is None:
            return 0
        try:
            fresh = RulePack.from_env()
        except Exception as exc:
            self._obs.record_reload_audit(
                ok=False,
                rules_version=self._rules_version,
                error=f"{type(exc).__name__}:{exc}",
                sidecar_version=self._sidecar_version,
            )
            raise
        self._c.invariant.set_rules(fresh.rules)
        # The fresh pack's internal version restarts at 0 (it is a new
        # object), so the engine keeps its own monotonic version.
        if isinstance(self._rules_version, int):
            self._rules_version += 1
        else:
            self._rules_version = fresh.version
        self._c.rule_pack = fresh
        self._obs.record_reload_audit(
            ok=True,
            rules_version=self._rules_version,
            rule_count=len(fresh.rules),
            sidecar_version=self._sidecar_version,
        )
        logger.info(
            "invariant rules reloaded (v%s, %d rules)", self._rules_version, len(fresh.rules)
        )
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
        exchange_id: str = "",
    ) -> Decision:
        start = time.perf_counter()
        caller = _whitelisted_caller(headers, self._cfg.audit_caller_headers)
        ctx = McpCallContext(
            method=method,
            service_names=tuple(service_names),
            tool_name=tool_name,
            params=dict(params),
            headers=dict(headers),
            upstream_transport=upstream_transport,
            route_name=route_name,
            exchange_id=exchange_id,
            caller=caller,
        )
        # PR-#65 semantics: the ref is ALWAYS an engine-minted random uuid8
        # (unique, unguessable) — it is what the wire deny reason exposes.
        # The servicer-supplied exchange_id is a separate audit-only
        # correlation field; it must never become the wire ref, otherwise a
        # dataplane-supplied (potentially guessable) id leaks onto the wire.
        ref = uuid.uuid4().hex[:8]
        extracted = extract_text(params)
        texts, truncated, scanned_bytes, total_bytes = self._scan_chunks(extracted)
        payload_sha256 = _payload_digest(extracted)
        ctx_with_trunc = _with_scan_coverage(ctx, truncated, scanned_bytes, total_bytes)

        with self._obs.span(
            "guardrail.check_request",
            method=method,
            tool=tool_name,
            transport=upstream_transport,
        ) as attrs:
            attrs["exchange_id"] = exchange_id or ref
            if caller:
                attrs["caller"] = caller
            attrs["payload_sha256"] = payload_sha256
            attrs["rules_version"] = self._rules_version
            results: list[ScanResult] = []
            results.extend(self._payload_size_results(total_bytes, scanned_bytes))

            # F-P1-5: tool-level ACL, applied BEFORE any content scanner.
            # DENY wins; a non-empty ALLOW list is a whitelist. The wire
            # reason is generalised by the servicer; the tool name is already
            # an audit field, so recording it here adds no new disclosure.
            if method == "tools/call" and tool_name:
                acl_hit = _tool_acl_violation(
                    tool_name, self._cfg.allow_tools, self._cfg.deny_tools
                )
                if acl_hit is not None:
                    results.append(acl_hit)

            # Content scanners on the params text (head/mid/tail windows when
            # over budget, so padding cannot hide an injection past the cut
            # or between the head and tail windows). The McpCallContext is
            # threaded through so context-aware scanners can inspect method /
            # headers / transport without re-parsing wire bytes.
            if not any(r.outcome is ScanOutcome.BLOCK for r in results):
                for text in texts:
                    scan_results = await self._run_scanners(
                        text, "tool", self._c.request_scanners, context=ctx
                    )
                    results.extend(scan_results)

            # Invariant: record + evaluate toxic flow against THIS route's
            # trace. Trace mutation must be serialised so concurrent requests
            # can't interleave half-calls.
            inv_result: ScanResult | None = None
            if self._c.invariant is not None:
                trace_key = _trace_key(
                    route_name,
                    service_names,
                    headers,
                    self._cfg.invariant_trace_key_headers,
                )
                async with self._trace_lock:
                    # F-P1-6: only genuine tool calls enter the trace —
                    # other methods (or a tools/call with an empty name)
                    # would pollute the window with nameless entries.
                    if method == "tools/call" and tool_name:
                        self._c.invariant.record(
                            tool_name, params.get("arguments", {}), key=trace_key
                        )
                    inv_result = self._c.invariant.evaluate_or_allow(key=trace_key)
                results.append(inv_result)

            decision = self._c.aggregator.aggregate(results)

            # Mutation stage (opt-in on the request side): redact secrets/PII
            # inside params.arguments. Runs when nothing blocked; review
            # payloads are redacted too when REDACT_ON_REVIEW=1 (default).
            if self._cfg.redact_request_params:
                args = params.get("arguments")
                if args is not None:
                    mutated_args, n = await self._redact(args, decision, attrs)
                    if n:
                        decision = replace(
                            decision,
                            mutated={**dict(params), "arguments": mutated_args},
                            reason=_redaction_reason(decision.reason, n),
                            redactions=n,
                        )

            # Mint/attach the per-exchange correlation ref BEFORE the audit
            # record is emitted, so the servicer's generalised deny reason and
            # the audit line share the same ref (S-M5 follow-up).
            decision = replace(decision, ref=decision.ref or ref)
            attrs["outcome"] = (
                "deny" if decision.deny else ("mutated" if decision.is_mutated else "allow")
            )
            attrs["reason"] = decision.reason
            attrs["ref"] = decision.ref
            self._obs.record_decision(
                phase="request",
                method=method,
                tool_name=tool_name,
                ctx=ctx_with_trunc,
                decision=decision,
                payload_sha256=payload_sha256,
                rules_version=self._rules_version,
                sidecar_version=self._sidecar_version,
                duration_ms=(time.perf_counter() - start) * 1000.0,
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
        exchange_id: str = "",
    ) -> Decision:
        start = time.perf_counter()
        ctx = McpCallContext(
            method=method,
            service_names=tuple(service_names),
            result=result,
            upstream_transport=upstream_transport,
            route_name=route_name,
            exchange_id=exchange_id,
        )
        # A-P0-1 / PR-#65: ref is always an engine-minted random uuid8 (see
        # check_request). When the dataplane supplies the same exchange_id on
        # both RPCs of an exchange, the two audit lines still grep together
        # via the exchange_id field.
        ref = uuid.uuid4().hex[:8]
        extracted = extract_text(result)
        texts, truncated, scanned_bytes, total_bytes = self._scan_chunks(extracted)
        payload_sha256 = _payload_digest(extracted)
        ctx_with_trunc = _with_scan_coverage(ctx, truncated, scanned_bytes, total_bytes)

        with self._obs.span(
            "guardrail.check_response",
            method=method,
            transport=upstream_transport,
        ) as attrs:
            attrs["exchange_id"] = exchange_id or ref
            attrs["payload_sha256"] = payload_sha256
            attrs["rules_version"] = self._rules_version
            results: list[ScanResult] = []
            results.extend(self._payload_size_results(total_bytes, scanned_bytes))
            first_stage: list[ScanResult] = []
            flagged_chunks: list[str] = []
            for text in texts:
                chunk_results = await self._run_scanners(
                    text, "assistant", self._c.response_scanners, context=ctx
                )
                first_stage.extend(chunk_results)
                if any(r.outcome is ScanOutcome.HUMAN_REVIEW for r in chunk_results):
                    flagged_chunks.append(text)
            results.extend(first_stage)

            # Second stage: only when a first-stage scanner flagged HUMAN_REVIEW
            # and a second-stage (AgentAlignment) is configured. Only the
            # flagged chunk(s) are re-scanned, bounding the LLM-based alignment
            # cost to suspicious content only.
            if self._c.second_stage_scanners and flagged_chunks:
                # Trajectory context for the second stage: the last few tool
                # calls this route/session made, so AgentAlignment judges the
                # flagged chunk against the agent's recent behaviour. The
                # response proto carries no headers, so the key falls back to
                # the route dimension when session-header templating is on.
                ctx_second = _with_trace_summary(ctx, self._c.invariant, route_name, service_names)
                for text in flagged_chunks:
                    second = await self._run_scanners(
                        text, "assistant", self._c.second_stage_scanners, context=ctx_second
                    )
                    results.extend(second)
                attrs["second_stage"] = True

            # No Invariant on the response side; toxic-flow is a request-time
            # property. Response-side is purely content (indirect injection).
            decision = self._c.aggregator.aggregate(results)

            # Mutation stage: structurally redact secrets/PII in the result.
            # A BLOCK always wins (no mutation). HUMAN_REVIEW payloads are
            # redacted too when REDACT_ON_REVIEW=1 (default): the review
            # verdict is preserved and the mutated payload rides alongside,
            # so review-grade PII is masked on the wire.
            mutated_result, n = await self._redact(result, decision, attrs)
            if mutated_result is not None:
                decision = replace(
                    decision,
                    mutated=mutated_result,
                    reason=_redaction_reason(decision.reason, n),
                    redactions=n,
                )

            decision = replace(decision, ref=decision.ref or ref)
            attrs["outcome"] = (
                "deny" if decision.deny else ("mutated" if decision.is_mutated else "allow")
            )
            attrs["reason"] = decision.reason
            attrs["ref"] = decision.ref
            self._obs.record_decision(
                phase="response",
                method=method,
                # Response side has no tool name on the wire (the JSON-RPC
                # envelope id is not forwarded); the exchange_id, method and
                # route provide the correlation instead (A-P0-1).
                tool_name="",
                ctx=ctx_with_trunc,
                decision=decision,
                payload_sha256=payload_sha256,
                rules_version=self._rules_version,
                sidecar_version=self._sidecar_version,
                duration_ms=(time.perf_counter() - start) * 1000.0,
            )
            return decision

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _scan_chunks(self, text: str) -> tuple[list[str], bool, int, int]:
        """Split extracted text into scan windows and measure coverage.

        Returns ``(chunks, truncated, scanned_bytes, total_bytes)``.
        ``scanned_bytes`` is the number of distinct payload bytes covered by
        the returned windows (capped at ``total_bytes``).
        """
        texts, truncated = scan_windows(
            text, self._cfg.max_content_bytes, self._cfg.scan_tail_bytes
        )
        total_bytes = len(text.encode("utf-8", errors="ignore"))
        scanned = sum(len(t.encode("utf-8", errors="ignore")) for t in texts)
        return texts, truncated, min(scanned, total_bytes), total_bytes

    def _payload_size_results(self, total_bytes: int, scanned_bytes: int) -> list[ScanResult]:
        """S-H2: flag payloads beyond the SCAN_MAX_PAYLOAD_BYTES hard cap.

        The payload is still scanned (head/mid/tail windows) as usual; on top
        of that we attach a HUMAN_REVIEW result from a synthetic
        ``payload_size`` scanner so the aggregator escalates per
        ``HUMAN_REVIEW_MODE`` (pass+warn or deny) — under fail-closed review
        handling a giant, mostly-unscanned payload can never sail through
        silently. The reason carries scanned/total bytes for the audit log.
        """
        if self._cfg.scan_max_payload_bytes <= 0 or total_bytes <= self._cfg.scan_max_payload_bytes:
            return []
        return [
            ScanResult.review(
                "payload_size",
                f"payload exceeds scan hard limit: scanned {scanned_bytes} of "
                f"{total_bytes} bytes (limit {self._cfg.scan_max_payload_bytes})",
                score=1.0,
            )
        ]

    async def _redact(
        self, value: Any, decision: Decision, attrs: dict[str, Any]
    ) -> tuple[Any | None, int]:
        """Run the redaction transformer when policy permits mutation.

        Returns ``(redacted_value, substitutions)``; ``redacted_value`` is
        ``None`` when redaction is disabled, the decision is a deny, the
        decision is a human-review pass and ``config.redact_on_review`` is
        off (S-H3: with it on — the default — review payloads ARE redacted;
        the review verdict is kept and the mutated payload rides along, so
        review-grade PII/credentials are masked instead of passing through
        verbatim), the payload exceeds ``config.redaction_max_bytes``, or
        nothing matched. On hits the span gets a ``redactions=N`` attribute;
        the audit line picks it up via the span exit hook, and the decision
        audit record keeps the review outcome alongside.

        Two guards keep redaction off the request hot path:

        - **Size cap** — payloads larger than ``REDACTION_MAX_BYTES``
          (default 256KiB) skip redaction entirely and pass through
          unchanged, flagged ``redaction_skipped=size`` in the audit span.
          Safe because scanner BLOCK decisions still apply upstream: an
          over-cap payload carrying block-grade secrets is denied by the
          RegexScanner on the head+tail ``scan_windows`` before redaction
          would ever run. Only best-effort masking of ALLOW-grade PII is
          skipped.
        - **Thread offload** — the ~11-pattern regex sweep runs via
          :func:`asyncio.to_thread`, so a large (but under-cap) payload
          cannot stall the event loop and starve concurrent exchanges.
        """
        if self._redactor is None or decision.deny:
            return None, 0
        if decision.human_review and not self._cfg.redact_on_review:
            return None, 0
        if _payload_bytes(value) > self._cfg.redaction_max_bytes:
            attrs["redaction_skipped"] = "size"
            return None, 0
        redacted, n = await asyncio.to_thread(self._redactor.redact_value, value)
        if n == 0:
            return None, 0
        attrs["redactions"] = n
        self._obs.record_redactions(n)  # A-P1-2: redactions_total counter
        return redacted, n

    async def _run_scanners(
        self,
        content: str,
        role: str,
        scanners: Sequence[Scanner],
        *,
        context: McpCallContext | None = None,
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
            with self._obs.span(f"scanner.{name}", scanner=name, role=role) as attrs:
                attrs["outcome"] = "unknown"
                try:
                    result = await asyncio.wait_for(
                        scanner.scan(content, role, context=context),
                        timeout=timeout,
                    )
                    attrs["outcome"] = result.outcome.value
                    self._scan_health.append(True)  # A-P0-4
                    return result
                except asyncio.TimeoutError:
                    attrs["outcome"] = "timeout"
                    self._scan_health.append(False)  # A-P0-4
                    return self._failure_result(name, f"timeout>{self._cfg.scanner_timeout_ms}ms")
                except Exception as exc:
                    attrs["outcome"] = "error"
                    attrs["error"] = f"{type(exc).__name__}:{exc}"
                    self._scan_health.append(False)  # A-P0-4
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


def _trace_key(
    route_name: str,
    service_names: Sequence[str],
    headers: Mapping[str, str],
    key_headers: Sequence[str],
) -> str:
    """Compute the Invariant trace key (S-H5 / F-P0-1(b)).

    Default: ``route_name`` (falling back to the first service name) — the
    legacy route dimension. When ``INVARIANT_TRACE_KEY_HEADERS`` is configured
    and one of those headers (case-insensitive) is present, its value extends
    the key (``route|header=value``), isolating toxic-flow traces per caller /
    session: two sessions on the same route can no longer assemble a
    cross-session toxic flow or trip each other's loop rules. A missing
    header falls back to the route dimension, so deployments without a
    session header keep the current behaviour.
    """
    base = route_name or (service_names[0] if service_names else "")
    if key_headers:
        lowered = {str(k).lower(): v for k, v in headers.items()}
        for name in key_headers:
            value = lowered.get(str(name).lower())
            if value:
                # Cap the header contribution: it is attacker-influenced and
                # keys an LRU map, so length is bounded (the map's max_traces
                # cap already bounds cardinality).
                return f"{base}|{name}={str(value)[:128]}"
    return base


def _with_trace_summary(
    ctx: McpCallContext,
    invariant: InvariantEngine | None,
    route_name: str,
    service_names: Sequence[str],
    *,
    last_n: int = 5,
) -> McpCallContext:
    """Attach a recent-tool-call summary for second-stage scanners.

    The summary is the names of the last ``last_n`` calls in this route's
    Invariant trace (oldest first, comma-separated) — e.g.
    ``"inbox_read, fs_read, email_send"``. No args/content are included:
    the summary reaches an external LLM, so it stays metadata-only.
    """
    if invariant is None:
        return ctx
    key = route_name or (service_names[0] if service_names else "")
    snapshot = invariant.snapshot(key=key)
    if not snapshot:
        return ctx
    summary = ", ".join(entry.tool for entry in snapshot[-last_n:])
    return replace(ctx, trace_summary=summary)


def _tool_acl_match(tool: str, patterns: Sequence[str]) -> str | None:
    """Return the first ACL pattern matching ``tool``, else None.

    Patterns are exact tool names or ``prefix/*`` wildcards (``fs/*`` matches
    ``fs/read`` but not ``fsx/read``).
    """
    for pat in patterns:
        if pat.endswith("/*"):
            if tool.startswith(pat[:-1]):
                return pat
        elif tool == pat:
            return pat
    return None


def _tool_acl_violation(
    tool: str, allow: Sequence[str], deny: Sequence[str]
) -> ScanResult | None:
    """F-P1-5 tool-level ACL: DENY wins; a non-empty ALLOW is a whitelist.

    The reason carries the tool name for the audit log (the tool name is
    already a top-level audit field, so this discloses nothing new); the
    servicer generalises the wire-visible deny reason as usual.
    """
    if _tool_acl_match(tool, deny) is not None:
        return ScanResult.block(
            "tool_acl", f"tool {tool!r} denied by tool ACL", score=1.0
        )
    if allow and _tool_acl_match(tool, allow) is None:
        return ScanResult.block(
            "tool_acl", f"tool {tool!r} not in tool allowlist", score=1.0
        )
    return None


def _payload_bytes(value: Any) -> int:
    """Approximate serialized byte size of a redaction candidate.

    Used to enforce ``REDACTION_MAX_BYTES`` before running the regex sweep.
    Strings are measured directly; structured values go through
    :func:`json.dumps` (C-speed, so even a multi-MB payload costs far less
    than one regex pass). Underserializable values return 0 — they cannot
    contain redactable strings the JSON wire would carry anyway.
    """
    if isinstance(value, str):
        return len(value.encode("utf-8", "ignore"))
    try:
        return len(json.dumps(value, default=str).encode("utf-8", "ignore"))
    except (TypeError, ValueError):
        return 0


def _redaction_reason(reason: str, n: int) -> str:
    """Fold a redaction hit-count marker into a decision reason for audit."""
    tag = f"redaction:{n} substitution(s)"
    return f"{reason};{tag}" if reason else tag


def _with_scan_coverage(
    ctx: McpCallContext, truncated: bool, scanned_bytes: int, total_bytes: int
) -> McpCallContext:
    """Attach scan-coverage metadata to the audit context."""
    return replace(
        ctx, truncated=truncated, scanned_bytes=scanned_bytes, total_bytes=total_bytes
    )


def _package_version() -> str:
    """Sidecar version for audit lines; empty string when unresolvable."""
    try:
        from . import __version__

        return __version__
    except Exception:  # pragma: no cover - defensive
        return ""


def _whitelisted_caller(
    headers: Mapping[str, str], whitelist: Sequence[str]
) -> str:
    """Return the first whitelisted caller header value (A-P1-1).

    Header lookup is case-insensitive (HTTP/2 lowercases, but tests and
    alternate dataplanes may not). Only headers named in
    ``GuardrailConfig.audit_caller_headers`` are ever copied — arbitrary
    headers can carry bearer tokens / cookies and must not reach the audit
    log.
    """
    if not whitelist:
        return ""
    lowered = {str(k).lower(): v for k, v in headers.items()}
    for name in whitelist:
        value = lowered.get(name.lower())
        if value:
            return str(value)[:256]
    return ""


def _payload_digest(text: str) -> str:
    """12-hex-char SHA-256 prefix of the scanned text (A-P1-1).

    Lets an operator prove two audit lines saw the same payload without the
    audit log storing any payload content.
    """
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:12]
