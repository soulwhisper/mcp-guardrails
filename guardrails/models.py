"""Core data types shared across the guardrail engine.

These types are deliberately dependency-free (pure dataclasses + enums) so the
policy core can be unit-tested without torch/transformers/grpc loaded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScanOutcome(str, Enum):
    """Three-state outcome produced by every scanner / rule evaluation.

    ``ALLOW``     — content is safe, forward unchanged.
    ``BLOCK``     — content violates policy, deny the exchange.
    ``HUMAN_REVIEW`` — suspicious but not confidently malicious; the
                      aggregator resolves this to pass+warn or deny based on
                      ``human_review_mode``.
    """

    ALLOW = "allow"
    BLOCK = "block"
    HUMAN_REVIEW = "human_review"


class FailureMode(str, Enum):
    """Behaviour when a scanner raises or the sidecar is degraded.

    ``failClosed`` — deny the exchange (preferred for write-capable agents).
    ``failOpen``   — allow the exchange (only when guardrail outage is judged
                     less harmful than blocking the agent).
    """

    FAIL_CLOSED = "failClosed"
    FAIL_OPEN = "failOpen"


class HumanReviewMode(str, Enum):
    """How ``HUMAN_REVIEW`` outcomes are resolved by the aggregator."""

    PASS = "pass"  # forward + emit audit warning
    DENY = "deny"  # escalate to a hard deny


@dataclass(frozen=True)
class ScanResult:
    """Result of a single scanner/rule evaluation."""

    scanner: str
    outcome: ScanOutcome
    reason: str = ""
    score: float = 0.0

    @staticmethod
    def allow(scanner: str) -> ScanResult:
        return ScanResult(scanner=scanner, outcome=ScanOutcome.ALLOW)

    @staticmethod
    def block(scanner: str, reason: str, score: float = 0.0) -> ScanResult:
        return ScanResult(scanner=scanner, outcome=ScanOutcome.BLOCK, reason=reason, score=score)

    @staticmethod
    def review(scanner: str, reason: str, score: float = 0.0) -> ScanResult:
        return ScanResult(
            scanner=scanner, outcome=ScanOutcome.HUMAN_REVIEW, reason=reason, score=score
        )


@dataclass(frozen=True)
class Decision:
    """Aggregated decision returned by :class:`GuardrailEngine`.

    ``mutated`` is a plain Python object (dict/list/str) that the servicer
    JSON-serialises back into the MCP payload bytes. ``None`` means "no
    mutation"; pass through unchanged.
    """

    deny: bool = False
    reason: str = ""
    mutated: Any | None = None
    human_review: bool = False
    scanners: tuple[ScanResult, ...] = field(default_factory=tuple)
    # Short correlation id minted by the engine per exchange. Recorded in the
    # audit decision line AND reused by the servicer's generalised deny reason,
    # so a tenant-reported ``ref`` always greps to the full internal record.
    ref: str = ""
    # Number of redaction substitutions applied to the forwarded payload
    # (0 when redaction did not run or matched nothing). Surfaced by the
    # servicer in the ``guardrail.redactions`` result metadata (F-P1-2).
    redactions: int = 0

    @property
    def is_mutated(self) -> bool:
        return self.mutated is not None


@dataclass(frozen=True)
class McpCallContext:
    """Normalised view of an MCP exchange passed into the engine.

    Captured once by the servicer from the protobuf request and threaded
    through every scanner so rules can inspect method/transport/headers
    without re-parsing wire bytes.
    """

    method: str
    service_names: tuple[str, ...] = ()
    tool_name: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    upstream_transport: str = ""
    route_name: str = ""
    truncated: bool = False
    # Scan coverage (S-H2): how many UTF-8 bytes of the extracted text the
    # scanners actually saw vs the payload's total size. Surfaced in the
    # audit record so operators can spot under-scanned giant payloads.
    scanned_bytes: int = 0
    total_bytes: int = 0
    # A-P0-1: audit-only correlation id for the MCP exchange, extracted by
    # the servicer from trusted agentgateway-injected channels
    # (metadata_context / x-request-id header, uuid8 fallback) — never from
    # the attacker-controlled payload. Independent of ``Decision.ref``,
    # which is always an engine-minted random uuid8 (PR-#65 semantics).
    exchange_id: str = ""
    # A-P1-1: whitelisted caller identity header (see
    # ``GuardrailConfig.audit_caller_headers``). Request side only — the
    # CheckResponse proto carries no headers.
    caller: str = ""
