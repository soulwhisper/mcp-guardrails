"""ExtMcp gRPC servicer — the wire boundary between agentgateway and the
guardrail engine.

Two RPCs:

* ``CheckRequest`` — deserialises ``McpRequest.mcp_request`` (raw JSON-RPC
  params) and delegates to :meth:`GuardrailEngine.check_request`.
* ``CheckResponse`` — deserialises ``McpResponse.mcp_response`` (raw JSON-RPC
  result) and delegates to :meth:`GuardrailEngine.check_response`.

Both map the engine's :class:`Decision` to the upstream protobuf oneof
``{pass, mutated, error}``:

* deny        -> ``error`` with ``PERMISSION_DENIED``
* mutated     -> ``mutated`` (raw JSON bytes)
* otherwise   -> ``pass`` (Pass)

Malformed payloads map to ``INVALID`` (fail-closed on parse failure).
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Mapping
from typing import Any

from google.protobuf import struct_pb2
from google.protobuf.json_format import MessageToDict

from .engine import GuardrailEngine
from .models import Decision, ScanOutcome
from .proto_bridge import pb, pbg

logger = logging.getLogger("mcp.guardrails.servicer")


def _safe_json_loads(raw: bytes, *, allow_absent: bool = False) -> tuple[Any, str]:
    """Return ``(parsed_or_None, error_message)``."""
    if not raw:
        if allow_absent:
            return {}, ""
        return None, "empty json payload"
    try:
        return json.loads(raw), ""
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"invalid json payload: {exc}"


def _extract_metadata(request: Any) -> tuple[str, str]:
    """Pull (upstream_transport, route_name) from the Struct metadata context."""
    try:
        if not request.HasField("metadata_context"):
            return "", ""
        md = MessageToDict(request.metadata_context)
    except (ValueError, TypeError):
        return "", ""
    transport = str(md.get("upstream_transport", "") or "")
    route = str(md.get("route_name", "") or "")
    return transport, route


# metadata_context keys probed for a per-exchange correlation id, in priority
# order. agentgateway deployments can inject any of these (e.g. from an
# x-request-id header at the gateway edge) to make the request/response
# audit lines of one MCP exchange grep together.
_EXCHANGE_ID_METADATA_KEYS = ("exchange_id", "request_id", "x_request_id", "trace_id")


def _sanitize_exchange_id(value: Any) -> str:
    """Reduce a candidate correlation id to a log-safe token.

    Strips whitespace, removes CR/LF and every other C0/C1 control character
    (a raw ``\\n`` would otherwise allow audit-log line injection), and caps
    the length at 64 chars so a garbage id cannot bloat the audit line.
    Returns "" when nothing usable remains (caller falls through to the next
    resolution source / uuid8).
    """
    text = str(value).strip()
    # C0 controls (incl. \r \n \t), DEL and C1 controls.
    cleaned = "".join(
        ch for ch in text if ch >= " " and ch != "\x7f" and not "\x80" <= ch <= "\x9f"
    )
    return cleaned[:64]


def _extract_exchange_id(request: Any, headers: Mapping[str, str] | None = None) -> str:
    """Resolve the exchange correlation id (A-P0-1).

    ``McpRequest.mcp_request`` / ``McpResponse.mcp_response`` carry the
    JSON-RPC ``params`` / ``result`` BODY — attacker-controlled data — so
    the payload is NEVER consulted for a correlation id (an ``id`` member
    there could be forged to pin one tenant's deny on another tenant's
    exchange). Only trusted, agentgateway-injected channels are used.
    Resolution order:

    1. a correlation key in the agentgateway ``metadata_context`` Struct
       (``exchange_id`` / ``request_id`` / ``x_request_id`` / ``trace_id``).
       TRUST ASSUMPTION: ``metadata_context`` is populated by the
       agentgateway dataplane (e.g. from an edge ``x-request-id``), not by
       the end client — deployments must not let callers set these keys;
    2. the ``x-request-id`` header (request side only — the CheckResponse
       proto carries no headers), likewise forwarded by the gateway;
    3. a fresh uuid8, guaranteeing uniqueness per side.

    Every accepted candidate is sanitised (control chars removed, length
    capped) before use. The returned id rides the audit record's
    ``exchange_id`` field only; the engine mints its own random uuid8
    ``ref`` for the wire deny reason, so a correlation id supplied here can
    never be used to pre-compute or spoof a wire ref.
    """
    try:
        if request.HasField("metadata_context"):
            md = MessageToDict(request.metadata_context)
            for key in _EXCHANGE_ID_METADATA_KEYS:
                value = md.get(key)
                if value not in (None, ""):
                    candidate = _sanitize_exchange_id(value)
                    if candidate:
                        return candidate
    except (ValueError, TypeError):
        pass
    if headers:
        for key, value in headers.items():
            if key.lower() == "x-request-id" and value:
                candidate = _sanitize_exchange_id(value)
                if candidate:
                    return candidate
    return uuid.uuid4().hex[:8]


def _request_pass() -> Any:
    # `pass` is a Python keyword, so it cannot be used as a protobuf
    # constructor kwarg. Set the oneof member through getattr instead.
    result = pb.McpRequestResult()
    getattr(result, "pass").CopyFrom(pb.Pass())
    return result


def _response_pass() -> Any:
    result = pb.McpResponseResult()
    getattr(result, "pass").CopyFrom(pb.Pass())
    return result


def _public_deny_reason(phase: str, internal_reason: str, ref: str = "") -> str:
    """Generalise a deny reason for the wire (S-M5 / A-P1-4).

    The engine's internal reason names the offending scanner and pattern and
    may carry match fingerprints — exactly the feedback an attacker needs to
    iterate a payload until it passes. The external (proto / MCP-visible)
    reason is therefore a fixed generic string plus a short correlation id
    that an operator can grep in the audit log, where the FULL internal
    reason is still recorded (audit behaviour is unchanged).

    The correlation id is minted by the engine per exchange and threaded here
    via ``decision.ref``, so the exact ref a tenant reports greps to the audit
    decision line (which carries the full internal reason). The uuid fallback
    only fires for decisions built outside the engine (defensive).
    """
    if not ref:
        ref = uuid.uuid4().hex[:8]
    _ = internal_reason  # retained in the audit record, never on the wire
    return f"denied by {phase} policy (ref {ref})"


# F-P1-1: generalised scanner categories for the structured mcp_error body.
# The blocking scanner's raw name (``regex:aws_access_key``,
# ``invariant:<rule>``) leaks pattern/rule identity to the caller, so the
# wire body only carries the CLASS of policy that fired plus a generic
# remediation hint. Full detail stays in the audit log (grep via ``ref``).
_DENY_CATEGORY: dict[str, tuple[str, str]] = {
    "tool_acl": ("tool_policy", "call a tool permitted by policy"),
    "invariant": ("tool_flow", "avoid the denied sequence of tool calls"),
    "payload_size": ("payload_size", "reduce the payload size"),
    "regex": (
        "content_policy",
        "remove credentials, PII or instruction markers from tool arguments",
    ),
    "onnx-promptguard": (
        "prompt_injection",
        "rephrase the request without embedded instructions",
    ),
}
_DEFAULT_CATEGORY = ("policy", "adjust the payload and retry")


def _deny_category(decision: Decision) -> tuple[str, str]:
    """Map the first blocking scanner to a generalised (category, remedy)."""
    for r in decision.scanners:
        if r.outcome is ScanOutcome.BLOCK:
            klass = r.scanner.split(":", 1)[0]
            return _DENY_CATEGORY.get(klass, _DEFAULT_CATEGORY)
    return _DEFAULT_CATEGORY


def _mcp_error_body(decision: Decision, phase: str, reason: str) -> bytes:
    """Build the structured JSON-RPC error body (F-P1-1).

    agentgateway forwards ``AuthorizationError.mcp_error`` as the JSON-RPC
    error returned to the MCP client. The body mirrors the generalised wire
    ``reason`` in ``message`` and adds a generalised category + remediation
    hint in ``data`` — never pattern names, rule internals or match detail.
    """
    category, remedy = _deny_category(decision)
    ref = decision.ref or uuid.uuid4().hex[:8]
    body = {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": -32001,
            "message": reason,
            "data": {
                "ref": ref,
                "phase": phase,
                "category": category,
                "remedy": remedy,
            },
        },
    }
    return json.dumps(body).encode("utf-8")


def _result_metadata(decision: Decision, exchange_id: str) -> Any:
    """Populate ``McpRequestResult.metadata`` (F-P1-2).

    Emits the guardrail observability fields the dataplane can log/route on
    without parsing the audit stream:

    * ``guardrail.scan_score``  — highest scanner score seen this exchange;
    * ``guardrail.rules_hit``   — invariant rule names that fired;
    * ``guardrail.redactions``  — redaction substitution count;
    * ``guardrail.exchange_id`` — the trusted correlation id;
    * ``guardrail.outcome``     — allow | mutated | deny.

    Response side: ``McpResponseResult`` carries no ``metadata`` field in the
    proto (only ``McpRequestResult`` does), so this is request-side only.
    ``header_mutation`` is deliberately NOT emitted: injecting a caller-visible
    ``x-guardrail-ref`` header would let a tenant correlate their own denies
    without audit access — which the wire ``ref`` already provides — and the
    evaluation ranked it low priority; revisit if a dataplane use case lands.
    """
    scan_score = max((r.score for r in decision.scanners), default=0.0)
    rules_hit = [
        r.scanner.split(":", 1)[1]
        for r in decision.scanners
        if r.scanner.startswith("invariant:") and r.outcome is ScanOutcome.BLOCK
    ]
    outcome = "deny" if decision.deny else ("mutated" if decision.is_mutated else "allow")
    struct = struct_pb2.Struct()
    struct.update(
        {
            "guardrail.scan_score": scan_score,
            "guardrail.rules_hit": rules_hit,
            "guardrail.redactions": decision.redactions,
            "guardrail.exchange_id": exchange_id or decision.ref,
            "guardrail.outcome": outcome,
        }
    )
    return struct


def _build_request_result(
    decision: Decision, parse_error: str, exchange_id: str = ""
):
    if parse_error:
        return pb.McpRequestResult(
            error=pb.AuthorizationError(
                code=pb.AuthorizationError.INVALID,
                reason=parse_error,
            )
        )
    metadata = _result_metadata(decision, exchange_id)
    if decision.deny:
        reason = _public_deny_reason("content", decision.reason, decision.ref)
        return pb.McpRequestResult(
            error=pb.AuthorizationError(
                code=pb.AuthorizationError.PERMISSION_DENIED,
                reason=reason,
                mcp_error=_mcp_error_body(decision, "content", reason),
            ),
            metadata=metadata,
        )
    if decision.is_mutated:
        return pb.McpRequestResult(
            mutated=json.dumps(decision.mutated).encode("utf-8"),
            metadata=metadata,
        )
    result = _request_pass()
    result.metadata.CopyFrom(metadata)
    return result


def _build_response_result(decision: Decision, parse_error: str):
    if parse_error:
        return pb.McpResponseResult(
            error=pb.AuthorizationError(
                code=pb.AuthorizationError.INVALID,
                reason=parse_error,
            )
        )
    if decision.deny:
        reason = _public_deny_reason("response", decision.reason, decision.ref)
        # NOTE: McpResponseResult has no `metadata` field in the proto, so
        # the F-P1-2 metadata emission is request-side only (see
        # _result_metadata). The structured mcp_error body IS emitted here.
        return pb.McpResponseResult(
            error=pb.AuthorizationError(
                code=pb.AuthorizationError.PERMISSION_DENIED,
                reason=reason,
                mcp_error=_mcp_error_body(decision, "response", reason),
            )
        )
    if decision.is_mutated:
        return pb.McpResponseResult(
            mutated=json.dumps(decision.mutated).encode("utf-8")
        )
    return _response_pass()


class ExtMcpServicer(pbg.ExtMcpServicer):
    """gRPC servicer fronting :class:`GuardrailEngine`."""

    def __init__(self, engine: GuardrailEngine):
        self._e = engine

    async def CheckRequest(self, request, context):
        has_payload = request.HasField("mcp_request")
        params, parse_error = _safe_json_loads(
            request.mcp_request if has_payload else b"",
            allow_absent=not has_payload,
        )
        transport, route = _extract_metadata(request)
        if parse_error:
            return _build_request_result(Decision(deny=False), parse_error)

        tool_name = ""
        if request.method == "tools/call" and isinstance(params, dict):
            tool_name = str(params.get("name", ""))

        headers = {
            h.key: h.value.decode("utf-8", errors="replace") for h in request.headers
        }
        exchange_id = _extract_exchange_id(request, headers)

        try:
            decision = await self._e.check_request(
                method=request.method,
                service_names=list(request.service_names),
                tool_name=tool_name,
                params=params if isinstance(params, dict) else {"_raw": params},
                headers=headers,
                upstream_transport=transport,
                route_name=route,
                exchange_id=exchange_id,
            )
        except Exception:  # pragma: no cover - defensive
            # S-M5: the exception detail (type names, paths, model errors)
            # goes to the log/audit only; the wire gets a fixed string so a
            # caller cannot probe internal failure modes.
            logger.exception("CheckRequest engine error")
            return pb.McpRequestResult(
                error=pb.AuthorizationError(
                    code=pb.AuthorizationError.PERMISSION_DENIED,
                    reason="engine_error",
                )
            )
        return _build_request_result(decision, "", exchange_id)

    async def CheckResponse(self, request, context):
        result, parse_error = _safe_json_loads(request.mcp_response)
        transport, route = _extract_metadata(request)
        if parse_error:
            return _build_response_result(Decision(deny=False), parse_error)
        exchange_id = _extract_exchange_id(request, result)

        try:
            decision = await self._e.check_response(
                method=request.method,
                service_names=list(request.service_names),
                result=result,
                upstream_transport=transport,
                route_name=route,
                exchange_id=exchange_id,
            )
        except Exception:  # pragma: no cover - defensive
            logger.exception("CheckResponse engine error")
            return pb.McpResponseResult(
                error=pb.AuthorizationError(
                    code=pb.AuthorizationError.PERMISSION_DENIED,
                    reason="engine_error",
                )
            )
        return _build_response_result(decision, "")
