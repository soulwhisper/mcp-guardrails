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
from typing import Any

from google.protobuf.json_format import MessageToDict

from .engine import GuardrailEngine
from .models import Decision
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


def _build_request_result(decision: Decision, parse_error: str):
    if parse_error:
        return pb.McpRequestResult(
            error=pb.AuthorizationError(
                code=pb.AuthorizationError.INVALID,
                reason=parse_error,
            )
        )
    if decision.deny:
        return pb.McpRequestResult(
            error=pb.AuthorizationError(
                code=pb.AuthorizationError.PERMISSION_DENIED,
                reason=decision.reason or "denied",
            )
        )
    if decision.is_mutated:
        return pb.McpRequestResult(
            mutated=json.dumps(decision.mutated).encode("utf-8")
        )
    return _request_pass()


def _build_response_result(decision: Decision, parse_error: str):
    if parse_error:
        return pb.McpResponseResult(
            error=pb.AuthorizationError(
                code=pb.AuthorizationError.INVALID,
                reason=parse_error,
            )
        )
    if decision.deny:
        return pb.McpResponseResult(
            error=pb.AuthorizationError(
                code=pb.AuthorizationError.PERMISSION_DENIED,
                reason=decision.reason or "denied",
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

        try:
            decision = await self._e.check_request(
                method=request.method,
                service_names=list(request.service_names),
                tool_name=tool_name,
                params=params if isinstance(params, dict) else {"_raw": params},
                headers=headers,
                upstream_transport=transport,
                route_name=route,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("CheckRequest engine error")
            return _build_request_result(Decision(deny=True, reason=f"engine_error:{exc}"), "")
        return _build_request_result(decision, "")

    async def CheckResponse(self, request, context):
        result, parse_error = _safe_json_loads(request.mcp_response)
        transport, route = _extract_metadata(request)
        if parse_error:
            return _build_response_result(Decision(deny=False), parse_error)

        try:
            decision = await self._e.check_response(
                method=request.method,
                service_names=list(request.service_names),
                result=result,
                upstream_transport=transport,
                route_name=route,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("CheckResponse engine error")
            return _build_response_result(Decision(deny=True, reason=f"engine_error:{exc}"), "")
        return _build_response_result(decision, "")
