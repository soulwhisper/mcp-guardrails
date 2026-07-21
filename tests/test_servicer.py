"""Tests for the ExtMcp gRPC servicer wire-mapping + an in-process server test."""

from __future__ import annotations

import json

import grpc
import pytest
from google.protobuf import struct_pb2

from guardrails.proto_bridge import pb, pbg
from guardrails.servicer import ExtMcpServicer

# ---------------------------------------------------------------------------
# Wire-mapping unit tests (call servicer methods directly with constructed pb)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_request_pass(stub_engine):
    servicer = ExtMcpServicer(stub_engine)
    stub_engine.request_decision = type(stub_engine.request_decision)(deny=False)
    req = pb.McpRequest(
        method="tools/call",
        service_names=["svc"],
        mcp_request=json.dumps({"name": "ping", "arguments": {"x": 1}}).encode(),
    )
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "pass"
    # engine received the parsed params
    assert stub_engine.request_calls[0]["tool_name"] == "ping"
    assert stub_engine.request_calls[0]["method"] == "tools/call"


@pytest.mark.asyncio
async def test_check_request_deny_maps_to_authorization_error(stub_engine):
    from guardrails.models import Decision

    stub_engine.request_decision = Decision(deny=True, reason="LF:block:injection")
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"name": "t", "arguments": {}}).encode(),
    )
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "error"
    assert result.error.code == pb.AuthorizationError.PERMISSION_DENIED
    assert "LF:block:injection" in result.error.reason


@pytest.mark.asyncio
async def test_check_request_mutated_payload(stub_engine):
    from guardrails.models import Decision

    stub_engine.request_decision = Decision(
        deny=False, mutated={"name": "t", "arguments": {"q": "[redacted]"}}
    )
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpRequest(method="tools/call", mcp_request=json.dumps({"name": "t"}).encode())
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "mutated"
    decoded = json.loads(result.mutated.decode())
    assert decoded["arguments"]["q"] == "[redacted]"


@pytest.mark.asyncio
async def test_check_request_malformed_json_maps_to_invalid(stub_engine):
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpRequest(method="tools/call", mcp_request=b"{not json")
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "error"
    assert result.error.code == pb.AuthorizationError.INVALID
    # engine should NOT have been called for malformed input
    assert stub_engine.request_calls == []


@pytest.mark.asyncio
async def test_check_request_absent_payload_passes_to_engine(stub_engine):
    # tools/list has no params -> absent optional mcp_request is valid
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpRequest(method="tools/list")
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "pass"
    assert stub_engine.request_calls[0]["params"] == {}


@pytest.mark.asyncio
async def test_check_request_present_but_empty_payload_is_invalid(stub_engine):
    # optional bytes present but empty is malformed, not "no params"
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpRequest(method="tools/call", mcp_request=b"")
    result = await servicer.CheckRequest(req, None)
    assert result.WhichOneof("result") == "error"
    assert result.error.code == pb.AuthorizationError.INVALID
    assert stub_engine.request_calls == []


@pytest.mark.asyncio
async def test_check_response_pass(stub_engine):
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpResponse(
        method="tools/call",
        mcp_response=json.dumps({"content": [{"type": "text", "text": "ok"}]}).encode(),
    )
    result = await servicer.CheckResponse(req, None)
    assert result.WhichOneof("result") == "pass"
    assert stub_engine.response_calls[0]["method"] == "tools/call"


@pytest.mark.asyncio
async def test_check_response_deny(stub_engine):
    from guardrails.models import Decision

    stub_engine.response_decision = Decision(deny=True, reason="LF:indirect_injection")
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpResponse(
        method="tools/call",
        mcp_response=json.dumps({"content": [{"type": "text", "text": "bad"}]}).encode(),
    )
    result = await servicer.CheckResponse(req, None)
    assert result.WhichOneof("result") == "error"
    assert "indirect_injection" in result.error.reason


@pytest.mark.asyncio
async def test_check_response_mutated_payload(stub_engine):
    from guardrails.models import Decision

    stub_engine.response_decision = Decision(
        deny=False, mutated={"content": [{"type": "text", "text": "[redacted]"}]}
    )
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpResponse(
        method="tools/call",
        mcp_response=json.dumps({"content": [{"type": "text", "text": "secret"}]}).encode(),
    )
    result = await servicer.CheckResponse(req, None)
    assert result.WhichOneof("result") == "mutated"
    decoded = json.loads(result.mutated.decode())
    assert decoded["content"][0]["text"] == "[redacted]"


@pytest.mark.asyncio
async def test_headers_forwarded_to_engine(stub_engine):
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"name": "t"}).encode(),
        headers=[pb.McpHeader(key="authorization", value=b"Bearer xyz")],
    )
    await servicer.CheckRequest(req, None)
    assert stub_engine.request_calls[0]["headers"]["authorization"] == "Bearer xyz"


@pytest.mark.asyncio
async def test_metadata_context_forwarded(stub_engine):
    servicer = ExtMcpServicer(stub_engine)
    req = pb.McpRequest(
        method="tools/call",
        mcp_request=json.dumps({"name": "t"}).encode(),
        metadata_context=struct_pb2.Struct(
            fields={
                "upstream_transport": struct_pb2.Value(string_value="stdio"),
                "route_name": struct_pb2.Value(string_value="mcp-route"),
            }
        ),
    )
    await servicer.CheckRequest(req, None)
    assert stub_engine.request_calls[0]["upstream_transport"] == "stdio"
    assert stub_engine.request_calls[0]["route_name"] == "mcp-route"


# ---------------------------------------------------------------------------
# In-process gRPC server integration test (full wire round-trip)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_in_process_grpc_round_trip(stub_engine):
    """Boot a real grpc.aio server in-process, talk to it via the generated
    client stub. Verifies servicer registration, health, and both RPCs.
    """
    from grpc_health.v1 import health, health_pb2, health_pb2_grpc

    server = grpc.aio.server()
    pbg.add_ExtMcpServicer_to_server(ExtMcpServicer(stub_engine), server)
    hs = health.aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(hs, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()

    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            # Health check
            health_stub = health_pb2_grpc.HealthStub(channel)
            hr = await health_stub.Check(health_pb2.HealthCheckRequest(service=""))
            assert hr.status == health_pb2.HealthCheckResponse.SERVING

            stub = pbg.ExtMcpStub(channel)

            # CheckRequest: pass
            stub_engine.request_decision = type(stub_engine.request_decision)(deny=False)
            r1 = await stub.CheckRequest(
                pb.McpRequest(
                    method="tools/call",
                    mcp_request=json.dumps({"name": "ping"}).encode(),
                )
            )
            assert r1.WhichOneof("result") == "pass"

            # CheckRequest: deny
            from guardrails.models import Decision

            stub_engine.request_decision = Decision(deny=True, reason="blocked")
            r2 = await stub.CheckRequest(
                pb.McpRequest(method="tools/call", mcp_request=json.dumps({"name": "t"}).encode())
            )
            assert r2.WhichOneof("result") == "error"
            assert r2.error.code == pb.AuthorizationError.PERMISSION_DENIED

            # CheckResponse: pass
            stub_engine.response_decision = Decision(deny=False)
            r3 = await stub.CheckResponse(
                pb.McpResponse(
                    method="tools/call", mcp_response=json.dumps({"content": []}).encode()
                )
            )
            assert r3.WhichOneof("result") == "pass"
    finally:
        await server.stop(grace=0)
