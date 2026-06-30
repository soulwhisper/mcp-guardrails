import grpc, asyncio, json, struct
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from concurrent import futures
import ext_mcp_pb2 as pb
import ext_mcp_pb2_grpc as pb_grpc
from guardrails.engine import GuardrailEngine

class ExtMcpServicer(pb_grpc.ExtMcpServicer):
    def __init__(self, engine: GuardrailEngine):
        self._e = engine

    async def CheckRequest(self, request: pb.McpRequest, context):
        # mcp_request 是 JSON-RPC params 的原始字节，可能为空
        params = json.loads(request.mcp_request) if request.mcp_request else {}
        tool_name = params.get("name", "") if request.method == "tools/call" else ""
        decision = await self._e.check_request(
            method=request.method,
            service_names=list(request.service_names),
            tool_name=tool_name,
            params=params,
            headers={h.key: h.value for h in request.headers},
        )
        if decision.deny:
            return pb.McpRequestResult(
                error=pb.AuthorizationError(
                    code=pb.AuthorizationError.PERMISSION_DENIED,
                    message=decision.reason,
                )
            )
        if decision.mutated_params is not None:
            return pb.McpRequestResult(mutated=json.dumps(decision.mutated_params).encode())
        return pb.McpRequestResult(pass=pb.Pass())

    async def CheckResponse(self, request: pb.McpResponse, context):
        result = json.loads(request.mcp_response) if request.mcp_response else {}
        decision = await self._e.check_response(
            method=request.method,
            service_names=list(request.service_names),
            result=result,
        )
        if decision.deny:
            return pb.McpResponseResult(
                error=pb.AuthorizationError(
                    code=pb.AuthorizationError.PERMISSION_DENIED,
                    message=decision.reason,
                )
            )
        if decision.mutated_result is not None:
            return pb.McpResponseResult(mutated=json.dumps(decision.mutated_result).encode())
        return pb.McpResponseResult(pass=pb.Pass())

async def serve():
    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=8))
    engine = GuardrailEngine.from_env()
    await engine.awarm()  # 预热 LF 模型
    pb_grpc.add_ExtMcpServicer_to_server(ExtMcpServicer(engine), server)
    # health/v1 供 agentgateway readiness 探测
    hs = health.aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(hs, server)
    await hs.set("ExtMcp", health_pb2.HealthCheckResponse.SERVING)
    server.add_insecure_port("[::]:9001")  # h2c
    await server.start()
    await server.wait_for_termination()

asyncio.run(serve())
