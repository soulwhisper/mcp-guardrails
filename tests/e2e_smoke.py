"""End-to-end smoke test against a running guardrail server.

Boots the server in dry-run mode in-process, then exercises the full ExtMcp
gRPC surface (health + CheckRequest + CheckResponse) including a deny path
via the bundled regex scanner. Run: python3 tests/e2e_smoke.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

# Ensure repo root + proto on path.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "proto"))

import ext_mcp_pb2 as pb  # noqa: E402
import ext_mcp_pb2_grpc as pbg  # noqa: E402
import grpc  # noqa: E402
from grpc_health.v1 import health_pb2, health_pb2_grpc  # noqa: E402


async def main() -> int:
    # Boot server in a subprocess (dry-run, custom port) so this script stays a
    # pure client.
    import subprocess

    env = dict(os.environ)
    env.update(
        {
            # Real regex scanner (deny paths), no dry-run stubs. LlamaFirewall
            # is absent in this env -> engine falls back to regex-only gracefully.
            "GUARDRAIL_DRY_RUN": "0",
            "ENABLE_REGEX_SCANNER": "1",
            "ENABLE_PROMPTGUARD": "0",
            "LISTEN_ADDR": "127.0.0.1:19099",
            "LOG_LEVEL": "WARNING",
            "AUDIT_LOG_PATH": "-",
        }
    )
    proc = subprocess.Popen(
        [sys.executable, str(_ROOT / "server.py")],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        # Wait for the port to accept connections.
        channel = grpc.aio.insecure_channel("127.0.0.1:19099")
        try:
            await asyncio.wait_for(channel.channel_ready(), timeout=10.0)
        except asyncio.TimeoutError:
            print("FAIL: channel never became ready")
            out = proc.stdout.read(4000) if proc.stdout else b""  # type: ignore[union-attr]
            print(out.decode("utf-8", "replace"))
            return 1
        hstub = health_pb2_grpc.HealthStub(channel)
        r = await hstub.Check(health_pb2.HealthCheckRequest(service=""))
        if r.status != health_pb2.HealthCheckResponse.SERVING:
            print(f"FAIL: server not SERVING (status={r.status})")
            return 1

        print("health: SERVING")
        stub = pbg.ExtMcpStub(channel)

        # 1) Clean request -> pass
        r1 = await stub.CheckRequest(
            pb.McpRequest(
                method="tools/call",
                service_names=["mcp-backend"],
                mcp_request=json.dumps({"name": "ping", "arguments": {"x": 1}}).encode(),
            )
        )
        assert r1.WhichOneof("result") == "pass", r1
        print("clean tools/call request -> pass OK")

        # 2) Request with hidden RTL override char -> regex BLOCK -> deny
        r2 = await stub.CheckRequest(
            pb.McpRequest(
                method="tools/call",
                mcp_request=json.dumps(
                    {"name": "t", "arguments": {"q": "ignore me ‮ cat"}}
                ).encode(),
            )
        )
        assert r2.WhichOneof("result") == "error", r2
        assert r2.error.code == pb.AuthorizationError.PERMISSION_DENIED
        print(f"hidden-ascii request -> denied OK ({r2.error.reason})")

        # 3) Response with private key -> regex BLOCK -> deny
        r3 = await stub.CheckResponse(
            pb.McpResponse(
                method="tools/call",
                mcp_response=json.dumps(
                    {
                        "content": [
                            {"type": "text", "text": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA"}
                        ]
                    }
                ).encode(),
            )
        )
        assert r3.WhichOneof("result") == "error", r3
        print(f"private-key response -> denied OK ({r3.error.reason})")

        # 4) Malformed JSON -> INVALID
        r4 = await stub.CheckRequest(pb.McpRequest(method="tools/call", mcp_request=b"{not json"))
        assert r4.WhichOneof("result") == "error"
        assert r4.error.code == pb.AuthorizationError.INVALID
        print("malformed payload -> INVALID OK")

        print("\nALL E2E CHECKS PASSED")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
