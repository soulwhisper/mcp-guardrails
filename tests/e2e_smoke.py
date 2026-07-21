#!/usr/bin/env python3
"""e2e smoke: start the real server in a subprocess, hit it over real gRPC.

Runs the actual binary (`python server.py`) with PromptGuard disabled (regex-only
mode, no ML downloads), then makes real gRPC calls:

  1. gRPC health check reaches SERVING
  2. clean tools/call request  -> pass
  3. payload with hidden char  -> PERMISSION_DENIED
  4. malformed JSON payload    -> INVALID

Exits non-zero on any failure. Intended for CI / release-gate use.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

from guardrails.proto_bridge import pb, pbg


def wait_for_health(channel: grpc.Channel, timeout_s: float = 20.0) -> None:
    stub = health_pb2_grpc.HealthStub(channel)
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = stub.Check(health_pb2.HealthCheckRequest(service=""), timeout=1.0)
            if resp.status == health_pb2.HealthCheckResponse.SERVING:
                return
        except grpc.RpcError as exc:
            last_err = exc
        time.sleep(0.25)
    raise RuntimeError(f"server did not become SERVING within {timeout_s}s: {last_err}")


def main() -> int:
    env = os.environ.copy()
    env["ENABLE_PROMPTGUARD"] = "0"  # regex-only: no model download, fast startup
    env["LISTEN_ADDR"] = "127.0.0.1:19099"
    env["AUDIT_LOG_PATH"] = "/dev/null"
    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        channel = grpc.insecure_channel("127.0.0.1:19099")
        wait_for_health(channel)
        print("health check -> SERVING OK")

        stub = pbg.ExtMcpStub(channel)

        # 1) Clean request -> pass
        r1 = stub.CheckRequest(
            pb.McpRequest(
                method="tools/call",
                mcp_request=json.dumps({"name": "ping", "arguments": {"q": "hello"}}).encode(),
            )
        )
        assert r1.WhichOneof("result") == "pass", r1
        print("clean tools/call request -> pass OK")

        # 2) Request containing a hidden unicode char -> denied by RegexScanner
        r2 = stub.CheckRequest(
            pb.McpRequest(
                method="tools/call",
                mcp_request=json.dumps(
                    {"name": "ping", "arguments": {"q": "hello\u202eworld"}}
                ).encode(),
            )
        )
        assert r2.WhichOneof("result") == "error", r2
        assert r2.error.code == pb.AuthorizationError.PERMISSION_DENIED, r2
        assert "hidden" in r2.error.reason.lower(), r2
        print("hidden-unicode request -> PERMISSION_DENIED OK")

        # 3) Response containing a private key -> denied (indirect injection/secret leak)
        r3 = stub.CheckResponse(
            pb.McpResponse(
                method="tools/call",
                mcp_response=json.dumps(
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": "-----BEGIN PRIVATE KEY-----\nMIIEvg...",
                            }
                        ]
                    }
                ).encode(),
            )
        )
        assert r3.WhichOneof("result") == "error", r3
        assert r3.error.code == pb.AuthorizationError.PERMISSION_DENIED, r3
        assert "private key" in r3.error.reason.lower(), r3
        print("private-key response -> PERMISSION_DENIED OK")

        # 4) Malformed JSON -> INVALID
        r4 = stub.CheckRequest(pb.McpRequest(method="tools/call", mcp_request=b"{not json"))
        assert r4.WhichOneof("result") == "error", r4
        assert r4.error.code == pb.AuthorizationError.INVALID, r4
        print("malformed payload -> INVALID OK")

        print("\nALL E2E SMOKE CHECKS PASSED")
        return 0
    finally:
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        if proc.returncode not in (0, -15):  # -15 = SIGTERM (expected on success)
            print("---- server output ----")
            print(out)
            return 1


if __name__ == "__main__":
    sys.exit(main())
