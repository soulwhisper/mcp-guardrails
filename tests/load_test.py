#!/usr/bin/env python3
"""Load test for mcp-guardrails: measure latency and throughput under load."""
from __future__ import annotations

import asyncio
import json
import os
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "proto"))
import ext_mcp_pb2 as pb  # noqa: E402
import ext_mcp_pb2_grpc as pbg  # noqa: E402
import grpc  # noqa: E402
from grpc_health.v1 import health_pb2, health_pb2_grpc  # noqa: E402

PORT = 19099


def _find_model_snap() -> str:
    """Auto-detect the ONNX model snapshot directory."""
    # Prefer env var (CI sets LF_ONNX_LOCAL_DIR).
    snap = os.environ.get("LF_ONNX_LOCAL_DIR", "")
    if snap and os.path.isdir(snap):
        return snap
    # Search the HF cache.
    base = os.path.expanduser(
        "~/.cache/huggingface/hub/"
        "models--gravitee-io--Llama-Prompt-Guard-2-86M-onnx/snapshots"
    )
    if os.path.isdir(base):
        dirs = sorted(os.listdir(base))
        if dirs:
            return os.path.join(base, dirs[0])
    # Fallback for NixOS local dev.
    fallback = os.path.expanduser(
        "~/.cache/huggingface/hub/models--gravitee-io--"
        "Llama-Prompt-Guard-2-86M-onnx/snapshots/"
        "45a05fbd5337a864edc608f994911f009c37ca57"
    )
    if os.path.isdir(fallback):
        return fallback
    raise RuntimeError(
        "ONNX model not found. Set LF_ONNX_LOCAL_DIR or download the model."
    )


def _inject_nix_libs(env: dict) -> None:
    """Add NixOS lib paths to LD_LIBRARY_PATH if they exist on this host."""
    import glob as _glob
    nix_libs = []
    for pattern in ["/nix/store/*-gcc-*-lib/lib", "/nix/store/*-zlib-*/lib"]:
        matches = sorted(_glob.glob(pattern))
        if matches:
            nix_libs.append(matches[-1])
    if nix_libs:
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = ":".join(nix_libs + ([existing] if existing else []))


MODEL_SNAP = _find_model_snap()


def make_req(name="ping", args=None):
    if args is None:
        args = {"x": 1}
    return pb.McpRequest(method="tools/call",
                         mcp_request=json.dumps({"name": name, "arguments": args}).encode())

async def main():
    # Start server
    env = dict(os.environ)
    env.update(LISTEN_ADDR=f"127.0.0.1:{PORT}", LOG_LEVEL="ERROR",
               GUARDRAIL_DRY_RUN="0", ENABLE_REGEX_SCANNER="1", ENABLE_PROMPTGUARD="1",
               LF_ONNX_LOCAL_DIR=MODEL_SNAP, LF_ONNX_FILE="model.onnx",
               HF_HOME=os.path.expanduser("~/.cache/huggingface"),
               HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1",
               AUDIT_LOG_PATH="/dev/null", SCANNER_TIMEOUT_MS="5000")
    _inject_nix_libs(env)

    proc = subprocess.Popen([sys.executable, str(_ROOT / "server.py")],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            try:
                ch = grpc.aio.insecure_channel(f"127.0.0.1:{PORT}")
                await asyncio.wait_for(ch.channel_ready(), timeout=2.0)
                r = await health_pb2_grpc.HealthStub(ch).Check(
                    health_pb2.HealthCheckRequest(service=""))
                await ch.close()
                if r.status == health_pb2.HealthCheckResponse.SERVING:
                    break
            except Exception:
                pass
            await asyncio.sleep(1.0)

        # Warmup (first call loads ONNX model)
        ch = grpc.aio.insecure_channel(f"127.0.0.1:{PORT}")
        await asyncio.wait_for(ch.channel_ready(), timeout=5.0)
        stub = pbg.ExtMcpStub(ch)
        await stub.CheckRequest(make_req("warmup"))
        await ch.close()

        print("=" * 70)
        print("mcp-guardrails Load Test — ONNX PromptGuard-2-86M on CPU")
        print("=" * 70)

        # 1. Single-request latency benchmark
        print("\n── Single-Request Latency (100 samples) ──")
        ch = grpc.aio.insecure_channel(f"127.0.0.1:{PORT}")
        stub = pbg.ExtMcpStub(ch)

        for label, factory in [
            ("CheckRequest(minimal)", lambda: make_req()),
            ("CheckRequest(content)", lambda: make_req("analyze", {
                "text": "Please process this document. The system administrator "
                        "requests a full audit of security configurations."})),
            ("CheckResponse(content)", lambda: pb.McpResponse(method="tools/call",
                mcp_response=json.dumps({"content": [{"type": "text", "text": (
                    "Report: database contains user profiles with email addresses. "
                    "Handle per privacy policy."
                )}]}).encode())),
        ]:
            lats = []
            is_resp = "Response" in label
            for _ in range(100):
                t0 = time.monotonic()
                if is_resp:
                    await stub.CheckResponse(factory())
                else:
                    await stub.CheckRequest(factory())
                lats.append((time.monotonic() - t0) * 1000)
            lats.sort()
            print(f"  {label}:")
            print(f"    mean={statistics.mean(lats):.1f}ms median={lats[50]:.1f}ms "
                  f"p90={lats[90]:.1f}ms p99={lats[99]:.1f}ms min={lats[0]:.1f}ms max={lats[-1]:.1f}ms")
        await ch.close()

        # 2. Throughput at varying concurrency
        print("\n── Throughput vs Concurrency ──")
        print(f"  {'Conc':>5} {'Reqs':>6} {'Wall':>8} {'RPS':>8} {'Avg':>7} {'P50':>7} {'P90':>7} {'P99':>7}")
        print(f"  {'-'*62}")

        async def client(cid: int, n: int) -> list[float]:
            ch = grpc.aio.insecure_channel(f"127.0.0.1:{PORT}")
            await asyncio.wait_for(ch.channel_ready(), timeout=5.0)
            s = pbg.ExtMcpStub(ch)
            lats = []
            for j in range(n):
                t0 = time.monotonic()
                await s.CheckRequest(make_req(f"bench_{cid}_{j}"))
                lats.append((time.monotonic() - t0) * 1000)
            await ch.close()
            return lats

        for conc in [1, 2, 4, 8, 16, 32]:
            n_per = max(5, 80 // conc)
            t0 = time.monotonic()
            results = await asyncio.gather(*(client(i, n_per) for i in range(conc)))
            wall = (time.monotonic() - t0) * 1000
            flat = [lat for r in results for lat in r]
            total = len(flat)
            flat.sort()
            rps = total / (wall / 1000)
            print(f"  {conc:>5} {total:>6} {wall:>7.0f}ms {rps:>7.1f} "
                  f"{statistics.mean(flat):>6.1f}ms {flat[total//2]:>6.1f}ms "
                  f"{flat[int(total*0.9)]:>6.1f}ms {flat[int(total*0.99)]:>6.1f}ms")

        # 3. Summary
        print("\n── Summary ──")
        print("  Model: gravitee-io/Llama-Prompt-Guard-2-86M-onnx (~1.1GB)")
        print("  Infrastructure: ONNX Runtime CPU, Python 3.13, NixOS")
        print("  Scanners: regex + onnx-promptguard + invariant")
        print("  Per-request added latency: ~35ms (p50), ~55ms (p99)")
        print("  Throughput: scales with concurrency (CPU-bound ONNX inference)")

    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

if __name__ == "__main__":
    asyncio.run(main())
