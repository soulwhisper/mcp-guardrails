"""Server entrypoint — grpc-aio ExtMcp servicer on :9001 (h2c).

Boots:

* the :class:`GuardrailEngine` (warmed up before accepting traffic)
* the gRPC aio server with the ExtMcp servicer + grpc.health.v1
* a ``SIGHUP`` handler that hot-reloads the Invariant rule pack
* a graceful-shutdown path on SIGTERM/SIGINT

``appProtocol: kubernetes.io/h2c`` on the Service is what tells agentgateway
this is plaintext-HTTP/2 gRPC; we therefore bind an *insecure* port (no TLS).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from concurrent import futures

from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from guardrails.engine import GuardrailEngine
from guardrails.proto_bridge import pbg
from guardrails.servicer import ExtMcpServicer

logger = logging.getLogger("mcp.guardrails.server")

_LISTEN_ADDR_DEFAULT = "[::]:9001"
_GRACE_SECS = 5.0


async def serve() -> None:
    from guardrails.config import GuardrailConfig

    config = GuardrailConfig.from_env()
    engine = GuardrailEngine.from_config(config)
    await engine.awarm()

    server = grpc_aio_server(
        engine,
        max_workers=config.server_max_workers,
        max_recv_bytes=config.grpc_max_recv_bytes,
        max_concurrent_rpcs=config.grpc_max_concurrent_rpcs,
    )
    server.add_insecure_port(config.listen_addr)

    # Health check: starts NOT_SERVING and is driven by a background task
    # that follows ``engine.healthy`` — SERVING only after warmup completes,
    # and flipped back to NOT_SERVING when the sliding-window scanner
    # error/timeout rate exceeds UNHEALTHY_SCANNER_ERROR_RATE (A-P0-4).
    # Recovers automatically once the failure rate drops back below the
    # threshold. The readinessProbe keeps the Pod out of rotation during
    # model load; the same signal now also drains an unhealthy sidecar.
    health_servicer = health.aio.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    await health_servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
    await health_servicer.set("ExtMcp", health_pb2.HealthCheckResponse.NOT_SERVING)

    async def _health_watchdog(period_s: float = 2.0) -> None:
        last: bool | None = None
        while True:
            healthy = engine.healthy
            if healthy != last:
                status = (
                    health_pb2.HealthCheckResponse.SERVING
                    if healthy
                    else health_pb2.HealthCheckResponse.NOT_SERVING
                )
                await health_servicer.set("", status)
                await health_servicer.set("ExtMcp", status)
                if last is not None:
                    logger.warning(
                        "health transitioned to %s (scanner error-rate degradation)",
                        "SERVING" if healthy else "NOT_SERVING",
                    )
                last = healthy
            await asyncio.sleep(period_s)

    health_task = asyncio.create_task(_health_watchdog())

    stop_event = asyncio.Event()

    def _request_stop(*_: object) -> None:
        logger.info("shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # pragma: no cover - Windows
            loop.add_signal_handler(sig, _request_stop)

    # SIGHUP -> reload Invariant rules without dropping the server.
    def _reload_rules(*_: object) -> None:
        try:
            engine.reload_rules()
        except Exception as exc:  # pragma: no cover
            logger.warning("rule reload failed: %s", exc)

    with contextlib.suppress(NotImplementedError, AttributeError):  # pragma: no cover
        loop.add_signal_handler(signal.SIGHUP, _reload_rules)

    await server.start()
    logger.info("ExtMcp guardrail listening on %s (h2c)", config.listen_addr)

    await stop_event.wait()
    logger.info("draining connections (grace=%ss)", _GRACE_SECS)
    health_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await health_task
    await server.stop(grace=_GRACE_SECS)
    await health_servicer.enter_graceful_shutdown()
    await server.wait_for_termination()


def grpc_aio_server(
    engine: GuardrailEngine,
    max_workers: int = 8,
    max_recv_bytes: int = 8 * 1024 * 1024,
    max_concurrent_rpcs: int = 128,
):
    import grpc

    # DoS hardening (S-M4): bound the accepted message size and the number of
    # in-flight RPCs so a runaway or hostile caller cannot exhaust memory or
    # starve the asyncio loop. Both are env-tunable (GRPC_MAX_RECV_BYTES /
    # GRPC_MAX_CONCURRENT_RPCS, see GuardrailConfig).
    server = grpc.aio.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        options=[
            ("grpc.max_receive_message_length", max_recv_bytes),
            ("grpc.max_send_message_length", max_recv_bytes),
        ],
        maximum_concurrent_rpcs=max_concurrent_rpcs,
    )
    pbg.add_ExtMcpServicer_to_server(ExtMcpServicer(engine), server)
    return server


if __name__ == "__main__":
    asyncio.run(serve())
