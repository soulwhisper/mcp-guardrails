"""Smoke test for the ``server`` module.

The unit-test suite never starts the gRPC server (that's the job of
``tests/e2e_smoke.py``, which boots ``server.py`` as a subprocess). Importing
``server`` here serves two purposes:

1. It exercises the module-level imports / logger setup so ``--cov=server``
   produces meaningful coverage instead of the
   ``CoverageWarning: Module server was never imported`` noise.
2. It guards against trivial import-time regressions (a typo in a top-level
   import would otherwise only surface at container boot).

The ``serve()`` coroutine is NOT invoked — importing the module only runs the
top-level def statements; ``asyncio.run(serve())`` lives under the
``if __name__ == "__main__"`` guard.
"""

from __future__ import annotations

import server


def test_server_module_exposes_entrypoints():
    assert callable(server.serve)
    assert callable(server.grpc_aio_server)
    assert callable(server.graceful_shutdown)


# ---------------------------------------------------------------------------
# A-P2-4 graceful shutdown ordering: NOT_SERVING -> drain wait -> stop(grace)
# ---------------------------------------------------------------------------


class _FakeHealthServicer:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def set(self, service, status):
        self.events.append(f"set:{service}:{int(status)}")

    async def enter_graceful_shutdown(self):
        self.events.append("health_graceful_shutdown")


class _FakeGrpcServer:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def stop(self, grace):
        self.events.append(f"stop:{grace}")

    async def wait_for_termination(self):
        self.events.append("wait_for_termination")


class _FakeTask:
    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self):
        self.cancelled = True

    def __await__(self):
        # Mimic a cancelled asyncio task.
        import asyncio

        raise asyncio.CancelledError()
        yield  # pragma: no cover


async def test_graceful_shutdown_order_and_drain():

    from grpc_health.v1 import health_pb2

    grpc_server = _FakeGrpcServer()
    health = _FakeHealthServicer()
    task = _FakeTask()
    await server.graceful_shutdown(grpc_server, health, task, drain_s=0.01, grace_s=5.0)
    assert task.cancelled
    not_serving = int(health_pb2.HealthCheckResponse.NOT_SERVING)
    # Health flips to NOT_SERVING (both services) BEFORE any drain work.
    assert health.events[:2] == [
        f"set::{not_serving}",
        f"set:ExtMcp:{not_serving}",
    ]
    assert health.events[2:] == ["health_graceful_shutdown"]
    assert grpc_server.events == ["stop:5.0", "wait_for_termination"]


async def test_graceful_shutdown_zero_drain_skips_wait(monkeypatch):
    import asyncio

    grpc_server = _FakeGrpcServer()
    health = _FakeHealthServicer()
    task = _FakeTask()
    sleeps: list[float] = []

    async def _spy(s):
        sleeps.append(s)

    monkeypatch.setattr(asyncio, "sleep", _spy)
    await server.graceful_shutdown(grpc_server, health, task, drain_s=0.0, grace_s=1.0)
    assert sleeps == []
    assert grpc_server.events == ["stop:1.0", "wait_for_termination"]


def test_shutdown_drain_config_from_env(monkeypatch):
    from guardrails.config import GuardrailConfig

    monkeypatch.setenv("SHUTDOWN_DRAIN_S", "12.5")
    cfg = GuardrailConfig.from_env()
    assert cfg.shutdown_drain_s == 12.5
    monkeypatch.delenv("SHUTDOWN_DRAIN_S")
    assert GuardrailConfig.from_env().shutdown_drain_s == 5.0
