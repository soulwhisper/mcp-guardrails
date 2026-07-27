"""HUMAN_REVIEW webhook notification tests (REVIEW_WEBHOOK_URL).

Covers:
* a configured webhook receives the metadata-only JSON POST on a
  human_review decision (fire-and-forget scheduled by the engine);
* an unreachable / failing endpoint only logs — the decision is returned
  unchanged and the decision path never blocks on delivery;
* no webhook configured -> no delivery attempt;
* non-review decisions -> no delivery attempt.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from guardrails.aggregator import DecisionAggregator
from guardrails.config import GuardrailConfig
from guardrails.engine import EngineComponents, GuardrailEngine
from guardrails.models import FailureMode, HumanReviewMode, ScanResult
from guardrails.notify import (
    build_review_payload,
    notify_human_review,
    schedule_review_notification,
)
from guardrails.otel import Observability
from tests.helpers import ScriptedScanner


class _Collector:
    """Tiny HTTP server recording POSTed JSON bodies."""

    def __init__(self, *, status: int = 200):
        self.bodies: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                try:
                    outer.bodies.append(json.loads(raw))
                except json.JSONDecodeError:
                    outer.bodies.append({"_raw": raw.decode("utf-8", "replace")})
                self.send_response(outer._status)
                self.end_headers()

            def log_message(self, *_args):  # silence
                pass

        self._status = status
        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}/hook"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=2)
        self._server.server_close()


def _review_engine(webhook_url: str = "") -> tuple[GuardrailEngine, list[dict[str, Any]]]:
    config = GuardrailConfig(
        enable_regex_scanner=False,
        enable_promptguard=False,
        enable_agent_alignment=False,
        enable_redaction=False,
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        review_webhook_url=webhook_url,
        log_level="WARNING",
    )
    lines: list[dict[str, Any]] = []
    obs = Observability()
    obs.audit.emit = lambda rec: lines.append(dict(rec))
    comps = EngineComponents(
        request_scanners=[ScriptedScanner("grey", [ScanResult.review("grey", "sus", score=0.7)])],
        response_scanners=[],
        aggregator=DecisionAggregator(human_review_mode=HumanReviewMode.PASS),
        observability=obs,
    )
    return GuardrailEngine(config, comps), lines


async def _drain_tasks() -> None:
    """Let fire-and-forget tasks finish (they are not decision-path)."""
    await asyncio.sleep(0.3)


def test_webhook_receives_review_payload():
    collector = _Collector()
    try:
        engine, _ = _review_engine(collector.url)

        async def run():
            decision = await engine.check_request(
                method="tools/call",
                service_names=["svc"],
                tool_name="fs_read",
                params={"arguments": {}},
                headers={},
                exchange_id="ex-42",
            )
            await _drain_tasks()
            return decision

        decision = asyncio.run(run())
        assert decision.human_review and not decision.deny
        assert len(collector.bodies) == 1
        body = collector.bodies[0]
        assert body["event"] == "human_review"
        assert body["outcome"] == "human_review"
        assert body["exchange_id"] == "ex-42"
        assert body["ref"] == decision.ref
        assert "grey" in body["reason"]
        assert isinstance(body["ts"], int)
    finally:
        collector.close()


def test_webhook_failure_does_not_affect_decision():
    # Nothing listening on this port: the POST fails fast with ECONNREFUSED.
    engine, lines = _review_engine("http://127.0.0.1:1/hook")

    async def run():
        decision = await engine.check_request(
            method="tools/call",
            service_names=["svc"],
            tool_name="fs_read",
            params={"arguments": {}},
            headers={},
            exchange_id="ex-x",
        )
        await _drain_tasks()
        return decision

    decision = asyncio.run(run())
    # The decision is untouched and the audit line was still emitted.
    assert decision.human_review and not decision.deny
    assert any(r.get("outcome") == "human_review" for r in lines)


def test_webhook_http_error_only_logs(caplog):
    collector = _Collector(status=500)
    try:
        engine, _ = _review_engine(collector.url)

        async def run():
            decision = await engine.check_request(
                method="tools/call",
                service_names=["svc"],
                tool_name="fs_read",
                params={"arguments": {}},
                headers={},
                exchange_id="ex-err",
            )
            await _drain_tasks()
            return decision

        decision = asyncio.run(run())
        assert decision.human_review
        assert len(collector.bodies) == 1  # delivery happened, server 500'd
    finally:
        collector.close()


def test_post_json_http_error_returns_status_and_closes(recwarn):
    # Regression: an HTTP error raises HTTPError (file-like, tempfile-backed);
    # _post_json must close it or GC cleanup emits a ResourceWarning.
    import gc

    from guardrails.notify import _post_json

    collector = _Collector(status=500)
    try:
        status = _post_json(collector.url, b"{}", 2.0)
        assert status == 500
        gc.collect()
    finally:
        collector.close()
    assert not [w for w in recwarn.list if issubclass(w.category, ResourceWarning)]


def test_no_webhook_configured_no_delivery():
    engine, _ = _review_engine("")

    async def run():
        with pytest.MonkeyPatch.context() as mp:

            def _boom(*_a, **_k):
                raise AssertionError("schedule_review_notification must not run")

            mp.setattr("guardrails.notify.schedule_review_notification", _boom)
            return await engine.check_request(
                method="tools/call",
                service_names=["svc"],
                tool_name="fs_read",
                params={"arguments": {}},
                headers={},
            )

    decision = asyncio.run(run())
    assert decision.human_review


def test_allow_decision_no_delivery():
    config = GuardrailConfig(
        enable_regex_scanner=False,
        enable_promptguard=False,
        enable_agent_alignment=False,
        enable_redaction=False,
        review_webhook_url="http://127.0.0.1:1/hook",
        log_level="WARNING",
    )
    comps = EngineComponents(
        request_scanners=[ScriptedScanner("ok", [ScanResult.allow("ok")])],
        response_scanners=[],
        observability=Observability(),
    )
    engine = GuardrailEngine(config, comps)

    async def run():
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "guardrails.notify.schedule_review_notification",
                lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not fire")),
            )
            return await engine.check_request(
                method="tools/call",
                service_names=["svc"],
                tool_name="fs_read",
                params={"arguments": {}},
                headers={},
            )

    decision = asyncio.run(run())
    assert not decision.deny and not decision.human_review


def test_notify_human_review_timeout_swallowed():
    # Unroutable address -> the 2s timeout path; must not raise.
    asyncio.run(
        notify_human_review(
            "http://10.255.255.1:9/hook",
            outcome="human_review",
            reason="x",
            ref="r",
            exchange_id="e",
            timeout_s=0.2,
        )
    )


def test_schedule_without_loop_returns_none():
    task = schedule_review_notification(
        "http://127.0.0.1:1/", outcome="human_review", reason="x", ref="r", exchange_id="e"
    )
    assert task is None


def test_build_review_payload_metadata_only():
    body = build_review_payload(outcome="human_review", reason="r" * 1000, ref="f", exchange_id="e")
    assert set(body) == {"event", "outcome", "reason", "ref", "exchange_id", "ts"}
    assert len(body["reason"]) == 512  # capped
