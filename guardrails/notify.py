"""HUMAN_REVIEW webhook notifier (fire-and-forget).

When ``REVIEW_WEBHOOK_URL`` is configured the engine POSTs a small
metadata-only JSON body (``outcome`` / ``reason`` / ``ref`` /
``exchange_id`` / ``ts``) to that endpoint whenever a decision carries the
``human_review`` flag — so an operator's review queue (Slack, PagerDuty, a
ticket intake, …) learns about grey-zone exchanges in near-real-time
instead of waiting for an audit-log tail.

Design constraints:

* **Never on the decision path.** Delivery runs as a background
  :func:`asyncio.create_task`; the caller's :class:`Decision` is returned
  immediately. A slow, failing or hostile endpoint can only produce a log
  line — it can never block, delay or alter a guardrail decision.
* **Bounded.** The POST has a hard 2s timeout and the body is capped
  metadata (no payload content, no scanner match detail — same
  generalisation rules as the audit log).
* **Zero-dependency.** ``urllib.request`` in a worker thread
  (:func:`asyncio.to_thread`) instead of pulling in httpx/aiohttp for one
  best-effort POST.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
from typing import Any

logger = logging.getLogger("mcp.guardrails.notify")

# Hard cap on the POST, connect + read combined. Deliberately short: this
# is a best-effort notification, not a decision dependency.
WEBHOOK_TIMEOUT_S = 2.0


def build_review_payload(
    *, outcome: str, reason: str, ref: str, exchange_id: str
) -> dict[str, Any]:
    """The metadata-only JSON body posted to the review webhook."""
    return {
        "event": "human_review",
        "outcome": outcome,
        # The internal reason may name scanner/rule classes; it is
        # metadata (never payload content), matching the audit record.
        "reason": reason[:512],
        "ref": ref,
        "exchange_id": exchange_id,
        "ts": int(time.time()),
    }


def _post_json(url: str, body: bytes, timeout_s: float) -> int:
    """Synchronous POST (runs in a worker thread). Returns the status."""
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        # HTTPError is file-like (its body may be backed by a tempfile);
        # close it explicitly or the GC cleanup emits a ResourceWarning.
        try:
            return e.status
        finally:
            e.close()


async def notify_human_review(
    url: str,
    *,
    outcome: str,
    reason: str,
    ref: str,
    exchange_id: str,
    timeout_s: float = WEBHOOK_TIMEOUT_S,
) -> None:
    """POST the review payload; every failure mode is log-only.

    Awaiting this coroutine performs the delivery (tests do exactly that);
    the engine schedules it via :func:`schedule_review_notification` so the
    decision path never awaits it.
    """
    payload = build_review_payload(outcome=outcome, reason=reason, ref=ref, exchange_id=exchange_id)
    try:
        body = json.dumps(payload).encode("utf-8")
        status = await asyncio.to_thread(_post_json, url, body, timeout_s)
        if status >= 400:
            logger.warning("review webhook %s returned HTTP %s (ref=%s)", url, status, ref)
    except Exception as exc:
        logger.warning("review webhook %s failed (ref=%s): %s", url, ref, exc)


def schedule_review_notification(
    url: str,
    *,
    outcome: str,
    reason: str,
    ref: str,
    exchange_id: str,
) -> asyncio.Task[None] | None:
    """Fire-and-forget wrapper: schedule the POST, swallow task failures.

    Returns the task (tests can await it) or ``None`` when there is no
    running loop (engine-direct synchronous callers — delivery is skipped
    with a debug log, the audit record still has the full decision).
    """
    if not url:
        return None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # pragma: no cover - defensive
        logger.debug("no running loop; skipping review webhook (ref=%s)", ref)
        return None

    async def _swallow() -> None:
        try:
            await notify_human_review(
                url, outcome=outcome, reason=reason, ref=ref, exchange_id=exchange_id
            )
        except Exception:  # pragma: no cover - notify is already exception-safe
            logger.exception("review webhook task crashed (ref=%s)", ref)

    return loop.create_task(_swallow())
