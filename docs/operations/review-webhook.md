# Review webhook

When `REVIEW_WEBHOOK_URL` is set, every decision carrying the `human_review`
flag POSTs a small **metadata-only** JSON body to that endpoint
(`guardrails/notify.py`) — so an operator's review queue (Slack, PagerDuty, a
ticket intake, …) learns about grey-zone exchanges in near-real-time instead
of waiting for an audit-log tail.

## Payload

```json
{
  "event": "human_review",
  "outcome": "human_review",
  "reason": "…(capped at 512 chars, metadata only)…",
  "ref": "engine-minted-uuid8",
  "exchange_id": "dataplane-correlation-id",
  "ts": 1730000000
}
```

No payload content, no scanner match detail — the same generalisation rules
as the audit log.

## Delivery guarantees (none, by design)

- **Never on the decision path.** Delivery runs as a background
  `asyncio.create_task`; the caller's decision is returned immediately.
- **Bounded.** Hard 2s timeout (connect + read), `urllib.request` in a worker
  thread — zero extra dependencies.
- **Log-only failures.** A slow, failing or hostile endpoint produces a
  warning log line and nothing else — it can never block, delay or alter a
  guardrail decision. No retries.

The [audit log](auditing.md) remains the authoritative record of
`human_review` decisions; the webhook is a convenience notification channel,
not a control.

## Receiver-side security

The sidecar does not sign requests. Restrict the endpoint to the intended
receiver (network policy + authentication at the receiver), and treat the
body as internal metadata — it contains decision reasons, correlation ids and
timestamps.
