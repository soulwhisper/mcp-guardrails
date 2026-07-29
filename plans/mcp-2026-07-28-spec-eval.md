# MCP 2026-07-28 Specification — Eval & Migration Plan

**Date**: 2026-07-29
**Baseline**: `main` @ `6fc576b` (#92)
**Spec**: [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) (final, published 2026-07-28)
**Re-eval trigger**: next agentgateway release announcing 2026-07-28 support (current pin v1.4.0 predates the spec; no upstream support observed as of this writing)

## Context

This repo is an **ExtMcp gRPC sidecar** — agentgateway terminates MCP and hands the
sidecar a method string + opaque params/result JSON (`proto/ext_mcp.proto`). The
sidecar never sees the transport, sessions, or JSON-RPC envelopes, so the spec's
headline changes (stateless transport, handshake/session removal) land on
**agentgateway**, not on `guardrails/` core. Blast radius is confined to the e2e
script, the example config, and one redaction coverage gap.

## Impact matrix (verified against code)

| Spec change | Impact | Evidence |
|---|---|---|
| `initialize` / `notifications/initialized` handshake removed | **Breaks e2e script** | `scripts/e2e_agentgateway.sh:100-106` — `initialize` call + `mcp-session-id` header extraction |
| `Mcp-Session-Id` header removed | **Breaks e2e + example config** | `e2e_agentgateway.sh:102-110` sends it per call; `examples/agentgateway.standalone.yaml:28` CORS-allows it |
| `ping`, `logging/setLevel`, `resources/subscribe` removed | None | Engine special-cases only `tools/call` (`guardrails/engine.py:402,436`); all other methods use the generic text-scan fallback |
| `resultType` required on all results | None | Sidecar never mints results; mutation round-trips preserve unknown keys (`guardrails/engine.py:553`, `guardrails/redaction.py:185-193`) |
| Error-code renumbering (`-32020..-32099` spec-reserved) | None | Sidecar's `-32001` is in the grandfathered implementation-defined range `-32000..-32019` (`guardrails/servicer.py:212`; e2e asserts on it at `e2e_agentgateway.sh:135`) |
| Elicitation/sampling → MRTR (`InputRequiredResult`, `inputResponses`) | Coverage gap, see M3 | Request redaction only touches `params.arguments` (`guardrails/engine.py:447`) |
| OTel trace context in `_meta` (`traceparent`/`tracestate`/`baggage`) documented | Optional enhancement | Current correlation uses header/metadata_context probing (`guardrails/servicer.py:88-140`) |
| Roots/Sampling/Logging deprecated; OAuth DCR deprecated | Docs only | Update references when touching docs |

## Migration items

### Gated on agentgateway 2026-07-28 support (single small PR, do together)

- [ ] **M1 — `scripts/e2e_agentgateway.sh`**: drop the initialize/session flow. Send
  stateless calls carrying `_meta` (`io.modelcontextprotocol/protocolVersion`,
  `clientCapabilities`, `clientInfo`) per SEP-2575; optionally probe
  `server/discover` first. Assert per-request behavior instead of session headers.
- [ ] **M2 — `examples/agentgateway.standalone.yaml`**: remove `mcp-session-id`
  from CORS `allowHeaders`; add `mcp-method` and `mcp-name` (required on Streamable
  HTTP POST per SEP-2243). Keep `mcp-protocol-version`.

### Coverage follow-ups

- [ ] **M3 — MRTR redaction gap**: client `inputResponses` ride on retried request
  params. They are *scanned* today (fallback JSON dump) but not structurally
  redacted — extend the request mutation path beyond `params.arguments` once
  agentgateway forwards MRTR shapes. Verify `InputRequiredResult`
  (`resultType: "input_required"`, `inputRequests[].message`) response-side text
  extraction in `guardrails/scanners.py:extract_text`.
- [ ] **M4 — Docs**: `docs/e2e.md` and session-affinity references assume sessions;
  update alongside M1/M2.

### Optional

- [ ] **M5 — OTel**: adopt `_meta` `traceparent`/`tracestate`/`baggage` for
  agentgateway → sidecar trace correlation.

## Re-evaluation checklist (on next agentgateway release)

1. Confirm upstream agentgateway release notes for 2026-07-28 transport support and
   any ExtMcp proto changes (`CheckRequest`/`CheckResponse` semantics, new methods
   forwarded: `server/discover`, `subscriptions/listen`).
2. Re-run this eval against the new agentgateway version; bump pins
   (`examples/agentgateway.standalone.yaml`, `docs/e2e.md`, `deploy/k8s/`).
3. Execute M1–M4; verify with `scripts/e2e_agentgateway.sh` end-to-end (7/7 matrix).
4. Regression gates: pytest + ruff + e2e_smoke + proto_check + version_check.
