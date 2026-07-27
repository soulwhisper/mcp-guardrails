# End-to-end test (real agentgateway)

`scripts/e2e_agentgateway.sh` stands up the full production topology against
a **real agentgateway binary** (verified with v1.3.1, standalone YAML):

```text
client(curl) -> agentgateway :3000 (mcpGuardrails processor, failClosed)
             -> ExtMcp sidecar gRPC :9001 (ENABLE_PROMPTGUARD=0, regex-only)
             -> stdio MCP upstream (examples/mcp_pii_upstream.py)
```

## Prerequisites

- `python3` with `-r requirements.txt` installed. No ONNX model download is
  needed — the script runs the sidecar with `ENABLE_PROMPTGUARD=0`
  (regex-only).
- A Python interpreter with the `mcp` package for the stdio upstream
  (`UPSTREAM_PYTHON`, defaults to `python3`).
- An agentgateway binary via `AGENTGATEWAY_BIN` or on `PATH`. If no binary is
  found the script prints a skip notice and exits 0, so CI can wire it in as
  an optional job.

## Running

```bash
AGENTGATEWAY_BIN=/path/to/agentgateway ./scripts/e2e_agentgateway.sh
```

The script drives the official Streamable-HTTP MCP handshake
(`initialize` → `mcp-session-id` → `notifications/initialized`) and asserts:

| Case | Expected |
| --- | --- |
| `tools/call echo` (benign) | pass-through, echo returned |
| `tools/call pii_leak` | response **mutated**: `jdoe@example.com` → `[REDACTED:EMAIL]` |
| `tools/call echo` with `-----BEGIN RSA PRIVATE KEY-----` arg | deny, JSON-RPC `-32001` |
| same tool+args ×4 | 3rd+ call denied (`invariant:denied-tool-retry-loop`) |
| sidecar killed, then `tools/call` | failClosed: JSON-RPC `-32603` |
| sidecar audit log | `outcome="mutated"` / `outcome="deny"` JSONL lines |

The gateway config it consumes is
[`examples/agentgateway.standalone.yaml`](https://github.com/soulwhisper/mcp-guardrails/blob/main/examples/agentgateway.standalone.yaml);
all processes are cleaned up by PID on exit.

## Lighter-weight checks

- `python3 tests/e2e_smoke.py` — boots a live server in a subprocess
  (regex-only) and exercises the full ExtMcp gRPC surface: health check,
  `CheckRequest` allow + deny (hidden Unicode), `CheckResponse` deny
  (private key), malformed-payload `INVALID`. Exits non-zero on any mismatch.
