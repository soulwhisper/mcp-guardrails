#!/usr/bin/env bash
# e2e_agentgateway.sh — live interoperability test: mcp-guardrails sidecar
# with a real agentgateway binary (standalone config, mcpGuardrails processor).
#
# Verified against agentgateway v1.3.1 (standalone YAML, binds/mcpGuardrails
# schema). The script boots:
#
#   client(curl) -> agentgateway :3000 (mcpGuardrails, failClosed)
#                -> ExtMcp sidecar gRPC :9001 (this repo, regex-only mode)
#                -> stdio MCP upstream (examples/mcp_pii_upstream.py)
#
# and asserts the use-case matrix:
#   a. tools/call echo (benign)            -> pass-through, echo returned
#   b. tools/call pii_leak                 -> response MUTATED ([REDACTED:EMAIL])
#   c. tools/call echo w/ private key arg  -> DENY, JSON-RPC -32001
#   d. same tool+args x4                   -> DENY (invariant loop rule)
#   e. sidecar killed, tools/call          -> failClosed, JSON-RPC -32603
#   f. sidecar audit log                   -> outcome="mutated"/"deny" lines
#
# Prerequisites:
#   - python3 with -r requirements.txt installed (protobuf, grpcio, ...).
#     The ONNX model is NOT needed: the sidecar runs with
#     ENABLE_PROMPTGUARD=0 (regex/redaction/invariant only, zero ML deps).
#   - a python interpreter with the `mcp` package for the stdio upstream
#     (set UPSTREAM_PYTHON; defaults to python3).
#   - an agentgateway binary: set AGENTGATEWAY_BIN or put `agentgateway`
#     on PATH. If absent, the script prints a skip notice and exits 0 so
#     CI can treat this as an optional integration job.
#
# Usage:
#   AGENTGATEWAY_BIN=/path/to/agentgateway ./scripts/e2e_agentgateway.sh
#   UPSTREAM_PYTHON=/path/to/venv/bin/python ./scripts/e2e_agentgateway.sh
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGW_BIN="${AGENTGATEWAY_BIN:-$(command -v agentgateway || true)}"
UPSTREAM_PYTHON="${UPSTREAM_PYTHON:-python3}"
SIDECAR_PORT="${SIDECAR_PORT:-9001}"
AGW_PORT="${AGW_PORT:-3000}"

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $*"; }

# --- Skip gate: no agentgateway binary -> optional CI job -------------------
if [ -z "$AGW_BIN" ] || [ ! -x "$AGW_BIN" ]; then
    echo "SKIP: agentgateway binary not found (set AGENTGATEWAY_BIN or add it to PATH)."
    echo "      This e2e is optional; unit tests (make test) cover the policy core."
    exit 0
fi
echo "agentgateway: $AGW_BIN"
"$AGW_BIN" --version 2>&1 | head -1 || true

WORKDIR="$(mktemp -d /tmp/mcp-guardrails-e2e.XXXXXX)"
SIDECAR_PID=""
AGW_PID=""

cleanup() {
    # Kill by PID only — pkill -f would match this script's own cmdline.
    [ -n "$SIDECAR_PID" ] && kill "$SIDECAR_PID" 2>/dev/null
    [ -n "$AGW_PID" ] && kill "$AGW_PID" 2>/dev/null
    wait 2>/dev/null
    echo "logs kept in: $WORKDIR"
}
trap cleanup EXIT

wait_port() { # host port timeout_secs
    local deadline=$((SECONDS + $3))
    while [ $SECONDS -lt $deadline ]; do
        (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && exec 3>&- 3<&- && return 0
        sleep 0.3
    done
    return 1
}

# --- 1. Start the guardrail sidecar (regex-only, no ONNX download) ---------
echo "== starting sidecar on :$SIDECAR_PORT (ENABLE_PROMPTGUARD=0) =="
# `exec` so $! is the python PID itself (a plain subshell would orphan it).
(cd "$REPO_ROOT" && exec env ENABLE_REDACTION=1 ENABLE_PROMPTGUARD=0 \
    LISTEN_ADDR="[::]:$SIDECAR_PORT" \
    python3 server.py > "$WORKDIR/sidecar.log" 2>&1) &
SIDECAR_PID=$!
wait_port 127.0.0.1 "$SIDECAR_PORT" 30 || { echo "FAIL: sidecar did not open :$SIDECAR_PORT"; tail -20 "$WORKDIR/sidecar.log"; exit 1; }

# --- 2. Render standalone agentgateway config & start it --------------------
sed -e "s|@UPSTREAM_PYTHON@|$UPSTREAM_PYTHON|g" \
    -e "s|@UPSTREAM_SCRIPT@|$REPO_ROOT/examples/mcp_pii_upstream.py|g" \
    -e "s|@SIDECAR_PORT@|$SIDECAR_PORT|g" \
    -e "s|@AGW_PORT@|$AGW_PORT|g" \
    "$REPO_ROOT/examples/agentgateway.standalone.yaml" > "$WORKDIR/agentgateway.yaml"

echo "== starting agentgateway on :$AGW_PORT =="
"$AGW_BIN" -f "$WORKDIR/agentgateway.yaml" > "$WORKDIR/agentgateway.log" 2>&1 &
AGW_PID=$!
wait_port 127.0.0.1 "$AGW_PORT" 30 || { echo "FAIL: agentgateway did not open :$AGW_PORT"; tail -20 "$WORKDIR/agentgateway.log"; exit 1; }

# --- 3. MCP handshake (Streamable HTTP) --------------------------------------
HDR=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0.1"}}}'
curl -s -D "$WORKDIR/init.hdrs" -X POST "http://localhost:$AGW_PORT/mcp" "${HDR[@]}" -d "$INIT" > "$WORKDIR/init.body"
SESSION=$(grep -i '^mcp-session-id:' "$WORKDIR/init.hdrs" | tr -d '\r' | awk '{print $2}')
[ -n "$SESSION" ] || { echo "FAIL: no mcp-session-id in initialize response"; cat "$WORKDIR/init.body"; exit 1; }
echo "session: $SESSION"
curl -s -o /dev/null -X POST "http://localhost:$AGW_PORT/mcp" "${HDR[@]}" -H "mcp-session-id: $SESSION" \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

mcp_call() { # json-payload -> body; unwrap the SSE "data: " frame when present
    # (allowed results stream as SSE; guardrail denies come back as plain JSON)
    curl -s -X POST "http://localhost:$AGW_PORT/mcp" "${HDR[@]}" -H "mcp-session-id: $SESSION" -d "$1" \
        | awk '/^data: /{sub(/^data: /,""); sse=$0; have=1; next} {plain=plain $0 "\n"}
               END{if(have) print sse; else printf "%s", plain}'
}
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }

# --- 4. Use-case matrix ------------------------------------------------------
echo "== a) tools/call echo (benign) =="
BODY=$(mcp_call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello guardrails"}}}')
echo "$BODY"
[ "$(echo "$BODY" | jget 'print(d["result"]["content"][0]["text"])')" = "hello guardrails" ] \
    && ok "echo pass-through" || bad "echo pass-through"

echo "== b) tools/call pii_leak (response redaction / mutation) =="
BODY=$(mcp_call '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pii_leak","arguments":{}}}')
echo "$BODY"
echo "$BODY" | grep -q '\[REDACTED:EMAIL\]' && ! echo "$BODY" | grep -q 'jdoe@example.com' \
    && ok "pii_leak mutated ([REDACTED:EMAIL])" || bad "pii_leak redaction"

echo "== c) private key in request args (deny) =="
BODY=$(mcp_call '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----"}}}')
echo "$BODY"
# The wire body is generalised (F-P1-1): pattern names (e.g. private_key)
# never reach the client — only the -32001 code plus a generalised
# category. Regex-scanner denies map to category "content_policy".
echo "$BODY" | grep -q '"code": *-32001' && echo "$BODY" | grep -q 'content_policy' \
    && ok "private-key request denied (-32001/content_policy)" || bad "private-key deny"
# The internal pattern name stays audit-only: the sidecar log records the
# full regex:private_key reason for the same exchange.
grep -q 'regex:private_key' "$WORKDIR/sidecar.log" \
    && ok "audit log records regex:private_key reason" || bad "audit log missing regex:private_key"

echo "== d) loop rule (same tool+args x4 -> 3rd+ denied) =="
LOOP_DENY=0
for i in 1 2 3 4; do
    BODY=$(mcp_call "{\"jsonrpc\":\"2.0\",\"id\":3$i,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"loop-probe\"}}}")
    echo "$BODY"
    # Invariant denies are generalised on the wire (F-P1-1): the rule name
    # (denied-tool-retry-loop) stays audit-only; the client sees -32001 with
    # the invariant category "tool_flow".
    echo "$BODY" | grep -q '"code": *-32001' && echo "$BODY" | grep -q 'tool_flow' \
        && LOOP_DENY=$((LOOP_DENY+1))
done
[ "$LOOP_DENY" -ge 1 ] && ok "loop rule fired ($LOOP_DENY wire denies, -32001/tool_flow)" || bad "loop rule did not fire"
# Supplementary check: the internal rule name is recorded in the sidecar's
# audit log (grep the audit reason, not the wire body).
grep -q 'invariant:denied-tool-retry-loop' "$WORKDIR/sidecar.log" \
    && ok "audit log records invariant:denied-tool-retry-loop" || bad "audit log missing loop rule name"

echo "== f) sidecar audit log (mutated / deny outcomes) =="
grep -q '"outcome": "mutated"' "$WORKDIR/sidecar.log" && ok 'audit outcome="mutated" present' || bad 'no mutated audit line'
grep -q '"outcome": "deny"' "$WORKDIR/sidecar.log" && ok 'audit outcome="deny" present' || bad 'no deny audit line'

echo "== e) failClosed interop (kill sidecar, then tools/call) =="
kill "$SIDECAR_PID" 2>/dev/null; wait "$SIDECAR_PID" 2>/dev/null; SIDECAR_PID=""
sleep 1
BODY=$(mcp_call '{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"echo","arguments":{"text":"failclosed-probe"}}}')
echo "$BODY"
echo "$BODY" | grep -q '"code": *-32603' \
    && ok "failClosed on sidecar outage (-32603)" || bad "failClosed interop"

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
