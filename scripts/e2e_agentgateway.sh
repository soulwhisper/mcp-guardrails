#!/usr/bin/env bash
# e2e_agentgateway.sh — live interoperability test: mcp-guardrails sidecar
# with a real agentgateway binary (standalone config, mcpGuardrails processor).
#
# Verified against agentgateway v1.6.0 (the version pinned in CI by
# .github/workflows/e2e-agentgateway.yml; standalone YAML, binds/mcpGuardrails
# schema) using the sessionless MCP 2026-07-28 flow end to end. The script boots:
#
#   client(curl) -> agentgateway :3000 (mcpGuardrails, failClosed)
#                -> ExtMcp sidecar gRPC :9001 (this repo, regex-only mode)
#                -> stdio MCP upstream (examples/mcp_pii_upstream.py)
#
# and asserts the use-case matrix over the sessionless 2026-07-28 protocol
# (no initialize handshake, no Mcp-Session-Id — per-request `_meta` per
# SEP-2575 and Mcp-Method/Mcp-Name headers per SEP-2243):
#   0. server/discover probe            -> supportedVersions includes 2026-07-28
#   a. tools/call echo (benign)         -> pass-through, echo returned, resultType complete
#   b. tools/call pii_leak              -> response MUTATED ([REDACTED:EMAIL])
#   c. tools/call echo w/ private key arg -> DENY as result (isError, generalised text)
#   d. same tool+args x4                -> DENY (invariant loop rule)
#   e. sidecar killed, tools/call       -> failClosed, JSON-RPC -32603
#   f. sidecar audit log                -> outcome="mutated"/"deny" lines
#
# Prerequisites:
#   - python3 with -r requirements.txt installed (protobuf, grpcio, ...).
#     The ONNX model is NOT needed: the sidecar runs with
#     ENABLE_PROMPTGUARD=0 (regex/redaction/invariant only, zero ML deps).
#   - a python interpreter with the `mcp` package (v2, MCPServer API — pin
#     "mcp>=2"; v2 servers answer server/discover and serve 2026-07-28) for
#     the stdio upstream (set UPSTREAM_PYTHON; defaults to python3).
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

# --- 3. Sessionless 2026-07-28: no initialize, no Mcp-Session-Id ------------
# Every POST carries the protocol version header, per-request `_meta`
# (SEP-2575), and the Mcp-Method/Mcp-Name pair (SEP-2243).
HDR=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream"
     -H "mcp-protocol-version: 2026-07-28")
META='{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"e2e","version":"0.1"}}'

# mcp_call <method> <name-or-empty> <params-json> — params may be empty.
mcp_call() {
    local method="$1" name="$2" params="$3"
    local extra=(-H "mcp-method: $method")
    [ -n "$name" ] && extra+=(-H "mcp-name: $name")
    local payload
    if [ -n "$params" ]; then
        payload=$(python3 -c "import json,sys; p=json.loads(sys.argv[1]); p['_meta']=json.loads(sys.argv[2]); print(json.dumps({'jsonrpc':'2.0','id':$RANDOM,'method':sys.argv[3],'params':p}))" "$params" "$META" "$method")
    else
        payload=$(python3 -c "import json,sys; print(json.dumps({'jsonrpc':'2.0','id':$RANDOM,'method':sys.argv[1],'params':{'_meta':json.loads(sys.argv[2])}}))" "$method" "$META")
    fi
    # Allowed results stream as SSE; guardrail denies come back as plain JSON.
    curl -s -X POST "http://localhost:$AGW_PORT/mcp" "${HDR[@]}" "${extra[@]}" -d "$payload" \
        | awk '/^data: /{sub(/^data: /,""); sse=$0; have=1; next} {plain=plain $0 "\n"}
               END{if(have) print sse; else printf "%s", plain}'
}
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }

echo "== 0) server/discover probe (SEP-2575) =="
BODY=$(mcp_call "server/discover" "" "")
echo "$BODY"
echo "$BODY" | grep -q '2026-07-28' && ok "discover advertises 2026-07-28" || bad "discover probe"
echo "$BODY" | jget 'assert "error" not in d' 2>/dev/null && ok "discover answered without error" || bad "discover errored"
# --- 4. Use-case matrix ------------------------------------------------------
echo "== a) tools/call echo (benign) =="
BODY=$(mcp_call "tools/call" "echo" '{"name":"echo","arguments":{"text":"hello guardrails"}}')
echo "$BODY"
[ "$(echo "$BODY" | jget 'print(d["result"]["content"][0]["text"])')" = "hello guardrails" ] \
    && ok "echo pass-through" || bad "echo pass-through"
# 2026-07-28 clients get the required resultType marker on every result.
[ "$(echo "$BODY" | jget 'print(d["result"].get("resultType"))')" = "complete" ] \
    && ok "resultType complete on 2026-07-28 result" || bad "resultType missing"

echo "== b) tools/call pii_leak (response redaction / mutation) =="
BODY=$(mcp_call "tools/call" "pii_leak" '{"name":"pii_leak","arguments":{}}')
echo "$BODY"
echo "$BODY" | grep -q '\[REDACTED:EMAIL\]' && ! echo "$BODY" | grep -q 'jdoe@example.com' \
    && ok "pii_leak mutated ([REDACTED:EMAIL])" || bad "pii_leak redaction"

echo "== c) private key in request args (deny) =="
BODY=$(mcp_call "tools/call" "echo" '{"name":"echo","arguments":{"text":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----"}}')
echo "$BODY"
# agentgateway v1.6 maps ExtMcp tools/call denials to an HTTP-200 tool-error
# result (resultType complete, isError true) instead of a JSON-RPC error.
# The wire body is generalised (F-P1-1): pattern names (e.g. private_key)
# never reach the client — only a fixed phrase plus an opaque ref.
echo "$BODY" | jget 'r=d["result"]; assert r["isError"] is True and r.get("resultType")=="complete"' 2>/dev/null \
    && echo "$BODY" | grep -q 'denied by content policy' && ! echo "$BODY" | grep -q 'private_key' \
    && ok "private-key request denied (isError, generalised)" || bad "private-key deny"
# The internal pattern name stays audit-only: the sidecar log records the
# full regex:private_key reason for the same exchange.
grep -q 'regex:private_key' "$WORKDIR/sidecar.log" \
    && ok "audit log records regex:private_key reason" || bad "audit log missing regex:private_key"

echo "== d) loop rule (same tool+args x4 -> 3rd+ denied) =="
LOOP_DENY=0
for i in 1 2 3 4; do
    BODY=$(mcp_call "tools/call" "echo" '{"name":"echo","arguments":{"text":"loop-probe"}}')
    echo "$BODY"
    # Invariant denies are generalised on the wire (F-P1-1): the rule name
    # (denied-tool-retry-loop) stays audit-only; the client sees an isError
    # result with the fixed phrase.
    echo "$BODY" | grep -q '"isError": *true' && echo "$BODY" | grep -q 'denied by content policy' \
        && LOOP_DENY=$((LOOP_DENY+1))
done
[ "$LOOP_DENY" -ge 1 ] && ok "loop rule fired ($LOOP_DENY wire denies, isError)" || bad "loop rule did not fire"
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
BODY=$(mcp_call "tools/call" "echo" '{"name":"echo","arguments":{"text":"failclosed-probe"}}')
echo "$BODY"
echo "$BODY" | grep -q '"code": *-32603' \
    && ok "failClosed on sidecar outage (-32603)" || bad "failClosed interop"

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
