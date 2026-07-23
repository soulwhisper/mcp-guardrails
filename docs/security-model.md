# Security model

## Threat model

The sidecar guards MCP exchanges between an LLM agent and upstream MCP
servers. In scope:

- **Direct prompt injection** in tool-call arguments (request side, `TOOL`
  role).
- **Indirect prompt injection** in tool output, tool descriptions, resource
  contents and prompt bodies (response side, `ASSISTANT` role) — the primary
  frontline, since attacker-controlled text is exactly where
  instructions-to-the-LLM sneak back into the agent's context.
- **Secret / PII leakage** in both directions (regex patterns + redaction).
- **Cross-call toxic flows**: exfiltration sequences, retry storms,
  volumetric abuse, cumulative-budget bleed (Invariant rules).
- **Obfuscation evasion**: hidden/zero-width Unicode, full-width forms,
  Cyrillic/Greek homoglyphs, base64-wrapped resource blobs, truncation
  padding.

Out of scope (by design):

- **Rewriting / normalisation as a policy primitive** — other agentgateway
  modules' job (redaction excepted).
- **Network isolation** — the deployer's responsibility. The sidecar binds
  plaintext h2c on `:9001` with **no authentication of its own**; protect the
  gateway↔sidecar path with a Kubernetes `NetworkPolicy`, mesh mTLS, or
  namespace segmentation.

!!! warning "Trust assumption"
    Without network isolation, any workload in the same cluster can talk to
    the sidecar directly — bypassing the gateway, replaying or probing
    exchanges. In that posture the integrity of the Invariant trace windows
    and of individual scan verdicts must not be relied upon for cross-tenant
    guarantees. Deploy a `NetworkPolicy` (or mesh mTLS) restricting `:9001`
    to agentgateway before treating audit verdicts as authoritative.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| Scanner raises / exceeds `SCANNER_TIMEOUT_MS` | `failClosed` → `BLOCK` → aggregator denies → `error` oneof → agentgateway returns JSON-RPC `-32001`. `failOpen` → `HUMAN_REVIEW` → forwarded with audit warning. |
| Sidecar Pod unreachable | agentgateway's mcp-guardrails processor fails closed → JSON-RPC `-32001` to the agent. |
| PromptGuard model load failure | Pod readiness probe stays `NOT_SERVING`; the Pod is removed from Service endpoints. No traffic reaches a half-initialised sidecar. |
| Malformed JSON-RPC payload | Servicer returns `AuthorizationError{INVALID}` (fail-closed on parse failure). |
| Tool output > `MAX_CONTENT_BYTES` | head (32KiB) + mid + tail (8KiB each) windows scanned; decision flagged `truncated=true`. Regions between the windows remain unscanned (bounded by `SCAN_MAX_PAYLOAD_BYTES`). |
| PromptGuard token-window ceiling | Chunks beyond ~`PG_MAX_WINDOWS*448 + 512` tokens (≈7.7K at the default) have unscanned middle regions — an injection padded past the scored windows can be missed. Defence-in-depth: byte-level head/mid/tail split + the `payload_size` cap. |
| Payload > `SCAN_MAX_PAYLOAD_BYTES` (1MiB) | Still scanned via the three windows, plus a `payload_size` `HUMAN_REVIEW` with scanned/total bytes — `HUMAN_REVIEW_MODE=deny` makes it a hard deny. |
| stdio upstream | agentgateway forwards an empty header set for stdio upstreams. Do **not** rely on headers for authn/authz when `upstream_transport == "stdio"`. |

**failOpen × redaction.** Under `failOpen` a scanner exception becomes
`HUMAN_REVIEW`. With the default `REDACT_ON_REVIEW=1` the payload is still
redacted before forwarding — failOpen trades away the block layer but keeps
the masking layer. With `REDACT_ON_REVIEW=0` (legacy) review payloads are
forwarded in cleartext (with the audit warning), trading both layers away
for availability.

**Deny-reason generalisation.** Wire-visible deny reasons are fixed generic
strings (`denied by content policy` / `denied by response policy`, plus a
short correlation `ref`; `engine_error` for internal failures) so a caller
cannot iterate a payload against scanner feedback. The full internal reason
— scanner, pattern, match fingerprint — lives only in the audit log. The
structured deny body (`AuthorizationError.mcp_error`, code `-32001`) adds a
generalised policy `category` (e.g. `content_policy`, `tool_policy`,
`tool_flow`) and a generic `remedy` hint — never pattern names or rule
internals.

The fail-closed posture is deliberate: an agent that can call real tools is
far more dangerous when a guardrail outage is silent than when it is loud.
`-32001` is loud.

## Known limitations

- **Method coverage.** The sidecar only sees the MCP methods agentgateway
  forwards to it. The default methods mapping covers `tools/call`,
  `tools/list`, `prompts/get` and `resources/read`. **Reverse-channel / other
  MCP methods — `sampling/createMessage`, `elicitation/create`,
  `completion/complete`, `roots/list`, notifications — are NOT covered**
  unless the deployment's methods mapping is extended to forward them. If
  your threat model includes indirect injection via server-initiated
  sampling/elicitation, treat this sidecar as one layer of a broader policy.
- **Invariant trace scope.** Only `tools/call` requests with a non-empty
  tool name advance toxic-flow state; other methods are scanned for content
  but do not advance the trace.
- **Scan coverage residuals.** Unscanned middle regions on large payloads,
  multi-window split attacks, and the `REDACTION_MAX_BYTES` redaction skip —
  enumerated honestly in [Scan coverage](guardrails/scan-coverage.md).
- **Multi-replica state.** Trace windows and the audit hash chain are
  per-process; see [Deployment](deployment.md#multi-replica-guidance).
- **Audit limitations.** Best-effort local writes, hash chain is
  tamper-evident (not signed), no sidecar-side at-rest encryption, node-local
  clock — see [Compliance](compliance.md).

## Reporting a vulnerability

Do **not** open a public GitHub issue. Email the maintainer privately (see
`SECURITY.md` in the repo) with a description, the version/image tag, the
relevant configuration, and a repro if possible.
