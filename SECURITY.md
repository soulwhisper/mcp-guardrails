# Security Policy

## Reporting a vulnerability

Do **not** open a public GitHub issue for security vulnerabilities in
MCP Guardrails.

Email the maintainer privately at **`soulwhisper@outlook.com`** with:

- a description of the issue,
- the version / image tag you are running
  (`ghcr.io/soulwhisper/mcp-guardrails:<tag>`),
- the relevant configuration (env vars; redact secrets),
- a minimal repro if possible.

You should receive an acknowledgement within **72 hours**. We aim for a fix
or mitigation within **30 days** of acknowledgement, with coordinated
public disclosure after a patched release is available. If you have a
preferred disclosure timeline, say so in the report.

## Scope

In scope:

- Bypass of the fail-closed default (any path that lets an unguarded MCP
  exchange through to the upstream or to the agent).
- Bypass of any `BLOCK` outcome (regex scanner, ONNX PromptGuard scanner,
  Invariant rule).
- Malformed-payload handling that does not map to `INVALID_ARGUMENT`.
- Wire-contract drift between `proto/ext_mcp.proto` and the agentgateway
  ExtMcp contract that breaks fail-closed behaviour.
- Container escape / privilege escalation from the sidecar Pod.

Out of scope (but still welcome as regular issues):

- Bypasses that require an already-malicious upstream MCP server (the
  sidecar assumes the upstream is untrusted; response-side scanning is
  the defence).
- Generic PromptGuard-2 model weaknesses (report those upstream to the
  [PurpleLlama](https://github.com/meta-llama/PurpleLlama) project).
- Generic agentgateway issues (report those upstream to
  [agentgateway](https://github.com/agentgateway/agentgateway)).

## Supported versions

Only the latest minor release line receives security fixes.

## Hardening recommendations

For deployments handling write-capable agents (file write, email send,
k8s apply, shell exec):

- Keep `FAILURE_MODE=failClosed` (the default). Switch to `failOpen` only
  for read-only agents where a guardrail outage is judged less harmful
  than blocking the agent.
- Keep `HUMAN_REVIEW_MODE=pass` for homelab (forward + audit) or escalate
  to `deny` for stricter deployments. Do not set `failOpen` together
  with `HUMAN_REVIEW_MODE=deny` — that combination escalates every
  degraded scanner to a hard deny, which is rarely what you want.
- Set `OTEL_EXPORTER_OTLP_ENDPOINT` so counter `mcp.guardrails.decisions`
  is exported. Alert on any non-zero rate of `outcome=deny` (could indicate
  an active attack) or `outcome=human_review` (could indicate scanner
  degradation).
- Mount the rule pack as a read-only ConfigMap at
  `/etc/guardrails/rules.policy`. Reload via `kill -HUP 1` inside the
  container — never edit the file in place on a running Pod.
- Run the sidecar Pod with `runAsNonRoot: true`, `runAsUser: 65532`,
  `seccompProfile: RuntimeDefault`, and `readOnlyRootFilesystem: true`
  (the bundled K8s manifests in `deploy/k8s/` do all of this).
- Set `SCANNER_TIMEOUT_MS` strictly less than the agentgateway
  `mcp-guardrails` processor timeout so the sidecar always decides first.
- Do not rely on request headers for authn/authz when
  `metadata_context.upstream_transport == "stdio"` — agentgateway forwards
  an empty header set for stdio upstreams.

## Disclosure policy

Coordinated disclosure. We credit reporters in the release notes and
`CHANGELOG.md` entry unless they request anonymity.
