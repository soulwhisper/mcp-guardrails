# Deployment

## Container image

`ghcr.io/soulwhisper/mcp-guardrails:<version>` (current: `0.4.0`). Multi-stage
build, runs as nonroot (uid 65532), pre-bakes the PromptGuard-2 ONNX model
pinned via the `PG2_REVISION` build-arg. Version tags (`x.y.z`) are immutable;
`latest` and `x.y` float.

## Kubernetes manifests

`deploy/k8s/` contains a ready-made set:

| Manifest | Purpose |
| --- | --- |
| `namespace.yaml` | Dedicated namespace. |
| `deployment.yaml` | Sidecar Deployment (image pinned by release-please; env knobs incl. commented optional overrides). |
| `service.yaml` | Service with `appProtocol: kubernetes.io/h2c`. |
| `configmap.yaml` | Rule pack, mounted at `/etc/guardrails/rules.policy`. |
| `agentgateway-policy.yaml` | `AgentgatewayPolicy` CRD wiring the sidecar into agentgateway. |
| `hpa.yaml` / `pdb.yaml` | Scaling / disruption budgets. |
| `kustomization.yaml` | Kustomize bundle. |

Key points:

- **`appProtocol: kubernetes.io/h2c`** on the Service port is what tells
  agentgateway this is plaintext-HTTP/2 gRPC; the sidecar binds an insecure
  port (no TLS) because the gateway handles transport security. Do not add
  TLS to the sidecar unless you also switch the Service appProtocol to
  `kubernetes.io/grpc` and provide a certificate.
- **ConfigMap rule pack**: mount at `/etc/guardrails/rules.policy` and set
  `INVARIANT_RULES_PATH` to match. Reload without restarting the Pod with
  `kill -HUP 1` inside the container.
- **`failureMode: FailClosed`** in the policy: the only safe default for
  write-capable agents. If the sidecar Pod is unreachable, agentgateway
  returns JSON-RPC `-32001` rather than forwarding unguarded.
- **Readiness probe**: the `grpc.health.v1` check goes `SERVING` only after
  engine warmup (PromptGuard-2 model load), keeping the Pod out of the
  Service endpoints during cold start.
- **Resources**: a 2Gi memory budget covers onnxruntime CPU + the ~350MB
  PromptGuard-2 weights. Bump when enabling `ENABLE_AGENT_ALIGNMENT=1`.

## agentgateway wiring

Two supported shapes:

1. **CRD (Kubernetes)** — `deploy/k8s/agentgateway-policy.yaml` maps:
   - `tools/call` → `Full` (request + response double gate — the
     indirect-injection frontline lives on the response side);
   - `tools/list`, `prompts/get`, `resources/read` → `Response`;
   - `ping` / `initialize` → `None`.
2. **Standalone** —
   [`examples/agentgateway.standalone.yaml`](https://github.com/soulwhisper/mcp-guardrails/blob/main/examples/agentgateway.standalone.yaml)
   points a non-K8s agentgateway at `localhost:9001` (the `binds` /
   `mcpGuardrails` schema; `@PLACEHOLDER@` tokens are substituted by the
   [e2e script](e2e.md)).

## Multi-replica guidance

Two sidecar subsystems are per-process:

- **Invariant traces** live in memory. Have agentgateway inject a session
  header (e.g. `x-session-id`), set `INVARIANT_TRACE_KEY_HEADERS` to match,
  and configure sticky/session-affinity routing on the gateway side — sticky
  routing itself is the deployer's responsibility. Without it, a toxic flow
  whose calls land on different replicas cannot be detected.
- **The audit hash chain** assumes a single writer per stream. Do not point
  multiple replicas at one shared `AUDIT_LOG_PATH` file — use per-replica
  files or stdout shipping (see [Auditing](operations/auditing.md)).

## Network isolation

The sidecar authenticates nothing on `:9001`. Restrict access to agentgateway
with a `NetworkPolicy` (or mesh mTLS) before treating audit verdicts as
authoritative — see the [security model](security-model.md).
