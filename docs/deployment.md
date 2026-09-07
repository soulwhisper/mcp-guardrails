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
| `deployment.yaml` | Sidecar Deployment (image pinned by release-please; env knobs incl. commented optional overrides; preStop drain hook + grace period aligned with `SHUTDOWN_DRAIN_S`). |
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

## Rollout and drain

Rolling updates and HPA scale-downs are aligned with the sidecar's
shutdown sequence (R-5). On pod deletion, in order:

1. **preStop sleep (10s).** Kubernetes marks the pod for deletion and
   removes it from Service endpoints immediately, but kubelet holds the
   SIGTERM while the `preStop` hook sleeps. Endpoint removal propagates
   (kubelet → endpoints controller → agentgateway dataplane) during this
   window, so new exchanges stop arriving before the process even begins
   shutting down.
2. **SIGTERM.** The health service flips to `NOT_SERVING` first (the
   health watchdog is cancelled so it cannot flip back mid-drain) — a
   second propagation barrier for anything that missed step 1.
3. **Drain wait (`SHUTDOWN_DRAIN_S`, default 5s).** The sidecar waits for
   readiness propagation; in-flight exchanges keep running.
4. **gRPC drain (grace 5s) + exit.** `server.stop(grace)` lets in-flight
   RPCs complete, then the process exits.

`terminationGracePeriodSeconds: 30` budgets preStop (10s) + drain wait
(5s) + gRPC grace (5s) = 20s of scripted shutdown, plus 10s headroom for
slow in-flight exchanges inside the drain grace. It must **exceed**
preStop + `SHUTDOWN_DRAIN_S` — if kubelet's grace expires first it sends
SIGKILL mid-drain, truncating in-flight exchanges and their audit lines.
If you raise `SHUTDOWN_DRAIN_S` or the preStop sleep, raise the grace
period to match.

The `POD_NAME` env (via `fieldRef: metadata.name`) is set so audit
replica attribution (`AUDIT_REPLICA_ID`, default `$POD_NAME`) works out
of the box — see [Compliance §2](compliance.md).

Remaining validation step: a live rolling-update soak against a real
cluster (watch endpoint churn, drain timing and audit-chain continuity
across several rollouts under load) has not yet been run — the sequence
above is derived from the shutdown implementation and probe timings, not
soak-tested.

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

Two sidecar subsystems are per-process by default:

- **Invariant traces** default to in-memory per replica
  (`INVARIANT_STATE_BACKEND=memory`). Have agentgateway inject a session
  header (e.g. `x-session-id`), set `INVARIANT_TRACE_KEY_HEADERS` to match,
  and configure sticky/session-affinity routing on the gateway side — sticky
  routing itself is the deployer's responsibility. Without it, a toxic flow
  whose calls land on different replicas cannot be detected. The stronger
  option is `INVARIANT_STATE_BACKEND=redis` with `REDIS_URL` pointing at a
  shared Redis: loop/rate/aggregate rules then evaluate the fleet-wide
  trace regardless of which replica a call lands on (appends are
  linearised by Redis; detection may lag one call under concurrent
  replicas; the sidecar fails closed at startup if Redis is unreachable).
  Sticky ToxicFlow prefix-progress remains per-replica in both modes.
- **The audit hash chain** is per-process: each replica maintains an
  independent chain. Do not point multiple replicas at one shared
  `AUDIT_LOG_PATH` file — use per-replica files or stdout shipping (see
  [Auditing](operations/auditing.md)). Every chained line carries a
  `replica` field (from `AUDIT_REPLICA_ID`, default `$POD_NAME` via the
  `fieldRef` in `deployment.yaml`) inside the hashed payload, so exported
  per-replica chains stay attributable — see [Compliance §2](compliance.md).

## Network isolation

The sidecar authenticates nothing on `:9001`. Restrict access to agentgateway
with a `NetworkPolicy` (or mesh mTLS) before treating audit verdicts as
authoritative — see the [security model](security-model.md).
