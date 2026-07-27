# Getting started

Three steps from zero to a guarded MCP exchange: run the sidecar, deploy it
next to agentgateway, wire the gateway policy — then verify.

## 1. Run the sidecar (Docker)

```bash
docker run --rm -p 9001:9001 \
  --env-file examples/docker-run.env \
  -v $(pwd)/examples/rules.policy:/etc/guardrails/rules.policy:ro \
  ghcr.io/soulwhisper/mcp-guardrails:0.4.0
```

The image pre-bakes the PromptGuard-2 ONNX model (pinned via the
`PG2_REVISION` build-arg), so no HuggingFace token and no runtime download is
needed. The sidecar listens on plaintext h2c gRPC on `:9001`.

To validate wiring without loading any ML models, use dry-run mode:

```bash
docker run --rm -p 9001:9001 \
  -e GUARDRAIL_DRY_RUN=1 -e ENABLE_REGEX_SCANNER=0 -e ENABLE_PROMPTGUARD=0 \
  ghcr.io/soulwhisper/mcp-guardrails:0.4.0
```

## 2. Deploy on Kubernetes

Apply the manifests in `deploy/k8s/` (Deployment + Service + ConfigMap rule
pack + `AgentgatewayPolicy` CRD), e.g. with the bundled Kustomize overlay:

```bash
kubectl apply -k deploy/k8s/
```

See the [Deployment](deployment.md) guide for the full walkthrough,
multi-replica guidance and network-isolation requirements.

## 3. Wire agentgateway

Either mount the `AgentgatewayPolicy` CRD (Kubernetes) or point a standalone
agentgateway at the sidecar with
[`examples/agentgateway.standalone.yaml`](https://github.com/soulwhisper/mcp-guardrails/blob/main/examples/agentgateway.standalone.yaml).
The policy maps `tools/call` to `Full` (request + response double gate),
`tools/list` / `prompts/get` / `resources/read` to `Response`, and
`ping` / `initialize` to `None`.

## 4. Verify

- **Smoke test** — `python3 tests/e2e_smoke.py` boots a live server in a
  subprocess (regex-only) and exercises the full ExtMcp gRPC surface:
  health check, `CheckRequest` allow + deny, `CheckResponse` deny,
  malformed-payload `INVALID`.
- **Real agentgateway e2e** — `AGENTGATEWAY_BIN=/path/to/agentgateway
  ./scripts/e2e_agentgateway.sh` stands up the full production topology and
  asserts pass / mutate / deny / fail-closed behaviour. See
  [End-to-end test](e2e.md).
- **Audit log** — every decision emits one JSON line on stdout; watch for
  `outcome="allow"` / `"mutated"` / `"deny"` lines as traffic flows. See
  [Auditing](operations/auditing.md).

## Where to next

- [Guardrails overview](guardrails/index.md) — the decision pipeline and
  every guardrail in detail.
- [Configuration](configuration.md) — the complete environment-variable
  reference.
- [Deployment](deployment.md) — Kubernetes manifests, agentgateway wiring,
  multi-replica notes.
