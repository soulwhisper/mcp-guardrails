# Health & shutdown

The sidecar exposes a standard `grpc.health.v1` service (used by the K8s
readiness probe) with two watch names: `""` and `ExtMcp`.

## Warmup gating

The health service starts `NOT_SERVING`. The engine warms up before accepting
traffic (`GuardrailEngine.awarm()` — the PromptGuard-2 model load dominates,
taking several seconds on cold start). Only when warmup completes does a
background watchdog (2s poll) flip health to `SERVING`. This keeps the Pod
out of Service endpoints during cold start, so no traffic reaches a
half-initialised sidecar.

## Runtime degradation (A-P0-4)

The engine tracks a sliding window of scanner outcomes:

- over the last `UNHEALTHY_SCANNER_WINDOW` (default 100) scan invocations,
- once at least `UNHEALTHY_SCANNER_MIN_SAMPLES` (default 20) were seen,
- if the error/timeout rate exceeds `UNHEALTHY_SCANNER_ERROR_RATE`
  (default 0.5),

the engine reports unhealthy and health flips back to `NOT_SERVING` —
recovering automatically once the rate drops below the threshold. Degradation
is tracked **regardless of `FAILURE_MODE`**: failOpen still surfaces scanner
problems via health and metrics. The min-samples floor avoids flapping on the
first few calls.

## Graceful shutdown (A-P2-4)

On SIGTERM/SIGINT the shutdown is ordered (`server.py`):

1. Health flips to `NOT_SERVING` **immediately**, so the next readiness probe
   takes the Pod out of Service endpoints and the dataplane stops routing
   new exchanges to this replica.
2. The health watchdog is cancelled (so a scanner error-rate recovery cannot
   flip health back mid-drain).
3. Wait `SHUTDOWN_DRAIN_S` seconds (default 5.0) for readiness propagation
   (kubelet probe interval + endpoint controller + dataplane convergence).
   In-flight exchanges keep running. `0` skips the wait.
4. Drain with `server.stop(grace=5s)`.

## SIGHUP rule reload

Sending `SIGHUP` (e.g. `kill -HUP 1` inside the container) hot-reloads the
Invariant rule pack from `INVARIANT_RULES_PATH` without dropping the server.
The swap is atomic; in-flight evaluations complete on the old rule tuple.
Both successful and failed reloads land in the audit log as
`{"event": "rules_reload", "ok": …}` lines and the
`mcp.guardrails.rules_reload{result}` counter — a failed reload keeps the
previous pack active.
