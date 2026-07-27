# Invariant rules (cross-call guardrails)

The `InvariantEngine` (`guardrails/invariant.py`) is the **rule layer**:
deterministic, stateful pattern matching over the rolling window of MCP tool
calls — the complement to the content scanners. It runs on the request side
only: every `tools/call` with a non-empty tool name is recorded
`(tool, args, ts)` into a bounded sliding window *before* evaluation, so the
current call participates in matching. First-match wins; rule order is
priority order. A hit produces a `BLOCK` result named `invariant:<rule>`.

## Trace windows and trace keys

- **Window size** — `INVARIANT_WINDOW` (default 256) entries per trace,
  covering long multi-step agent plans. Memory bound:
  `window × INVARIANT_ARGS_MAX_BYTES × INVARIANT_MAX_TRACES`
  (256 × 4KiB × 1024 ≈ 1GiB theoretical worst case; realistic entries are far
  below the cap, so the practical footprint is tens of MiB).
- **Per-key isolation** — traces are keyed by route name / first service
  name, extendable per session via `INVARIANT_TRACE_KEY_HEADERS` (e.g.
  `x-session-id` → key `route|header:value`). One noisy tenant cannot poison
  another tenant's window, and interleaved sessions cannot assemble a
  cross-session toxic flow. Key count is LRU-bounded by
  `INVARIANT_MAX_TRACES` (default 1024).
- **Args cap** — stored args copies are size-bounded
  (`INVARIANT_ARGS_MAX_BYTES`, default 4KiB) with structure-preserving
  truncation, so matchers keep resolving dotted paths on retained prefixes.
  The loop fingerprint is computed from the **full** args before truncation,
  so loop detection is unaffected.

!!! warning "Multi-replica deployments"
    Trace windows live in sidecar memory. A toxic flow whose calls land on
    **different replicas** cannot be detected. For multi-replica deployments,
    have agentgateway inject a session header, set
    `INVARIANT_TRACE_KEY_HEADERS` accordingly, and configure sticky/session-
    affinity routing on the agentgateway side (the deployer's responsibility).

## Rule types

### ToxicFlowRule — ordered subsequence

Fires when all steps match **in order** within the window. Steps need not be
contiguous — intervening calls are allowed, modelling real agent behaviour
where a dangerous pattern is spread across intermediate steps.

```python
ToxicFlowRule(
    name="inbox-to-external-email",
    description="Read an inbox then send email to an external recipient",
    steps=[
        FlowStep(tool="inbox_read"),
        FlowStep(tool="email_send", args={"to": _EXTERNAL_EMAIL}),
    ],
)
```

**Negate guards.** A step with `negate=True` never advances the sequence;
while *armed* (between the previously matched positive step and the next
positive step) any trace entry matching it **voids** the in-progress match —
including parked sticky progress — and matching restarts from step 0. Use for
"A then C with no B between":

```python
steps=[
    FlowStep(tool="inbox_read"),
    FlowStep(tool="email_approve", negate=True),   # approval voids the flow
    FlowStep(tool="email_send", args={"to": _EXTERNAL_EMAIL}),
]
```

`inbox_read → email_send` fires; `inbox_read → email_approve → email_send`
does not. Negate steps at the start of a rule guard from the beginning of
the window; trailing negate steps stay armed until the rule completes.

**Sticky progress (S-H4).** When a rule matches a *prefix* of its steps, the
progress is parked in a TTL-bounded sticky map (`INVARIANT_STICKY_TTL_S`,
default 600s) so a flow whose early steps slide out of the rolling window
still completes. Only new advancement refreshes the TTL; a negate void drops
the parked progress too. The sticky map is LRU-bounded like the trace map.

### LoopRule — fingerprint repetition

Fires when the same `(tool, sorted_args_json)` fingerprint repeats
`threshold` times (≥2) in the window. A parameterised search (args differ
each call) does **not** fire — only an identical retry loop does. Models the
prompt-injection "retry storm": a compromised agent hammering the same denied
tool hoping a guardrail hiccups.

### RateLimitRule — sliding time-window rate

Fires when one tool matching `tool` is called more than `max_calls` times
within the trailing `window_s` seconds (per the `ts` the engine stamps on
every recorded call). Counting is **per concrete tool name** — the wildcard
`"*"` covers every tool without pooling them into one shared budget. Catches
volumetric abuse with *varying* args (enumeration / spray) that LoopRule
cannot see. The window is recomputed from timestamps on every evaluation, so
entries slide out exactly.

### AggregateRule — sliding time-window budget

Sums `cast(args[field])` (dotted path, default `float`) over matching calls
within the trailing `window_s` and fires when the total exceeds `max_total`.
Use for cumulative budgets a per-call rule cannot express — bytes
exfiltrated, recipients contacted, rows read — where every single call stays
under the per-call limits. Entries with a missing/uncastable field contribute
0. Like RateLimitRule, the window is recomputed per evaluation (no persistent
accumulator to drift).

## Default rule pack

`guardrails/rules/default.py` — a conservative, homelab-flavoured starter
pack targeting the highest-leverage exfiltration / privilege-escalation
patterns:

| Rule | Type | Sequence / parameters | Intent |
| --- | --- | --- | --- |
| `inbox-to-external-email` | ToxicFlowRule | `inbox_read` → `email_send` where `to` is outside the internal suffixes (`internal.local`, `corp.local`, `example.org`) | Data exfiltration via an email tool |
| `secret-read-then-exfil` | ToxicFlowRule | `(secret\|vault\|kms)_?(read\|get).*` → `(http\|curl\|fetch\|webhook).*post` to a non-internal URL | Read a secret, push it to an external HTTP endpoint |
| `shell-read-then-k8s-apply` | ToxicFlowRule | `(shell\|bash\|exec\|terminal).*` → `(kubernetes\|k8s\|kubectl).*apply` whose manifest contains `cluster-admin` / `privileged` / `hostPath` / `hostPID` | Privilege escalation into the cluster |
| `denied-tool-retry-loop` | LoopRule | threshold 3 | Same tool+args repeated 3+ times in the window (injection retry loop) |
| `per-tool-rate-limit` | RateLimitRule | `*`, 30 calls / 60s | Volumetric backstop — catches enumeration/spray with varying args while normal agent exploration stays well under the line |

## The example pack

[`examples/rules.policy`](https://github.com/soulwhisper/mcp-guardrails/blob/main/examples/rules.policy)
is a richer, well-commented pack of nine rules demonstrating every matcher
form: inbox→external email, secret-read→HTTP exfil, shell→privileged k8s
apply, db-dump→external upload, file-read→webhook exfil, an unapproved-send
flow using a `negate` guard, a per-tool `RateLimitRule`, an hourly read-volume
`AggregateRule` (10MiB/h), and a `LoopRule` retry storm. Load it with:

```bash
-v $(pwd)/examples/rules.policy:/etc/guardrails/rules.policy:ro
-e INVARIANT_RULES_PATH=/etc/guardrails/rules.policy
```

## Writing custom rules

A rule pack is a plain Python module exposing a module-level `RULES = [...]`
list. Resolution order (first non-empty wins):

1. `INVARIANT_RULES_PATH=/etc/guardrails/rules.policy` — a file on disk.
   **Hot-reloadable via `SIGHUP`** (`kill -HUP 1` in the container): the
   `RulePack` swaps the active rule tuple atomically behind a lock; in-flight
   evaluations see the old tuple to completion.
2. `INVARIANT_RULES_MODULE=my_org.rules.production` — a dotted import path.
3. `guardrails.rules.default` — the bundled pack.

**Matcher syntax:**

- *Tool matchers* — exact string (safest); regex string (any string
  containing `^$.*+?[]()|` meta-characters is compiled and `.search()`ed,
  except the literal `"*"`); compiled `re.Pattern`; or callable
  `(tool_name) -> bool`.
- *Arg value matchers* — same regex-vs-literal heuristic (literal strings use
  `==`), plus callables for arbitrary predicates, and literal
  `int` / `float` / `bool` equality.
- *Dotted paths* — `"to.address"`, `"recipients.0.email"`; integer segments
  are list indices. Missing segments resolve to `None` (no match).

Custom rule objects only need a `name: str` and
`match(trace) -> Optional[str]` — the loader duck-types it.

**Validate before rollout** with the operator CLI:
`guardrail_ctl rules lint <pack>` checks structure, thresholds and negate
placement, and dry-runs the pack against built-in sample traces (non-zero
exit on an invalid pack — suitable for gating a GitOps pipeline).

## Rule observability

Every rule hit lands in the [audit log](../operations/auditing.md) with
scanner name `invariant:<rule>`, and increments
`mcp.guardrails.invariant_hits{rule=…}`. Rule-pack reloads (SIGHUP) emit
`{"event": "rules_reload", "ok": …}` audit lines and the
`mcp.guardrails.rules_reload{result}` counter — a failed reload keeps the
previous pack active.
