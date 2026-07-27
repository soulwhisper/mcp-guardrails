# Tool ACL

A coarse, tool-level access-control gate applied on the **request side,
before any content scanner runs** (`guardrails/engine.py`,
`_tool_acl_violation`). A violation short-circuits to a `BLOCK` from the
`tool_acl` scanner — the payload is never scanned and the call is never
recorded into the Invariant trace.

## Semantics

| Env var | Default | Meaning |
| --- | --- | --- |
| `ALLOW_TOOLS` | _(empty)_ | Comma-separated tool names; `prefix/*` wildcards match any tool under the prefix. When non-empty it acts as a **whitelist**: any tool not matching it is denied. |
| `DENY_TOOLS` | _(empty)_ | Comma-separated tool names with the same wildcard syntax. **DENY wins over ALLOW.** |

- Both empty → every tool is allowed (the default; no ACL).
- A tool matching both lists is **denied**.
- A denial is a `BLOCK` result (`scanner="tool_acl"`, score 1.0) and follows
  the standard fail-closed path: `error` oneof, JSON-RPC `-32001`, audit line
  with the generalised wire reason.

## Examples

```bash
# Only filesystem tools and ping are usable; everything else denied:
-e ALLOW_TOOLS="fs/*,ping"

# Block specific dangerous tools inside an otherwise-open deployment:
-e DENY_TOOLS="fs/write,admin/*"

# Whitelist with an explicit carve-out (DENY wins):
-e ALLOW_TOOLS="fs/*" -e DENY_TOOLS="fs/delete"
```

## When to use it

The ACL is a blunt instrument for policy that content scanning cannot
express: "this agent must never call `admin/*`", "read-only filesystem
access". For finer-grained, behaviour-based control (sequences, rates,
budgets), use [Invariant rules](invariant-rules.md) instead.
