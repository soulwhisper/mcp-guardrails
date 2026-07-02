<!--
Thanks for contributing to extmcp-guardrails! Please fill in every section.
PRs that change deny / mutation behaviour or the wire contract need extra
scrutiny — flag those explicitly in the Guardrail-policy impact section.
-->

## Summary

<!-- One or two sentences describing what this PR does. -->

## Motivation

<!-- Why is this change needed? Link any issues (#NNN). -->

## Changes

<!-- Bullet list of behavioural changes. -->

-

## Risk

<!-- What could this break? What's the blast radius if it does?
Consider: fail-open vs fail-closed, hot-reload, audit log format,
wire-compat with agentgateway. -->

## Testing checklist

<!-- Tick every box. If something doesn't apply, explain why. -->

- [ ] `make lint` passes (ruff check guardrails server.py tests)
- [ ] `make test` passes (unit tests, regex-only mode — no ML deps required)
- [ ] `python tests/e2e_smoke.py` passes (live gRPC round-trip)
- [ ] `make proto` was re-run if `proto/ext_mcp.proto` changed (CI proto-check job will fail otherwise)
- [ ] New / changed deny patterns covered by a unit test in `tests/`
- [ ] No new dependency on the heavy ML stack (onnxruntime / transformers) in the unit-test path

## Guardrail-policy impact

<!-- This section is REQUIRED. Answer each. -->

- Does this change **deny** behaviour? (i.e. previously-allowed traffic now blocked)
  - [ ] No
  - [ ] Yes — explain:
- Does this change **mutation** behaviour? (i.e. requests/responses rewritten differently)
  - [ ] No
  - [ ] Yes — explain:
- Does this change the **fail-mode** (failClosed vs failOpen) or human-review mode?
  - [ ] No
  - [ ] Yes — explain:
- Does this change the **wire contract** (`proto/ext_mcp.proto`)?
  - [ ] No
  - [ ] Yes — wire-compat preserved (field numbers unchanged)
  - [ ] Yes — breaking change (requires agentgateway coordination + version bump)
- Does this require a **version bump**? (`pyproject.toml` + image tag + K8s manifest)
  - [ ] No
  - [ ] Yes — bumped to version:

## Checklist

<!-- Final gate before merge. -->

- [ ] **DCO signoff** — every commit is signed off (`git commit -s`) per the
      Developer Certificate of Origin.
- [ ] **Docs updated** — `README.md` / `docs/` / `examples/` updated if this
      changes user-facing behaviour, env vars, or the wire contract.
- [ ] **Changelog entry** — added a line to `CHANGELOG.md` (or noted why one
      isn't needed: e.g. test-only / refactor with no behaviour change).
- [ ] **No secrets / PII** in this PR, in code, logs, or rule packs.
- [ ] **Branch protection** — `ci-pass` (from ci.yml) and the `e2e` (pr.yml)
      status checks are green on this PR.
