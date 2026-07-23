# Development

Condensed from `CONTRIBUTING.md` — the repo file is the authoritative
version.

## Setup

Prerequisites: Python 3.10+ (3.11 is what CI and the image use), `pip`,
`make`, and `docker` (only for image targets).

```bash
git clone https://github.com/soulwhisper/mcp-guardrails.git
cd mcp-guardrails
make dev          # pip install -e ".[dev]" — pytest, ruff, grpcio-tools
make proto        # regenerate stubs (no-op if proto/ext_mcp.proto is unchanged)
make test         # unit suite, ~2s
make lint         # ruff check
```

The pure-Python policy core (models, aggregator, invariant engine, regex
scanner, servicer) runs **without** the ML stack. The dev install
deliberately does not pull in `onnxruntime` / `transformers`, and CI
hard-fails if either leaks back into the unit-test path — heavy imports must
stay lazy.

## Test pyramid

- **Unit suite** (`make test`, 320+ tests): aggregator fail-closed table;
  invariant engine (ordered subsequence matching, negate guards, LoopRule
  fingerprinting, RateLimitRule / AggregateRule time windows, dotted-path
  resolution); scanners (regex patterns, PromptGuard grey-zone thresholds,
  AgentAlignment pre-egress redaction, truncation, `extract_text` hidden
  Unicode preservation); engine (timeout/exception handling, second-stage
  gating, webhook notification); gRPC servicer (in-process round-trip + wire
  mapping); rule loader; graceful-shutdown ordering; `guardrail_ctl` CLI.
- **Property tests** (`tests/test_property.py`, hypothesis): `scan_windows`,
  `extract_text`, `_safe_json_loads`, `redact_value` (skips gracefully when
  hypothesis is absent).
- **Red-team capability baseline** (`tests/test_redteam.py`): base64
  injection, zero-width/confusables, markdown-image exfil, `### SYSTEM` case
  variants, head/mid/tail padding bypasses, window-flush sequences. Residual
  gaps are `xfail(strict=False)` with the residual documented.
- **E2E smoke** (`python3 tests/e2e_smoke.py`): boots a live server and
  exercises the ExtMcp gRPC surface.
- **Interop e2e** (`scripts/e2e_agentgateway.sh`): real agentgateway binary —
  see [End-to-end test](e2e.md).
- **Field / load tests** (`tests/field_test.py`, `tests/load_test.py`):
  require `onnxruntime` + the model cache.

`filterwarnings = ["error", ...]` in the pytest config — new warnings fail
the suite; fix the warning rather than suppressing it.

## Proto stub sync

`proto/ext_mcp.proto` is vendored from `agentgateway/agentgateway`. The
generated stubs (`ext_mcp_pb2.py`, `ext_mcp_pb2_grpc.py`) are **committed**
so CI and the image build do not need `grpcio-tools`. When you change the
proto, run `make proto` and commit all three files together — the CI
`proto-check` job regenerates and runs `git diff --exit-code`; drift fails
the build. Field **numbers** are the wire-compat surface; field names are
cosmetic.

## Release process (release-please)

Releases are automated via [Release Please](https://github.com/googleapis/release-please),
driven by [conventional commits](https://www.conventionalcommits.org/):

1. Every push to `main` updates a self-maintaining **release PR** (changelog
   + version bumps in `pyproject.toml`, `guardrails/__init__.py`,
   `CHANGELOG.md`).
2. Merging the release PR creates the tag + GitHub Release; the tag push
   triggers `docker-publish.yml` (multi-arch image).
3. Commit prefixes map to semver: `fix:`/`perf:` patch, `feat:` minor,
   `feat!:` major; `docs:` / `ci:` / `test:` / `chore:` / `build:` /
   `refactor:` produce no version bump.
4. Image tags: `x.y.z` is immutable (never re-point); `latest` and `x.y`
   float. A `RELEASE_PLEASE_TOKEN` PAT (classic, `repo` scope) is required
   for the tag push to trigger downstream workflows.

## Adding things

- **A scanner** — implement the `Scanner` protocol (`async scan(content, role, *, context) -> ScanResult`), wrap sync ML inference in `asyncio.to_thread`, register it in `GuardrailEngine.from_config` behind an `enable_*` flag with an `ImportError` fallback, add an env knob in `config.py`, document it in the README/config tables, and cover allow/block/review + timeout/exception paths with tests.
- **An invariant rule** — add to `guardrails/rules/default.py` (ships everywhere) or a custom pack; see [Invariant rules](guardrails/invariant-rules.md). Validate with `guardrail_ctl rules lint`.

## PR checklist (short form)

- `make lint` clean, `make test` green.
- `python3 tests/e2e_smoke.py` green if you touched servicer / engine /
  config / server entrypoint.
- `make proto` re-run and stubs committed if you touched the proto.
- New deny pattern / scanner / rule → a test asserting the deny fires.
- New env var → read in `config.py` **and** documented in the env table.
- DCO signoff (`git commit -s`) and conventional-commit messages.
- Security-sensitive paths (`aggregator.py`, `engine.py`, `invariant.py`,
  `scanners.py`, `rules/`, the proto) get extra review — call out the
  security impact in the PR description.
