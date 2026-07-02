# Contributing to ExtMcp Guardrail

Thanks for your interest in improving ExtMcp Guardrail. This document is the
short, practical guide to the dev workflow. The longer rationale for every
design choice lives in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Code of conduct

Be excellent to each other. Security-sensitive code requires extra care and
extra review; disagreeing about threat models is fine, doing so rudely is not.

## Prerequisites

- Python 3.10+ (3.11 is what CI and the container image use)
- `pip`
- `make`
- `docker` (only for `make docker` / `make docker-run`)
- `grpcio-tools` is pulled in by `make dev` for `make proto` — you do not need
  to install it globally

The pure-Python policy core (models, aggregator, invariant engine, regex
scanner, servicer) runs **without** the ML stack. The dev install
(`pip install -e ".[dev]"`) deliberately does **not** pull in `onnxruntime`
or `transformers`. The unit tests must pass in this minimal
environment; that is enforced by CI (the `test` job hard-fails if either of those
packages leaks back in).

## Clone and first run

```bash
git clone https://github.com/soulwhisper/mcp-guardrails.git
cd mcp-guardrails
make dev          # pip install -e ".[dev]" — pytest, ruff, grpcio-tools
make proto        # regenerate stubs (no-op if proto/ext_mcp.proto is unchanged)
make test         # 72 unit tests, ~0.3s
make lint         # ruff check
```

If `make test` fails after a fresh clone, do not commit anything — something
in your environment is wrong (most commonly: a stale virtualenv or a Python
version mismatch). Open an issue.

## Regenerating the proto stubs

The generated files `proto/ext_mcp_pb2.py` and `proto/ext_mcp_pb2_grpc.py` are
**committed** so that:

- CI does not need `grpcio-tools` in the runtime image.
- The container image build does not need `grpcio-tools`.
- A fresh `git clone && make test` passes without a proto regen step.

When you change `proto/ext_mcp.proto`:

```bash
make proto                            # regenerates the two stubs
git add proto/ext_mcp.proto proto/ext_mcp_pb2.py proto/ext_mcp_pb2_grpc.py
git commit -m "proto: <change>"
```

**The CI `proto-check` job enforces this.** It regenerates the stubs from
`proto/ext_mcp.proto` and runs `git diff --exit-code` on the two generated
files. If the committed stubs drift from the proto source, the job fails and
the PR cannot merge. There is no way to land a proto change without also
landing the regenerated stubs.

If you only rename a field (without touching field numbers), the generated
stubs will diff but the wire format is unchanged — still commit the regen.
Field **numbers** are the wire-compat surface; field **names** are cosmetic
(this is why the proto's oneof member is named `allowed` rather than `pass` —
see the field-naming note in [`README.md`](README.md)).

## Lint and test

```bash
make lint          # ruff check guardrails server.py tests
make format        # ruff format + ruff check --fix
make test          # pytest tests/ -q
make test-cov      # pytest with --cov=guardrails --cov=server
```

Ruff config lives in `pyproject.toml` (`[tool.ruff]`). Line length is 100,
target is py310. The generated stubs are excluded from lint.

The pytest config (`[tool.pytest.ini_options]`) sets `asyncio_mode = "auto"`
and `filterwarnings = ["error", ...]`. New warnings will fail the suite —
fix the warning rather than suppressing it. The exception is grpc
deprecation warnings, which are ignored.

The 72 unit tests cover:

- `tests/test_aggregator.py` — fail-closed table, HUMAN_REVIEW resolution,
  mutation passthrough.
- `tests/test_invariant.py` — ordered subsequence matching, LoopRule
  fingerprinting, dotted-path resolution, hot-reload.
- `tests/test_scanners.py` — regex patterns, truncation, `extract_text`
  hidden-Unicode preservation (the `ensure_ascii=False` regression).
- `tests/test_engine.py` — timeout / exception handling per failure mode,
  second-stage gating on HUMAN_REVIEW, invariant trace serialisation.
- `tests/test_servicer.py` — in-process gRPC round-trip + wire mapping
  (allowed / mutated / error oneof, INVALID_ARGUMENT on malformed JSON).

## Adding a scanner

The scanner interface is the `Scanner` Protocol in
[`guardrails/scanners.py`](guardrails/scanners.py):

```python
@runtime_checkable
class Scanner(Protocol):
    name: str

    async def scan(
        self,
        content: str,
        role: str,
        *,
        context: Optional[Mapping[str, Any]] = None,
    ) -> ScanResult: ...
```

To add a scanner:

1. **Subclass / implement the `Scanner` protocol** in a new module under
   `guardrails/scanners/` (or inline in `guardrails/scanners.py` for very
   small ones). Implementations **must** be safe to call concurrently. If
   your scanner does synchronous ML inference, wrap it in
   `asyncio.to_thread` so the asyncio event loop is never blocked (see
   `OnnxPromptGuardScanner.scan` for the pattern).
2. **Return a `ScanResult`** with one of `ScanOutcome.ALLOW`, `BLOCK`, or
   `HUMAN_REVIEW`. The aggregator handles the rest.
3. **Register it** in `GuardrailEngine.from_config`
   ([`guardrails/engine.py`](guardrails/engine.py)) — add it to
   `request_scanners` and/or `response_scanners` behind the appropriate
   `config.enable_*` flag, with a `try/except ImportError` fallback if it
   pulls in an optional dependency.
4. **Add an env-var knob** in `guardrails/config.py` (default `False` for any
   scanner that loads a model; `True` only for zero-dep deterministic
   scanners). Update the env-var table in [`README.md`](README.md) — every
   knob in `config.py` is documented there by contract.
5. **Add unit tests** under `tests/test_scanners.py` (or a new
   `tests/test_scanner_<name>.py`). Cover the allow / block / review paths
   and the timeout / exception path.

Heavy ML imports (`onnxruntime`, `transformers`) must be **lazy**
(inside `from_default` / `from_env`, never at module top level) so the unit
tests keep passing in the ML-free dev environment.

## Adding an Invariant rule

Rules live in a rule pack — a Python module exposing a module-level `RULES`
list. The bundled pack is [`guardrails/rules/default.py`](guardrails/rules/default.py);
the richer example pack is [`examples/rules.policy`](examples/rules.policy).

To add a rule:

1. **Decide the rule shape.**
   - `ToxicFlowRule` — an ordered subsequence of tool calls within the
     trace window (steps need not be contiguous). Use for
     "X then Y" exfiltration / escalation patterns.
   - `LoopRule` — fires when the same `(tool, args)` fingerprint repeats
     `threshold` times. Use for prompt-injection retry storms.
   - Custom rule — any object exposing `name: str` and
     `match(trace) -> Optional[str]`. The loader duck-types this.
2. **Pick the pack.** Add to `guardrails/rules/default.py` for a rule every
   deployment should ship with; add to a custom pack (e.g.
   `examples/rules.policy`, or a ConfigMap-mounted pack in K8s) for
   deployment-specific policy.
3. **Use matchers wisely.**
   - Tool matchers: exact string (safest), regex string (heuristic — any
     string containing regex meta-characters is compiled and `.search()`ed),
     compiled `re.Pattern`, or callable `(tool_name) -> bool`.
   - Arg value matchers: same heuristic, plus callables for arbitrary
     predicates.
   - Dotted paths: `"to.address"`, `"recipients.0.email"` — integer segments
     are list indices.
4. **Order rules by priority** — `InvariantEngine.evaluate` is first-match
   wins. Put high-confidence / high-severity rules first.
5. **Test it.** Add a case to `tests/test_invariant.py` that builds a fake
   trace and asserts the rule fires (and that a non-matching trace does not).

Rule packs are hot-reloadable at runtime via `SIGHUP` — see
[`ARCHITECTURE.md`](ARCHITECTURE.md#hot-reload) for the swap mechanics.

## Pull request checklist

Before opening a PR:

- [ ] `make lint` clean.
- [ ] `make test` green (72+ tests).
- [ ] `python3 tests/e2e_smoke.py` green if you touched the servicer, engine,
      config, or server entrypoint.
- [ ] `make proto` re-run and stubs committed if you touched
      `proto/ext_mcp.proto` (the `proto-check` CI job enforces this).
- [ ] If you added a deny pattern / scanner / rule, add a unit test that
      asserts the deny actually fires.
- [ ] If you added an env var, it is read in `guardrails/config.py` (or
      `guardrails/rules/__init__.py` for the two `INVARIANT_RULES_*` vars)
      **and** documented in the README env-var table.
- [ ] No new ML-stack dep (`onnxruntime` / `transformers`) in the
      unit-test path. Heavy imports stay lazy.
- [ ] DCO signoff on every commit (see below).
- [ ] Commit messages follow [conventional commits](https://www.conventionalcommits.org/)
      (`fix:`, `feat:`, `perf:`, `chore:`, etc.) — Release Please derives the
      semver bump and changelog entry from the commit message.

## DCO / signoff

We use the Developer Certificate of Origin, same mechanism the Linux kernel
uses. Every commit must be signed off:

```bash
git commit -s -m "feat: add foo scanner"
```

This adds a `Signed-off-by: Your Name <your.email@example.com>` trailer that
attests you have the right to contribute the change under the project's
license (Apache-2.0). `git rebase --signoff` can retroactively add the
trailer to a branch.

## Release process

Releases are automated via [Release Please](https://github.com/googleapis/release-please)
and driven by [conventional commits](https://www.conventionalcommits.org/).

### Repo setup (one-time, admin)

Release Please needs permission to create pull requests. In the repository
Settings → Actions → General:

- **Workflow permissions:** "Read and write permissions"
- **☑ Allow GitHub Actions to create and approve pull requests**

Without this, Release Please will fail with
`GitHub Actions is not permitted to create or approve pull requests.`
It successfully creates the branch and commit, but cannot open the PR.

### How it works

1. **Every push to `main`** triggers the `release-please.yml` workflow.
   Release Please scans commits since the last release and maintains a
   **release PR** that accumulates changelog entries and version bumps.

2. **The release PR** updates `pyproject.toml`, `guardrails/__init__.py`,
   and `CHANGELOG.md` automatically. It stays open and self-updates as
   new commits land on `main` — review it for changelog prose quality
   before merging.

3. **Merge the release PR** → Release Please creates the Git tag and
   GitHub Release with the curated `CHANGELOG.md` section as the body.
   The tag push triggers `docker-publish.yml`, which builds and pushes
   the multi-arch container image.

### Commit conventions

Every commit on `main` MUST follow conventional commits — Release Please
uses the prefix to determine the semver bump:

| Prefix     | Bump   | Example                                      |
| ---------- | ------ | -------------------------------------------- |
| `fix:`     | patch  | `fix: handle empty HF_ENDPOINT`              |
| `feat:`    | minor  | `feat: add per-scanner OTel child spans`     |
| `feat!:`   | major  | `feat!: drop Python 3.10 support`            |
| `perf:`    | patch  | `perf: parallelize scanner execution`        |
| `refactor:`| —      | no user-visible entry (included in release)  |
| `chore:`   | —      | no user-visible entry (included in release)  |
| `docs:`    | —      | no user-visible entry                        |
| `ci:`      | —      | no user-visible entry                        |
| `test:`    | —      | no user-visible entry                        |
| `build:`   | —      | no user-visible entry                        |

Breaking changes: append `!` after the type (e.g. `feat!:`) or include
`BREAKING CHANGE:` in the commit body.

### Token setup (PAT)

Release Please creates the Git tag and GitHub Release. For the tag push
to trigger the `docker-publish.yml` workflow, the action needs a
**Personal Access Token (classic)** with `repo` scope — the default
`GITHUB_TOKEN` suppresses downstream workflow triggers.

1. Create a [PAT (classic)](https://github.com/settings/tokens) with
   `repo` scope.
2. Add it as a repository secret named `RELEASE_PLEASE_TOKEN`
   (Settings → Secrets and variables → Actions → New repository secret).

Without a PAT, the release will still be created but `docker-publish`
won't fire automatically — trigger it manually with:
```bash
gh workflow run docker-publish.yml --ref <tag>
```

### Image tags: immutable vs floating

- **`x.y.z` (e.g. `0.3.0`) is immutable.** Never force-push a version tag to a
  different commit — consumers pin `0.3.0` expecting the exact image. To ship a
  change, cut a **new** tag (`0.3.1`).
- **`latest` and `x.y` (e.g. `0.3`) float** by design — they move to the newest
  tag on the next release. Don't manually re-point them.
- **Rebuild the *same* tag** (e.g. a build that failed and you want to retry the
  same commit) without changing it:
  ```bash
  gh workflow run docker-publish.yml --ref 0.3.0
  ```
  (`docker-publish.yml` has a `workflow_dispatch` trigger; it rebuilds the
  selected ref and re-pushes the same image tags.)

## Security-sensitive paths

The following paths get extra scrutiny in review (see
[`.github/CODEOWNERS`](.github/CODEOWNERS)):

- `guardrails/aggregator.py` — the fail-closed table.
- `guardrails/engine.py` — the orchestrator and timeout / exception handling.
- `guardrails/invariant.py` — the rule engine and trace semantics.
- `guardrails/scanners.py` — the scanner implementations and `extract_text`.
- `guardrails/rules/` — the bundled and default rule packs.
- `proto/ext_mcp.proto` — the wire contract with agentgateway.

Changes to these files should call out the security impact explicitly in the
PR description. If you are changing fail-closed behaviour, you are changing
the security posture of every deployment that pulls the image — say so.

## Reporting a security vulnerability

Do **not** open a public GitHub issue for security vulnerabilities. Email the
maintainer privately at `security@soulwhisper.dev` with a description and, if
possible, a repro. We will acknowledge within 72 hours and aim for a fix or
mitigation within 30 days. Disclosure happens after a fix is released.

## Questions

Open a GitHub Discussion for usage questions; open a GitHub Issue for bugs
and concrete feature requests (use the bug-report / feature-request issue
forms in `.github/ISSUE_TEMPLATE/`).
