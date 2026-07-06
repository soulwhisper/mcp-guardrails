# Changelog

All notable changes to ExtMcp Guardrail are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.3](https://github.com/soulwhisper/mcp-guardrails/compare/v0.3.2...v0.3.3) (2026-07-04)


### Features

* **container:** update image docker/dockerfile ( 1.7 → 1.25 ) ([#38](https://github.com/soulwhisper/mcp-guardrails/issues/38)) ([ad2f0d6](https://github.com/soulwhisper/mcp-guardrails/commit/ad2f0d6bdd0ce70c71f944bbb268363468294948))
* **github-action:** update python ([#39](https://github.com/soulwhisper/mcp-guardrails/issues/39)) ([710ec0f](https://github.com/soulwhisper/mcp-guardrails/commit/710ec0fc2af598129c9a50f87bd836c6e9068a12))


### Bug Fixes

* **ci:** make chore commits visible to release-please ([#35](https://github.com/soulwhisper/mcp-guardrails/issues/35)) ([a1d9b41](https://github.com/soulwhisper/mcp-guardrails/commit/a1d9b41c47af154ef7c555427096866f7cd6d728))


### Continuous Integration

* **github-action:** pin dependencies ([#37](https://github.com/soulwhisper/mcp-guardrails/issues/37)) ([50687f2](https://github.com/soulwhisper/mcp-guardrails/commit/50687f2ef5f2f8978345035a539ae5eca84b0e8b))
* **github-action:** pin dependencies ([#42](https://github.com/soulwhisper/mcp-guardrails/issues/42)) ([e5edade](https://github.com/soulwhisper/mcp-guardrails/commit/e5edade6e23d131117fddce703be55fc68f9f764))
* **github-action:** update docker/login-action digest ( c99871d → af1e73f ) ([#43](https://github.com/soulwhisper/mcp-guardrails/issues/43)) ([3eb30b8](https://github.com/soulwhisper/mcp-guardrails/commit/3eb30b83ecce276ef935818d448e1fe427253d45))


### Chores

* **ci:** optimize workflow triggers to reduce duplicate runs ([#34](https://github.com/soulwhisper/mcp-guardrails/issues/34)) ([207543c](https://github.com/soulwhisper/mcp-guardrails/commit/207543c673e69c8b4dbbae03df69df56a7560730))
* **ci:** update github actions ([#41](https://github.com/soulwhisper/mcp-guardrails/issues/41)) ([3fee6d0](https://github.com/soulwhisper/mcp-guardrails/commit/3fee6d0efae53d7fbad2a09882220ee148addb0c))

## [0.3.2](https://github.com/soulwhisper/mcp-guardrails/compare/0.3.1...v0.3.2) (2026-07-02)


### Features

* **ci:** automate releases with Release Please + update docs for 0.3.1 ([#28](https://github.com/soulwhisper/mcp-guardrails/issues/28)) ([e697df2](https://github.com/soulwhisper/mcp-guardrails/commit/e697df2bee64547c9d9c260b905fed3335dad2e4))


### Bug Fixes

* **ci:** document required repo setting for Release Please PR creation ([#29](https://github.com/soulwhisper/mcp-guardrails/issues/29)) ([6bd0ea2](https://github.com/soulwhisper/mcp-guardrails/commit/6bd0ea2468e9dd5f6209d0f820456701f752cc3b))
* **ci:** use GitHub App token in release-please to trigger downstream workflows ([#32](https://github.com/soulwhisper/mcp-guardrails/issues/32)) ([175791c](https://github.com/soulwhisper/mcp-guardrails/commit/175791c976a3f539de863fea994f5b95cbf2f204))


### Documentation

* add Llama 4 license notice, fix stale README/K8s refs ([#31](https://github.com/soulwhisper/mcp-guardrails/issues/31)) ([cdd109e](https://github.com/soulwhisper/mcp-guardrails/commit/cdd109e7d8382073bf58e65a513cd72479afa008))

## [0.3.0] - 2026-07-02

### Fixed

- **ONNX PromptGuard classification was inverted for the 2-class model.**
  The `gravitee-io/Llama-Prompt-Guard-2-86M-onnx` export produces 2 logits
  `[benign, malicious]`, not the 3-class `[safe, injection, jailbreak]` that
  the original Meta model outputs.  The code took `probs[0, 0]` (benign) as
  the block score for non-3-class models, which inverted every decision —
  clean text was blocked and prompt-injection text was allowed.  Fixed to
  always take `probs[0, -1]` (the last class is always the "should-block"
  dimension regardless of arity).  Found during field testing.

- **Added `sk-*` LLM API key detection.** The regex scanner now catches
  OpenAI (`sk-...`, `sk-proj-...`, `sk-svcacct-...`) and Anthropic
  (`sk-ant-api03-...`) API keys with the new `llm_api_key` pattern.
  Previously only AWS/GitHub/GitLab/Slack token shapes were matched.

- **Added 7 new regex patterns** from production guardrails config
  (home-ops agentgateway policy), ignoring Chinese-language rules:
  `google_api_key` (`AIza...`), `aws_temp_key` (`ASIA...` AWS STS),
  `jwt` (`eyJ...`), `format_injection` (`[SYSTEM]`, `<|im_start|>`,
  `<|endoftext|>`, `### system`, etc.), `connection_string` (URIs with
  embedded credentials), and `key_value_credential` (`password=...`,
  `token: ...`, `bearer=...`).  The format-injection patterns are a
  deterministic backstop for markers the ONNX PromptGuard model may
  not recognise (e.g. ChatML tokens on a Llama-based tokenizer).

### Added

- `tests/field_test.py` — comprehensive functional test exercising the full
  scanner pipeline (regex + ONNX PromptGuard + invariant engine) with a live
  server subprocess.  Covers request scanning, response indirect-injection
  defense, loop detection, and concurrency.

- `tests/load_test.py` — standalone latency-and-throughput benchmark.
  Measures per-request added latency (P50/P90/P99) and throughput under
  varying concurrency against a real ONNX PromptGuard server.

## [0.3.1] - 2026-07-02

### Changed

- **Scanners run in parallel** via `asyncio.gather` instead of sequentially.
  Each scanner gets its own deadline and failure-mode handling; a slow or
  failing scanner never blocks the others. Typical 2-scanner config (regex +
  ONNX PromptGuard) sees ~30-50% latency reduction per check.

- **OpenTelemetry SDK promoted to core dependency** (`opentelemetry-sdk` +
  `opentelemetry-exporter-otlp`). OTel gracefully degrades to audit-log-only
  when no OTLP endpoint is configured — zero overhead for users who don't
  export traces.

- **Per-scanner child spans** for latency breakdown. Each scanner invocation
  emits a child OTel span carrying `scanner`, `role`, `outcome`, and
  `duration_ms`. Audit log now includes `scanner.regex` and
  `scanner.onnx-promptguard` events alongside the parent `guardrail.*` span.

- **CI refresh:** bump `docker/build-push-action` v5 → v6, `codecov` v4 → v5.
  Drop redundant `pip install` steps in CI/PR workflows (grpcio et al. now
  resolved by `-e ".[dev]"`). Replace stale `llamafirewall` guard with
  `onnxruntime`. Fix `protobuf>=4.25,<6` constraint conflict in `pr.yml`.

### Fixed

- **Field-test workflow `HF_ENDPOINT` bug** — same empty-env-var issue that
  broke the Docker build in v0.2.1. Unset empty `HF_ENDPOINT` before
  `huggingface_hub` calls. Also removed `HF_ENDPOINT` mirror overrides
  project-wide (Dockerfile, docker-publish.yml, field-test.yml) — the default
  `huggingface.co` endpoint works everywhere.

- **Field-test scripts made portable.** Replaced hardcoded NixOS paths with
  auto-detection of the ONNX model snapshot directory (checks
  `LF_ONNX_LOCAL_DIR` env var → HF cache scan → NixOS fallback).

- **HF Hub rate-limiting.** All `snapshot_download()` calls now authenticate
  via `HF_TOKEN` (field-test workflow, Docker build). The field-test download
  step was failing with HTTP 429 from shared GHA IPs.

- **Docker build: BuildKit `env=` not supported.** GHA ships BuildKit v0.30.0
  which doesn't support the `env=HF_TOKEN` shorthand on `--mount=type=secret`
  (requires ≥ v0.31). Replaced with manual `export HF_TOKEN=$(cat ...)`.

### Added

- **18 OTel unit tests** (`tests/test_otel.py`): child-span emission, outcome
  tracking, degradated operation when OTel endpoint is absent, `AuditSink`
  resilience. Field test gains audit-trail assertions (4 new checks). Full
  suite: 108 tests (was 90).

- **K8s deployment docs:** OTLP endpoint configuration documented in
  `deployment.yaml` and `configmap.yaml` with cluster-internal collector
  endpoint and graceful degradation notes.

- **Release Please** (`.github/workflows/release-please.yml`, `release-please-config.json`,
  `.release-please-manifest.json`): automated releases from conventional commits.
  Release PR auto-updates `pyproject.toml`, `__version__`, and `CHANGELOG.md`.
  Merge → tag + GitHub Release + docker-publish. Replaces the manual release
  workflow (`CONTRIBUTING.md` updated).

## [0.2.1] - 2026-07-02

### Fixed

- **Docker build broke** with `httpx.UnsupportedProtocol: Request URL is
missing an 'http://' or 'https://' protocol`. The empty `HF_ENDPOINT`
  build-arg (the default when no mirror is configured) leaked into the build
  env as `HF_ENDPOINT=""`, which `huggingface_hub` picked up instead of its
  built-in default endpoint. The models stage now `unset`s `HF_ENDPOINT` when
  empty so the hub falls back to `https://huggingface.co` (a real mirror is
  still honoured when provided).

### Changed

- **ONNX PromptGuard is now truly torch-free.** Dropped `optimum` (which
  hard-requires `torch>=1.11`, ~750MB) — the scanner loads the `.onnx` graph
  with `onnxruntime.InferenceSession` directly and tokenises with
  `transformers.AutoTokenizer` (tokenizer-only, no torch extra). The image is
  ~700MB smaller and `pip install` is minutes faster; the "no torch" design
  claim is now actually true. Scoring (stable softmax over the 3-class logits)
  is unchanged.
- **Faster Docker builds.** The `models` stage is now self-contained (installs
  only `huggingface-hub` + `hf-xet`, decoupled from the builder) so a
  `requirements.txt` bump no longer invalidates the ~350MB model-download
  layer cache. A BuildKit cache mount (`/hf-cache`) persists the HF download
  across builds. The model is materialised as real flat files under
  `/models/hf/pg2` (copy, not symlink) so the runtime image is independent of
  the cache mount.
- **`docker-publish.yml`** now triggers on bare version tags (`0.2.0`) as well
  as `v`-prefixed ones (`v0.2.0`) — previously only `v*` matched, so a
  bare-semver tag push did not build the image. The `push: tags` event covers
  both tag creation and tag force-update (re-point). The Trivy scan step's
  image-ref now keys off `github.ref_type == 'tag'` instead of a `v` prefix
  check, so bare tags scan the just-built `latest` image.

### Added

- **`LF_ONNX_LOCAL_DIR`** config knob + `OnnxPromptGuardScanner(local_dir=...)`:
  when set (the container pre-bakes the model at `/models/hf/pg2`), the scanner
  loads the tokenizer + `.onnx` from disk — no HF hub access at runtime
  (air-gappable, `HF_HUB_OFFLINE=1`).
- **`.mise.toml`**: `install-onnx` task (torch-free ONNX stack) and
  `download-model` task (pre-fetches the model into the HF cache via
  `hf-xet` for fast local test runs).

### Removed

- **`optimum[onnxruntime]`** dependency (pulled torch). Replaced by direct
  `onnxruntime` usage.
- **`release.yml` workflow** — GitHub Releases are now created manually via the
  GitHub UI (tag → Draft a new release) with the `CHANGELOG.md` section pasted
  as the description. `docker-publish.yml` is the only workflow that fires on
  version tags. `CONTRIBUTING.md` release process updated accordingly.

## [0.2.0] - 2026-07-01

ONNX PromptGuard migration follow-up: correctness fix to the semantic scanner,
dead-code cleanup in the hot-reload path, a tag-driven release workflow, and a
pinned developer environment.

### Fixed

- **ONNX PromptGuard scoring** (`guardrails/scanners.py`): the scorer applied
  a per-logit sigmoid despite its docstring claiming a softmax. PromptGuard-2
  is a 3-class (`safe` / `injection` / `jailbreak`) classifier, so the
  jailbreak probability must come from a softmax over the class dimension —
  matching LlamaFirewall's `promptguard_utils`. Sigmoid produced miscalibrated
  scores (a single confident `safe` logit could still yield a high
  "jailbreak" probability). Now computes a numerically-stable softmax and
  takes the last class. Tokenizer switched to `return_tensors="np"` so the
  scanner truly needs no torch (previously `"pt"` would have required torch
  to materialise tensors).
- **`OnnxPromptGuardScanner` default `file_name`** aligned to `model.onnx`
  (full-precision, the same default `GuardrailConfig` ships), replacing the
  divergent `model.quant.onnx` scanner default.
- **Dead `GuardrailEngine.reload_rules`** was a stub that always returned 0.
  Reimplemented to re-resolve the rule pack from the configured source and
  atomically swap it into the `InvariantEngine` via a new public
  `InvariantEngine.set_rules()` (replaces the rule-list reference, so an
  in-flight evaluation keeps iterating the old list).
- **`server.py` SIGHUP handler** no longer reaches into
  `engine._c.invariant._rules` (private internals) and no longer discards the
  `RulePack` it constructed — it calls `engine.reload_rules()`.
- **Stale docstrings** in `guardrails/__init__.py`, `engine.awarm`, and the
  ONNX scanner that still referenced the removed `LlamaFirewallScanner` /
  torch path after the ONNX migration.
- **`pr.yml`** comment referenced the non-existent `ENABLE_LLAMAFIREWALL`
  env var; corrected to `ENABLE_PROMPTGUARD`.

### Added

- **`release.yml` workflow** (`.github/workflows/release.yml`): tag-driven
  (`v*`) GitHub Release creation. Verifies the tag matches the `pyproject.toml`
  version, extracts the matching `## [x.y.z]` section from `CHANGELOG.md` as
  the release body (falling back to auto-generated notes), and marks
  pre-releases when the tag contains a hyphen. Fills the gap left by
  `docker-publish.yml` and `CONTRIBUTING.md`, which both already referenced it.
- **`.mise.toml`** — pinned developer environment (Python 3.11 via
  python-build-standalone, no compilation) with `install` / `test` / `lint` /
  `proto-check` / `ci` tasks.

### Changed

- Version bump `0.1.0` → `0.2.0` in `pyproject.toml` and
  `guardrails/__init__.py.__version__`.

## [0.1.0] - 2025

First release. Wraps LlamaFirewall (Meta's semantic content scanners —
PromptGuard-2, AgentAlignment, CodeShield) and an Invariant Guardrails-style
rule engine (cross-call toxic-flow / loop detection) behind the agentgateway
ExtMcp gRPC contract as a fail-closed policy sidecar.

### Added

- **ExtMcp gRPC servicer** (`guardrails/servicer.py`) implementing the
  agentgateway ExtMcp v1alpha1 contract: `CheckRequest(McpRequest) ->
McpRequestResult` and `CheckResponse(McpResponse) -> McpResponseResult`.
  Both return one of `allowed` (Pass), `mutated` (Mutated), or `error`
  (AuthorizationError) via a protobuf `oneof`. Malformed JSON-RPC payloads
  map to `INVALID_ARGUMENT`; policy denies map to `PERMISSION_DENIED`
  (which agentgateway surfaces to the agent as JSON-RPC `-32001`).
- **Proto contract** (`proto/ext_mcp.proto`) with the `allowed` oneof
  field name (rather than `pass`) to avoid the Python reserved-word kwarg
  collision in the generated stubs. Wire-compatible with agentgateway via
  protobuf field numbers.
- **Content scanners** (`guardrails/scanners.py`):
  - `RegexScanner` — zero-dependency deterministic scanner with the
    default pattern set: hidden ASCII / control Unicode (RTL override,
    zero-width), private keys, AWS / GitHub / GitLab / Slack tokens,
    high-entropy blobs, credit cards, emails. First-match wins.
  - `LlamaFirewallScanner` — lazy-import wrapper around
    `llamafirewall.LlamaFirewall` running PromptGuard-2 + CodeShield for
    the `TOOL` role on request, PromptGuard for the `ASSISTANT` role on
    response. Sync model inference bridged via `asyncio.to_thread`.
  - `StubScanner` — for tests and `GUARDRAIL_DRY_RUN=1`.
  - `extract_text` flattens MCP params / results to a scan string with
    `ensure_ascii=False` (preserves hidden Unicode in argument values).
  - `truncate` cuts on a UTF-8 boundary at `MAX_CONTENT_BYTES` (default
    32 KiB) and returns a `truncated` flag for the audit record.
- **Invariant rule engine** (`guardrails/invariant.py`):
  - `FlowStep` — tool matcher (exact string / regex string / compiled
    `re.Pattern` / callable) plus optional `args` mapping of dotted-path
    -> value matcher. Dotted paths support nested dict / list structures
    with integer list indices (`recipients.0.email`).
  - `ToxicFlowRule` — ordered subsequence matcher. Steps need not be
    contiguous in the trace; first-match wins across rules in priority
    order.
  - `LoopRule` — fires when the same `(tool, args)` fingerprint repeats
    `threshold` times within the window. Distinguishes genuine retry
    loops (injection signature) from parameterised searches (args differ
    each call).
  - `InvariantEngine` — bounded `deque(maxlen=window)` sliding window,
    `record(tool, args)` + `evaluate()` API. Trace mutation serialised
    via an `asyncio.Lock` so concurrent requests cannot interleave
    half-calls.
- **Fail-closed DecisionAggregator** (`guardrails/aggregator.py`):
  `BLOCK` always wins; `HUMAN_REVIEW` resolved per `HUMAN_REVIEW_MODE`
  (`pass` -> forward with audit warning, `deny` -> escalate to hard
  deny); mutation passthrough when no scanner blocks.
- **GuardrailEngine orchestrator** (`guardrails/engine.py`):
  - Request path: content scanners on params (role `TOOL`) + invariant
    trace record + evaluate.
  - Response path: content scanners on result (role `ASSISTANT`) +
    optional second-stage AgentAlignment gated on first-stage
    `HUMAN_REVIEW` (cost control for the LLM-based alignment check).
  - Per-scanner `asyncio.wait_for` deadline (`SCANNER_TIMEOUT_MS`);
    exceptions and timeouts translated per `FAILURE_MODE` (failClosed ->
    BLOCK, failOpen -> HUMAN_REVIEW).
- **Rule pack loader** (`guardrails/rules/__init__.py`): resolution
  order `INVARIANT_RULES_PATH` (filesystem, hot-reloadable via SIGHUP) >
  `INVARIANT_RULES_MODULE` (dotted Python path) >
  `guardrails.rules.default`. `RulePack` swaps the active rule tuple
  atomically behind an `RLock`. Arbitrary file extensions (e.g.
  `rules.policy`) supported via `SourceFileLoader`.
- **Default rule pack** (`guardrails/rules/default.py`): inbox ->
  external email exfil, secret-read -> HTTP exfil, shell -> privileged
  k8s apply, denied-tool retry loop.
- **Configuration** (`guardrails/config.py`): every knob
  environment-variable driven with homelab defaults. 17 vars total:
  `FAILURE_MODE`, `HUMAN_REVIEW_MODE`, `MAX_CONTENT_BYTES`,
  `ENABLE_REGEX_SCANNER`, `ENABLE_PROMPTGUARD`,
  `ENABLE_AGENT_ALIGNMENT`, `INVARIANT_WINDOW`,
  `INVARIANT_RULES_PATH`, `INVARIANT_RULES_MODULE`,
  `SCANNER_TIMEOUT_MS`, `LISTEN_ADDR`, `SERVER_MAX_WORKERS`,
  `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `AUDIT_LOG_PATH`,
  `GUARDRAIL_DRY_RUN`, `LOG_LEVEL`.
- **Observability** (`guardrails/otel.py`):
  - Always-on JSONL audit sink (`AuditSink`) emitting one line per
    decision with phase, method, tool, outcome, reason, scanners list,
    truncated flag, transport, route. Defaults to stdout; durable path
    via `AUDIT_LOG_PATH`.
  - Optional OTel (`Observability._init_otel`) when
    `OTEL_EXPORTER_OTLP_ENDPOINT` is set: per-decision spans on
    `guardrail.check_request` / `guardrail.check_response` with
    method / tool / outcome / reason / duration_ms / second_stage
    attributes; counter `mcp.guardrails.decisions{phase,outcome,method}`.
    Degrades to audit-only when the SDK is absent or the endpoint is
    unreachable.
- **Server entrypoint** (`server.py`): `grpc.aio` server on
  `[::]:9001` (h2c), `grpc.health.v1` health service (SERVING only
  after `engine.awarm()` completes — keeps the Pod out of rotation
  during PromptGuard-2 model load), `SIGHUP` handler for hot rule-pack
  reload, `SIGTERM` / `SIGINT` graceful drain.
- **Multi-stage Dockerfile** (`base` / `builder` / `models` / `runtime`):
  `python:3.11-slim`, pre-downloads PromptGuard-2-86M at build time
  (air-gappable, fast cold-start), non-root UID/GID 65532, `EXPOSE 9001`,
  inline-Python `grpc.health.v1` healthcheck (zero extra system deps).
  Image published as
  `ghcr.io/soulwhisper/mcp-guardrails:0.1.0` (multi-arch
  linux/amd64 + linux/arm64).
- **Kubernetes manifests** (`deploy/k8s/`): Namespace, ConfigMap rule
  pack, 2-replica Deployment (fail-closed env, 500m/2Gi request,
  2/4Gi limit, grpc readiness + liveness probes), h2c Service
  (`appProtocol: kubernetes.io/h2c`), `AgentgatewayPolicy` CRD
  (tools/call Full, tools/list + prompts/get + resources/read Response),
  HPA (2-4 on CPU 70%), PDB (minAvailable 1), kustomization.
- **GitHub Actions** (`.github/workflows/`):
  - `ci.yml` — lint (ruff), test (71 unit tests, ML-free install, no
    torch/transformers/llamafirewall), proto-check (regenerate stubs +
    `git diff --exit-code`), `ci-pass` aggregator job for branch
    protection.
  - `pr.yml` — e2e on PRs (`python tests/e2e_smoke.py`).
  - `docker-publish.yml` — multi-arch image build + push on `main` and
    `v*` tags, four tag types (branch / semver major.minor / semver
    version / latest-on-tag), Trivy advisory scan.
  - `release.yml` — GitHub Release on `v*` tags with
    `generate_release_notes: true`.
  - `codeql.yml` — weekly Python CodeQL analysis.
- **Repo automation** (`.github/`): `CODEOWNERS` (security-sensitive
  paths flagged), `dependabot.yml` (pip / docker / github-actions,
  weekly, grouped), `PULL_REQUEST_TEMPLATE.md` (guardrail-policy impact
  checklist), bug-report + feature-request issue forms.
- **Examples** (`examples/`):
  - `rules.policy` — 6-rule commented pack (inbox -> external email,
    secret-read -> HTTP exfil, shell -> privileged k8s apply, db-dump
    -> external upload, file-read -> webhook exfil, retry storm loop).
  - `docker-run.env` — example env file for `docker run --env-file`.
  - `agentgateway-local.yaml` — standalone agentgateway config
    pointing at `localhost:9001` with `failureMode: FailClosed` and
    the standard method-phase matrix.
- **Tests** (`tests/`): 71 unit tests covering aggregator (fail-closed
  table), invariant (ordered subsequence, LoopRule fingerprint,
  dotted-path resolution, hot-reload), scanners (regex patterns,
  truncation, `extract_text` hidden-Unicode preservation), engine
  (timeout / exception handling, second-stage gating, trace
  serialisation), servicer (in-process gRPC round-trip + wire mapping),
  rules loader. Plus `tests/e2e_smoke.py` — boots a live server in a
  subprocess and exercises health + `CheckRequest` (allow + deny on
  hidden Unicode) + `CheckResponse` (deny on private key) + malformed
  `INVALID_ARGUMENT`.
- **Docs**: `README.md` (front door with env-var table, Mermaid sequence
  - flowchart diagrams, quick start, deployment, security model),
    `ARCHITECTURE.md` (deep dive: proto contract, request / response
    lifecycles, aggregator table, invariant engine, failure handling,
    observability, image build, homelab cost tradeoffs),
    `CONTRIBUTING.md` (dev workflow, proto-stub sync rule, scanner / rule
    extension guide, DCO, release process), `CHANGELOG.md` (this file),
    `LICENSE` (Apache-2.0).

### Security

- Fail-closed by default (`FAILURE_MODE=failClosed`). Scanner exceptions
  and timeouts produce `BLOCK`; aggregator denies; agentgateway returns
  JSON-RPC `-32001`.
- Sidecar-unreachable: agentgateway's `mcp-guardrails` processor
  `failureMode: FailClosed` denies the MCP exchange.
- Model load failure: gRPC health check stays `NOT_SERVING`; readiness
  probe keeps the Pod out of Service endpoints.
- Large result truncation (32 KiB default) on a UTF-8 boundary; decision
  flagged `truncated=true` in audit.
- stdio upstream caveat: agentgateway forwards an empty header set; do
  not rely on headers for authn/authz when
  `metadata_context.upstream_transport == "stdio"`.

[0.3.0]: https://github.com/soulwhisper/mcp-guardrails/releases/tag/v0.3.0
[0.3.1]: https://github.com/soulwhisper/mcp-guardrails/releases/tag/v0.3.1
[0.2.1]: https://github.com/soulwhisper/mcp-guardrails/releases/tag/v0.2.1
[0.2.0]: https://github.com/soulwhisper/mcp-guardrails/releases/tag/v0.2.0
[0.1.0]: https://github.com/soulwhisper/mcp-guardrails/releases/tag/v0.1.0
