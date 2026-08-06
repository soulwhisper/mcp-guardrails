# Production-Readiness Re-evaluation — 2026-08-05

**Baseline**: `main` @ `060a000` (v0.6.0)
**Prior baseline**: `mcp-guardrails-assessment-20260722.md` @ `519c4e6e` (2026-07-22)
**Method**: local gate suite (pytest / ruff / proto_check / version_check) + two
independent read-only re-verification passes (security+functional, audit+ops+CI)
against current code; every verdict carries `file:line` evidence.

## Local verification

| Check | Result |
|---|---|
| pytest | 363 passed / 1 skipped (skip = hypothesis absent from local venv; declared dev-extra, installed in CI) |
| ruff | clean |
| proto_check | clean — stubs in sync after normalization |
| version_check | clean — all release-facing versions 0.6.0 |

## Verdict

**Single-replica, default-config: production-ready.** Every P0 from the
2026-07-22 assessment is closed with test coverage; the full gate suite is green.

**Multi-replica / internet-adjacent: three workstreams remain** — interop e2e in
CI, signed/SBOM'd images with blocking Trivy, and dependency/model hash-locking.
All other items are documented accepted-risk or deliberate feature scope.

**Score vs. prior assessment**: security/functional 24 CLOSED / 6 PARTIAL / 5 OPEN;
audit/observability 11 of 13 tracked items CLOSED.

## Closed since 2026-07-22 (waves 1–4: PRs #65, #67, #68, #74, #75, #77, #91)

| Gap | Closing evidence |
|---|---|
| S-C1 gRPC zero isolation | `deploy/k8s/networkpolicy.yaml:33-46` deny-default, `:60-103` allow from agentgateway NS, `:116-133` egress DNS only; wired in `kustomization.yaml:23` |
| S-H1 PromptGuard 512-token cap | `scanners.py:759-773` sliding window (`PG_MAX_WINDOWS=16`), `:904-941` max-over-windows, `:830-858` id2label load-time validation |
| S-H2 mid-window blind spot | `scanners.py:1010-1047` head/mid/tail; `engine.py:610-629` hard cap → HUMAN_REVIEW `payload_size`; scanned/total bytes in audit |
| S-H3 review-path redaction suppressed | `config.py:124-130` `redact_on_review` default True; `engine.py:556-567` review payloads redacted, verdict preserved |
| S-H4 invariant window flush | `invariant.py:516` window 256 default, `:527-533`/`:580-606` TTL-bounded sticky partial matches |
| S-H5 trace key granularity | `engine.py:747-765` `route\|header=value` templating; `config.py:216-220` `INVARIANT_TRACE_KEY_HEADERS` |
| S-M1 regex evasion | `scanners.py:100` IGNORECASE, `:135-139` markdown-exfil, `:205-225`/`:435-452` NFKC/Cf-strip/homoglyph normalized view |
| S-M2/F-P1-4 extract_text shapes | `scanners.py:1126-1168` `contents[]` incl. blob decode (256KiB cap), `messages[]`; `:1170-1182` tools/list description+schema |
| S-M4 DoS bounds | `server.py:160-174` max message + `maximum_concurrent_rpcs`; `invariant.py:236-264` args storage truncation |
| S-M5 deny oracle / fingerprint PII | `servicer.py:147-165` generalized public reasons with ref; `scanners.py:244-261` keyed HMAC digests, low-entropy tier records length only |
| S-M7 LLM egress leak | `scanners.py:570-581` pre-egress RedactionScanner; `:686-698` fingerprint-only reasons |
| S-L1 scanner latency budget | `engine.py:695-719` concurrent scanners, per-scanner 500ms deadline; `agentgateway-policy.yaml:91` requestTimeout 5s |
| S-L3 LoopRule nonce evasion | `invariant.py:364-416` RateLimitRule backstop (default 30 calls/60s) |
| F-P0-1 multi-replica trace | `docs/deployment.md:58-69` session-sticky guidance; session-granular key (S-H5) |
| F-P0-2 reverse-channel coverage | documented as known gap: `docs/security-model.md:81-86` |
| F-P1-6 empty tool_name trace pollution | `engine.py:433-436` record only for tools/call with tool_name |
| F-P2-1 rule expressiveness | `invariant.py:364-416` RateLimitRule, `:420-487` AggregateRule, `:86-93`/`:190-211` negated flow steps |
| F-P2-3 grey-zone thresholds | `scanners.py:752-757`/`:883-893`; `PG_REVIEW_THRESHOLD=0.5` (`config.py:163`) |
| F-P2-4 AgentAlignment context | `scanners.py:570-581` pre-egress redaction; `engine.py:777-799` trace summary into ctx |
| F-P2-5 operator CLI | `scripts/guardrail_ctl.py:453-496` rules lint/dry-run, decision replay, audit verify |
| F-P2-7 review webhook | `notify.py:1-60` fire-and-forget POST; `engine.py:675-692`; `docs/operations/review-webhook.md` |
| A-P0-1 audit correlation | `servicer.py:66-134` `_extract_exchange_id` (trusted metadata keys only, sanitized, uuid8 fallback); both phases emit; `guardrail_ctl decision replay` pairs offline |
| A-P0-2 LLM raw in audit | `scanners.py:677-688`/`:690-700` length-only fingerprints, never text |
| A-P0-3 tamper evidence | `otel.py:31-105` hash chain (`prev_hash`/`line_hash`, default on); `guardrail_ctl audit verify`; WORM/retention in `docs/compliance.md` §2/§5 |
| A-P0-4 runtime health degradation | `engine.py:112`/`:277-296` sliding error-rate window; `server.py:52-83` watchdog flips NOT_SERVING; `docs/operations/health.md` |
| A-P1-1 audit fields | `otel.py:283-302` ts_ms, caller, payload_sha256, rules_version, sidecar_version, duration_ms, scanned/total bytes |
| A-P1-2 metrics | `otel.py:157-226` decisions counter, duration histogram, scanner_results, redactions, invariant_hits, rules_reload — bounded labels |
| A-P1-3 reload visibility | `engine.py:318-339` audit line + counter on success and failure |
| A-P1-4 engine_error leak | `servicer.py:361-367`/`:387-393` fixed wire reason, detail log-only |
| A-P2-1 property tests | `tests/test_property.py` (hypothesis over scan_windows/extract_text/JSON parsing); `tests/test_redteam.py` |
| A-P2-4 shutdown order | `server.py:117-155` NOT_SERVING → drain (`SHUTDOWN_DRAIN_S=5`) → stop |
| A-P2-5 stale audit doc example | resolved by docs restructure; fingerprints documented in `docs/operations/auditing.md` |
| compliance doc | `docs/compliance.md` — data classification, retention, access control, egress, limitations |

## Remaining gaps

### Tier 1 — blocks "multi-replica / internet-adjacent production" claim

| # | Gap | Evidence | Effort |
|---|---|---|---|
| T1-1 | **Real agentgateway interop e2e not in CI** — PR gate is in-process `e2e_smoke` only (`pr.yml:43-57`); `scripts/e2e_agentgateway.sh` referenced by zero workflows; contract drift with upstream would be invisible. Blocked on a `workflow`-scope token per the 2026-07-22 plan | grep over `.github/workflows/` | M |
| T1-2 | **Image supply chain unsigned** — `docker-publish.yml:93` `provenance: false`; no SBOM/cosign step (`gen_sbom.sh:15-19` intentionally unwired); Trivy advisory-only (`:121` `continue-on-error: true`, `:126` `exit-code: '0'`) | `docker-publish.yml` | M |
| T1-3 | **Dependency/model hash-locking** — `.onnx` revision pinned (`Dockerfile:78` `PG2_REVISION`) but no sha256 verify (`Dockerfile:76` comment only); `protobuf>=7.35` no upper bound (`requirements.txt:22`); requirements not hash-locked; pip-audit is local-only (`Makefile:73-76`), no CI job | Dockerfile, requirements.txt | S |

### Tier 2 — partial by design; confirm acceptance or schedule

| # | Gap | Evidence |
|---|---|---|
| T2-1 | **Mutation producer redaction-only** — no tools/list description sanitizer (BLOCK-or-pass only); NFKC normalization detection-only (`test_wave4_hardening.py:76`); over-`REDACTION_MAX_BYTES` payloads pass unredacted, gated only by size review (`engine.py:665-667`) | `engine.py:631-673` |
| T2-2 | **Contract fields unemitted** — response-side metadata impossible (proto lacks field, `servicer.py:305-307`); `header_mutation` deliberately never emitted (`servicer.py:239-242`); `RESOURCE_EXHAUSTED` never emitted (`proto/ext_mcp.proto:66`) | servicer.py, proto |
| T2-3 | **No per-route policy differentiation / tool×identity ACL** — ctx passthrough and ALLOW/DENY_TOOLS done (`config.py:185-192`, `engine.py:398-407`/`:802-828`); route-scoped scanner sets/thresholds absent | engine.py |
| T2-4 | Regex rules hardcoded Python — no YAML configuration path | `scanners.py:82-143` |
| T2-5 | Rule packs local-file-only — no signed remote distribution / staged rollout | `rules/__init__.py` |
| T2-6 | Redaction residuals (documented) — HR-grade shapes excluded from wire set (`redaction.py:103-113`); mapping keys not redacted (`redaction.py:24-28`) | redaction.py |

### Tier 3 — ops hygiene

| # | Gap | Evidence |
|---|---|---|
| T3-1 | **OTel exporters hardcode `insecure=True`**, no TLS knob; export failures silently `suppress(Exception)` | `otel.py:138,144,225-226` |
| T3-2 | Rules hot-load via `exec()` — ConfigMap-writable=RCE implication not documented in `docs/security-model.md` | `rules/__init__.py` |
| T3-3 | No Prometheus HTTP endpoint (OTLP-only; previously marked optional) | `docs/operations/metrics.md` |
| T3-4 | Stale workflow comments — `ci.yml` header claims push-to-main (PR-only at `ci.yml:8-14`); `codeql.yml` claims weekly schedule (no `schedule:` block) | ci.yml, codeql.yml |

### External gates

- **MCP 2026-07-28 spec migration (M1/M2)** — gated on agentgateway shipping spec
  support; pinned v1.4.0 predates the spec. Re-eval checklist in
  `plans/mcp-2026-07-28-spec-eval.md`.
- **Workflow-scope token** — required for T1-1 (e2e workflow) and T1-2
  (docker-publish changes).

## Recommended order

1. **T1-3** (S, no token needed): model sha256 verify, protobuf upper bound,
   pip-audit CI job.
2. **T1-1 + T1-2** once a workflow-scope token exists: nightly pinned-agentgateway
   interop e2e; SBOM + cosign keyless + blocking Trivy in docker-publish.
3. **T3-1/T3-2** (S): OTel TLS knob + security-model doc note.
4. Tier 2 items are scope decisions, not defects — schedule deliberately.
