# syntax=docker/dockerfile:1.28@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
#
# mcp-guardrails sidecar image.
#
# Multi-stage build:
#   1. base       — shared system deps (ca-certs, curl for healthcheck)
#   2. builder    — pip install into a clean prefix (no build tools leak)
#   3. models     — pre-download ONNX PromptGuard-2-22M so runtime never hits HF
#   4. runtime    — nonroot (65532), copy install + models + app, expose :9001
#
# The ONNX model (gravitee-io/Llama-Prompt-Guard-2-22M-onnx) is PUBLIC and
# non-gated — no token required for access. However, HF_TOKEN is recommended
# to avoid 429 rate-limiting during the model download stage (HF applies
# stricter limits to unauthenticated requests from shared IPs like GHA).
# Uses ONNX Runtime for CPU inference (no torch dependency, ~400MB smaller
# image than the torch path).
#
# Final image ~600-800MB (onnxruntime + transformers + model weights).

ARG PY_VERSION=3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

# ---------- base ----------
FROM python:${PY_VERSION} AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/models/hf \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# The base image's bundled setuptools lags behind CVE fixes (70.3.0 was
# flagged CVE-2025-47273 by the release-gate trivy scan even on a current
# 3.14-slim digest). Upgrade once here so all stages inherit it.
RUN pip install --no-cache-dir --upgrade "setuptools>=78.1.1"

# ---------- builder ----------
FROM base AS builder
WORKDIR /build
COPY requirements.txt .
# Install into /install prefix so we can copy just the artifacts to runtime.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefix=/install -r requirements.txt

# Pre-download the ONNX PromptGuard-2 model into the image. The model is
# PUBLIC and non-gated — no token required for access. However, HF_TOKEN
# is recommended to avoid 429 rate-limiting from shared GHA IPs. The secret
# is optional; the build works without it (just slower on cache miss).
# This keeps runtime cold-start fast (no download on first scan) and makes
# the image air-gappable.
#
# Default: Llama-Prompt-Guard-2 **22M** ONNX (full-precision, 271MB,
# accuracy 95.64% / recall 92.49% — gravitee benchmark). Chosen over the 86M
# fp32 (98.01% / 96.25%) because the 86M needs 0.5-2.1s per scan on 2 shared
# CPU cores — over any sane FailClosed scanner timeout — while the 22M cuts
# compute ~75% (Meta) and lands well under 1s. The 86M quantized variant is
# NOT an option (recall collapses to 80.18%); the 22M quant (95.79% / 92.04%,
# 69MB) keeps accuracy and is available via --build-arg LF_ONNX_FILE=
# model.quant.onnx (sha256 38c3f03e30a4d5d229aeb7bf638e778322f8179d0ed0d4953eb22f88d8e0cf6b).
#
# Build-cache: the HF download is cached in a BuildKit cache mount (/hf-cache)
# so a rebuild (even after an upstream layer change) reuses the ~350MB download
# instead of re-fetching it. The model is then materialised as REAL flat files
# under /models/hf/pg2 (copy, not symlink) so the runtime image is independent
# of the (ephemeral) cache mount. hf-xet (auto-detected) parallelises the
# download — 2-5x faster for the large .onnx blob.
FROM base AS models
ARG SKIP_MODEL_DOWNLOAD=0
ARG LF_ONNX_MODEL=gravitee-io/Llama-Prompt-Guard-2-22M-onnx
ARG LF_ONNX_FILE=model.onnx
# Supply-chain pin (S-M6): pin the model download to an immutable HF commit
# so a re-tagged or compromised upstream repo cannot silently swap the
# weights baked into the image. To update:
#   curl -s https://huggingface.co/api/models/$LF_ONNX_MODEL | jq -r .sha
# and bump the default here (and LF_ONNX_REVISION for non-container runs).
# Integrity pin (T1-3): fail the build if the downloaded .onnx does not
# match this sha256, so a corrupted or tampered upstream blob is never baked
# into the image. The default pins model.onnx at PG2_REVISION; to fetch the
# hash for a different file/revision:
#   curl -s https://huggingface.co/api/models/$LF_ONNX_MODEL/tree/$PG2_REVISION
# (the .lfs.oid field of the target file). When overriding LF_ONNX_FILE or
# LF_ONNX_MODEL, override PG2_SHA256 to match; set it empty to skip
# verification.
ARG PG2_REVISION=da68d0f6023c7aeaf6b256eec549de295d5e8740
ARG PG2_SHA256=c6f4d2ebf59be36f3557ad484bf11a51f1b356f570958d1ec1cbbe322a8dfddf
# Install ONLY what the download needs (huggingface_hub + hf-xet) — NOT the
# full runtime deps. This decouples the model-download layer from the builder
# stage, so a requirements.txt bump does NOT invalidate the (slow, ~350MB) model
# layer cache: the download RUN only re-runs when LF_ONNX_MODEL / LF_ONNX_FILE
# actually change.
RUN pip install --no-cache-dir "huggingface-hub>=0.30.2" "hf-xet>=1.5"
RUN --mount=type=cache,target=/hf-cache,sharing=locked \
    --mount=type=secret,id=HF_TOKEN \
    set -e; \
    if [ -f /run/secrets/HF_TOKEN ]; then export HF_TOKEN=$(cat /run/secrets/HF_TOKEN); fi; \
    if [ "${SKIP_MODEL_DOWNLOAD}" = "1" ]; then \
        echo "SKIP: model pre-download (SKIP_MODEL_DOWNLOAD=1)"; \
        echo "      Build-validation only: runtime sets HF_HUB_OFFLINE=1 and will fail closed if the model is absent."; \
        mkdir -p /models/hf/pg2; \
        exit 0; \
    fi; \
    export HF_HOME=/hf-cache; \
    echo "Pre-downloading ONNX model: ${LF_ONNX_MODEL} (${LF_ONNX_FILE})"; \
    python - <<PYEOF
from huggingface_hub import snapshot_download
import hashlib, os, shutil
m = "${LF_ONNX_MODEL}"
f = "${LF_ONNX_FILE}"
rev = "${PG2_REVISION}" or None
# Download the ONNX model + tokenizer files into the cache mount (persisted
# across builds), then materialise REAL bytes into the image layer at
# /models/hf/pg2 so the runtime image is self-contained (independent of the
# ephemeral cache mount). The revision is pinned (PG2_REVISION, S-M6) so the
# baked weights are an immutable upstream commit, not a mutable ref.
path = snapshot_download(repo_id=m, revision=rev, allow_patterns=[f, "config.json", "tokenizer*", "special_tokens_map.json", "vocab*"])
# Integrity verify (T1-3): sha256-check the downloaded weights against the
# pinned PG2_SHA256 before materialising them into the image; fail the build
# on mismatch. Empty PG2_SHA256 skips verification (documented override).
expected = "${PG2_SHA256}".strip().lower()
if expected:
    h = hashlib.sha256()
    with open(os.path.join(path, f), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    if digest != expected:
        raise SystemExit(f"FAIL: sha256 mismatch for {f}: got {digest}, expected {expected}")
    print(f"sha256 verified for {f}: {digest}")
else:
    print("WARNING: PG2_SHA256 empty — skipping model integrity verification")
os.makedirs("/models/hf/pg2", exist_ok=True)
for item in os.listdir(path):
    src = os.path.join(path, item)
    dst = os.path.join("/models/hf/pg2", item)
    if os.path.islink(dst) or os.path.isfile(dst):
        os.remove(dst)
    elif os.path.isdir(dst):
        shutil.rmtree(dst)
    if os.path.isdir(src):
        shutil.copytree(src, dst, symlinks=False)
    else:
        shutil.copy2(src, dst)  # dereferences the snapshot symlink -> real bytes
print(f"ONNX model materialised at /models/hf/pg2 (from {path})")
PYEOF

# ---------- runtime ----------
FROM base AS runtime
# Non-root user matching the K8s securityContext (runAsUser 65532).
RUN useradd -u 65532 -r -s /sbin/nologin nonroot

# Copy installed Python packages.
COPY --from=builder /install /usr/local
# Copy pre-downloaded models (may be empty if the models stage was skipped).
COPY --from=models /models/hf /models/hf

WORKDIR /app
# Application code. proto/ contains the generated stubs (committed) so we do
# not need grpcio-tools in the runtime image.
COPY proto/ext_mcp_pb2.py proto/ext_mcp_pb2_grpc.py /app/proto/
COPY guardrails/ /app/guardrails/
COPY server.py /app/server.py

# LF_ONNX_LOCAL_DIR points the scanner at the pre-baked model so it loads from
# disk (no HF hub access at all). HF_HUB_OFFLINE=1 guarantees no network call
# even on a cache miss (fail fast instead of hanging in an air-gapped env).
ENV HF_HOME=/models/hf \
    LF_ONNX_LOCAL_DIR=/models/hf/pg2 \
    HF_HUB_OFFLINE=1 \
    PYTHONPATH=/app \
    LISTEN_ADDR="[::]:9001"

USER 65532:65532
EXPOSE 9001

# grpcurl is not installed; use Python's grpc health probe instead so the
# HEALTHCHECK has zero extra system deps.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 --start-period=20s \
    CMD python -c "import grpc; from grpc_health.v1 import health_pb2, health_pb2_grpc; \
    ch=grpc.insecure_channel('localhost:9001'); stub=health_pb2_grpc.HealthStub(ch); \
    r=stub.Check(health_pb2.HealthCheckRequest(service='')); \
    exit(0 if r.status==1 else 1)" || exit 1

ENTRYPOINT ["python", "server.py"]
