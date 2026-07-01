# syntax=docker/dockerfile:1.7
#
# mcp-guardrails sidecar image.
#
# Multi-stage build:
#   1. base       — shared system deps (ca-certs, curl for healthcheck)
#   2. builder    — pip install into a clean prefix (no build tools leak)
#   3. models     — pre-download ONNX PromptGuard-2-86M so runtime never hits HF
#   4. runtime    — nonroot (65532), copy install + models + app, expose :9001
#
# The ONNX model (gravitee-io/Llama-Prompt-Guard-2-86M-onnx) is PUBLIC and
# non-gated — no HuggingFace token required. Uses ONNX Runtime for CPU
# inference (no torch dependency, ~400MB smaller image than the torch path).
#
# Final image ~600-800MB (onnxruntime + transformers + model weights).

ARG PY_VERSION=3.11-slim

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

# ---------- builder ----------
FROM base AS builder
WORKDIR /build
COPY requirements.txt .
# Install into /install prefix so we can copy just the artifacts to runtime.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefix=/install -r requirements.txt

# ---------- models ----------
# Pre-download the ONNX PromptGuard-2 model into the image. The model is
# PUBLIC and non-gated, so NO HF_TOKEN is needed. This keeps runtime cold-start
# fast (no download on first scan) and makes the image air-gappable.
#
# Default: model.onnx (full-precision, ~350MB, accuracy 98.01%).
# Override with --build-arg LF_ONNX_FILE=model.quant.onnx for the quantized
# variant (~90MB, accuracy 89.89%) if you want a smaller image.
FROM base AS models
ARG SKIP_MODEL_DOWNLOAD=0
ARG LF_ONNX_MODEL=gravitee-io/Llama-Prompt-Guard-2-86M-onnx
ARG LF_ONNX_FILE=model.onnx
COPY --from=builder /install /usr/local
RUN set -e; \
    if [ "${SKIP_MODEL_DOWNLOAD}" = "1" ]; then \
        echo "SKIP: model pre-download (SKIP_MODEL_DOWNLOAD=1)"; \
        echo "      Runtime will lazy-fetch on first scan."; \
        exit 0; \
    fi; \
    echo "Pre-downloading ONNX model: ${LF_ONNX_MODEL} (${LF_ONNX_FILE}) — public, no token needed"; \
    python - <<PYEOF
from huggingface_hub import snapshot_download
import os, shutil
m = "${LF_ONNX_MODEL}"
f = "${LF_ONNX_FILE}"
# Download the ONNX model + tokenizer files (not the full snapshot).
path = snapshot_download(repo_id=m, allow_patterns=[f, "config.json", "tokenizer*", "special_tokens_map.json", "vocab*"])
# Symlink into /models/hf/pg2 so runtime finds it via HF_HOME.
os.makedirs("/models/hf/pg2", exist_ok=True)
for item in os.listdir(path):
    src = os.path.join(path, item)
    dst = os.path.join("/models/hf/pg2", item)
    if os.path.exists(dst):
        os.remove(dst) if os.path.islink(dst) else shutil.rmtree(dst)
    os.symlink(src, dst)
print(f"ONNX model cached at /models/hf/pg2 (from {path})")
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

ENV HF_HOME=/models/hf \
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
