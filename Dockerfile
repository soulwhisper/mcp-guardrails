FROM python:3.11-slim AS base
ENV PYTHONUNBUFFERED=1 \
    HF_HOME=/models/hf \
    PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

FROM base as builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM base AS runtime
RUN useradd -u 65532 -r -s /sbin/nologin nonroot
COPY --from=builder /install /usr/local
COPY proto/ext_mcp_pb2.py proto/ext_mcp_pb2_grpc.py /app/proto/
COPY server.py guardrails/ /app/
RUN python -c "from transformers import AutoModelForSequenceClassification, AutoTokenizer; \
    m='meta-llama/Prompt-Guard-2-86M'; AutoTokenizer.from_pretrained(m).save_pretrained('/models/hf/pg2'); \
    AutoModelForSequenceClassification.from_pretrained(m).save_pretrained('/models/hf/pg2')"
WORKDIR /app
USER 65532:65532
EXPOSE 9001
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD grpcurl -plaintext -d '{"service":"grpc.health.v1.Health"}' localhost:9001 grpc.health.v1.Health/Check || exit 1
ENTRYPOINT ["python", "server.py"]
