# ExtMcp Guardrail — developer Makefile.
# Targets are idempotent and safe to re-run.

PY ?= python3
PORT ?= 9001
IMAGE ?= ghcr.io/soulwhisper/mcp-guardrails
TAG ?= 0.2.0

.PHONY: help proto proto-check install dev test lint format clean docker run ci

help: ## Show available targets
        @grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
                awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

proto: ## Regenerate Python gRPC stubs from proto/ext_mcp.proto
        # NOTE: the committed stubs are generated with grpcio-tools 1.71.2 +
        # protobuf 5.29.0 for CI compatibility (the CI proto-check job's
        # pip install resolves to that toolchain). If you run `make proto`
        # with a different grpcio-tools version, the output will differ
        # cosmetically (version stamps, class style) but be semantically
        # identical. Run `make proto-check` to verify — it normalizes
        # cosmetic differences before diffing.
        $(PY) -m grpc_tools.protoc -I proto \
                --python_out=proto --grpc_python_out=proto \
                proto/ext_mcp.proto
        @echo "stubs regenerated in proto/ (run 'make proto-check' to verify)"

proto-check: ## Verify committed stubs are in sync with the .proto (normalized)
        $(PY) scripts/proto_check.py

install: ## Install runtime deps into the active environment
        pip install -r requirements.txt

dev: ## Install dev/test deps (no ML stack — for fast local iteration)
        pip install -e ".[dev]"

test: ## Run the unit test suite
        $(PY) -m pytest tests/ -q

test-cov: ## Run tests with coverage
        $(PY) -m pytest tests/ --cov=guardrails --cov=server --cov-report=term-missing

lint: ## Lint with ruff
        $(PY) -m ruff check guardrails server.py tests scripts

format: ## Format with ruff
        $(PY) -m ruff format guardrails server.py tests scripts
        $(PY) -m ruff check --fix guardrails server.py tests scripts

docker: ## Build the container image
        docker build -t $(IMAGE):$(TAG) .

docker-run: ## Run the container locally on $(PORT)
        docker run --rm -p $(PORT):9001 $(IMAGE):$(TAG)

run: ## Run the server locally (requires deps installed)
        $(PY) server.py

clean: ## Remove build/test artifacts
        rm -rf build dist *.egg-info .pytest_cache .ruff_cache
        find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

ci: lint test proto-check ## What CI runs on every PR
        @echo "CI checks passed"
