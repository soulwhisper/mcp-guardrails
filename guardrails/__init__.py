"""ExtMcp Guardrail — agentgateway ExtMcp policy sidecar.

This package wraps an ONNX PromptGuard-2 semantic scanner (``onnxruntime`` +
``transformers`` tokenizer, no torch) and an Invariant Guardrails-style
cross-call toxic-flow rule engine behind the agentgateway ExtMcp gRPC
contract. The public entrypoint is :class:`guardrails.engine.GuardrailEngine`,
which the gRPC servicer in :mod:`guardrails.servicer` drives.

ML dependencies (``onnxruntime``, ``transformers``) are imported lazily so
that the pure-Python policy core (models, aggregator, invariant engine,
regex scanners) remains importable and unit-testable without them — the
engine falls back to regex-only when the ONNX stack is absent.
"""

from .models import Decision, ScanOutcome, ScanResult

__version__ = "0.2.0"
__all__ = ["Decision", "ScanOutcome", "ScanResult", "__version__"]
