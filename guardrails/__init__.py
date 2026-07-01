"""ExtMcp Guardrail — agentgateway ExtMcp policy sidecar.

This package wraps ONNX PromptGuard-2 (semantic content scanner, via
``optimum[onnxruntime]``) and an Invariant Guardrails-style cross-call
toxic-flow rule engine behind the agentgateway ExtMcp gRPC contract. The
public entrypoint is :class:`guardrails.engine.GuardrailEngine`, which the
gRPC servicer in :mod:`guardrails.servicer` drives.

Heavy ML dependencies (``optimum``, ``onnxruntime``, ``transformers``) are
imported lazily so that the pure-Python policy core (models, aggregator,
invariant engine, regex scanners) remains importable and unit-testable in an
environment without the model weights — the engine falls back to regex-only
when the ONNX stack is absent.
"""

from .models import Decision, ScanOutcome, ScanResult

__version__ = "0.2.0"
__all__ = ["Decision", "ScanOutcome", "ScanResult", "__version__"]
