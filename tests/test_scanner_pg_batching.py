"""PromptGuard batched-window inference regression tests (denial ref bad631b3).

``OnnxPromptGuardScanner._score`` stacks all token windows of a content chunk
into ONE ``InferenceSession.run`` call instead of one run per window. These
tests prove:

* the batched score is identical to the old per-window loop score (and so are
  the BLOCK / HUMAN_REVIEW / ALLOW decisions),
* the ONNX run count collapses to 1 per ``_score`` call while the batch row
  count keeps honouring the ``PG_MAX_WINDOWS`` latency bound,
* the batched feed keeps the pinned-graph contract — ``(batch, seq)`` int64
  ``input_ids`` / ``attention_mask`` (all ones) / ``token_type_ids`` (all
  zeros), and only the input names the graph declares are fed,
* a 42,649-byte long response (the bad631b3 payload size) is split into four
  balanced windows, each scored in one run, with malicious head / middle /
  tail controls still detected.

Same convention as ``tests/test_scanners.py``: fake sessions mimic
``onnxruntime.InferenceSession`` and every test is skipped in the ML-free CI
environment via the numpy importorskip. The repo keeps no pinned ``.onnx``
test fixture (CI hard-fails if onnxruntime/transformers leak into the unit
path), so graph batch-shape equivalence is asserted against the recorded
feeds of the shape-recording fake session rather than a real graph.
"""

from __future__ import annotations

import pytest

from guardrails.config import GuardrailConfig
from guardrails.engine import EngineComponents, GuardrailEngine
from guardrails.models import ScanOutcome
from guardrails.otel import Observability
from guardrails.scanners import OnnxPromptGuardScanner, scan_windows

# The exact response-body size from denial ref bad631b3.
_BAD631B3_BYTES = 42_649


class _CharTokenizer:
    """One token per character — exact token offsets without a real model."""

    def __call__(self, text, **kwargs):
        return {"input_ids": [[ord(c) % 251 for c in text]]}


class _FakeInput:
    def __init__(self, name):
        self.name = name


def _row_logits(row):
    """Deterministic per-row logits, computed row-by-row so a row yields
    bit-identical logits whether it arrives alone (old per-window loop) or
    inside a batch (new path).

    * contains marker id 250 -> malicious logits
    * contains marker id 249 -> grey-zone logits (softmax ~0.70)
    * otherwise -> benign logits
    """
    if (row == 250).any():
        return (0.0, 5.0)
    if (row == 249).any():
        return (0.0, 0.85)
    return (5.0, 0.0)


class _RecordingSession:
    """Batch-aware fake InferenceSession: per-row logits, records every feed
    and invocation so tests can assert run counts and batch shapes/dtypes."""

    def __init__(self, input_names=("input_ids", "attention_mask", "token_type_ids")):
        # Skips the whole test in the ML-free CI environment.
        np = pytest.importorskip("numpy")

        self._np = np
        self._inputs = [_FakeInput(n) for n in input_names]
        self.calls = 0
        self.feeds: list[dict] = []

    def get_inputs(self):
        return self._inputs

    def run(self, _targets, feed):
        np = self._np
        self.calls += 1
        self.feeds.append({k: np.asarray(v).copy() for k, v in feed.items()})
        ids = np.asarray(feed["input_ids"])
        rows = ids.reshape(1, -1) if ids.ndim == 1 else ids
        logits = np.array([_row_logits(r) for r in rows], dtype=np.float64)
        return [logits]


def _scanner(session, **kwargs) -> OnnxPromptGuardScanner:
    scanner = OnnxPromptGuardScanner(block_threshold=0.9, **kwargs)
    scanner._loaded = True
    scanner._tokenizer = _CharTokenizer()
    scanner._sess = session
    return scanner


def _reference_per_window_score(session, batch_feed):
    """Replay the OLD per-window loop against the recorded batched feed: one
    run per row (all-ones attention mask, zeros token types), per-row
    softmax, max last-class probability. Returns (score, run_count)."""
    import numpy as np

    declared = {i.name for i in session.get_inputs()}
    ids = batch_feed["input_ids"]
    best = 0.0
    runs = 0
    for row in ids:
        feed = {}
        if "input_ids" in declared:
            feed["input_ids"] = row[np.newaxis, :]
        if "attention_mask" in declared:
            feed["attention_mask"] = np.ones((1, row.shape[0]), dtype=np.int64)
        if "token_type_ids" in declared:
            feed["token_type_ids"] = np.zeros((1, row.shape[0]), dtype=np.int64)
        logits = np.asarray(session.run(None, feed)[0], dtype=np.float64)
        runs += 1
        shifted = logits - logits.max(axis=-1, keepdims=True)
        exp = np.exp(shifted)
        probs = exp / exp.sum(axis=-1, keepdims=True)
        best = max(best, float(probs[0, -1]))
    return best, runs


def test_pg_batched_score_matches_per_window_reference():
    """Old per-window loop and new batched run produce the SAME score on a
    multi-window payload with a mid-payload marker."""
    session = _RecordingSession()
    scanner = _scanner(session)
    # ~8000 tokens -> adaptive budget grows to 16 windows.
    text = "a" * 2000 + chr(250) + "b" * 6000
    batched = scanner._score(text)
    assert session.calls == 1
    reference, ref_runs = _reference_per_window_score(_RecordingSession(), session.feeds[0])
    assert ref_runs == session.feeds[0]["input_ids"].shape[0] == scanner.max_windows
    assert batched == reference


def test_pg_batched_score_matches_reference_grey_zone():
    """Grey-zone marker: identical score in the review band, per-window vs batched."""
    session = _RecordingSession()
    scanner = _scanner(session, review_threshold=0.5)
    text = "a" * 3000 + chr(249) + "b" * 3000
    batched = scanner._score(text)
    reference, _ = _reference_per_window_score(_RecordingSession(), session.feeds[0])
    assert batched == reference
    assert 0.5 <= batched < 0.9


def test_pg_batched_score_matches_reference_short_text():
    """Single short window: batch of one, identical to the old single run."""
    session = _RecordingSession()
    scanner = _scanner(session)
    batched = scanner._score("hello world")
    assert session.calls == 1
    assert session.feeds[0]["input_ids"].shape == (1, len("hello world"))
    reference, ref_runs = _reference_per_window_score(_RecordingSession(), session.feeds[0])
    assert ref_runs == 1
    assert batched == reference


@pytest.mark.asyncio
async def test_pg_batched_decisions_match_reference():
    """Decisions (ALLOW / HUMAN_REVIEW / BLOCK) are unchanged by batching."""
    cases = {
        "benign": ("a" * 5000, ScanOutcome.ALLOW),
        "grey": ("a" * 3000 + chr(249) + "b" * 3000, ScanOutcome.HUMAN_REVIEW),
        "malicious": ("a" * 2000 + chr(250) + "b" * 6000, ScanOutcome.BLOCK),
    }
    for label, (text, expected) in cases.items():
        session = _RecordingSession()
        scanner = _scanner(session, review_threshold=0.5)
        res = await scanner.scan(text, "tool")
        assert res.outcome is expected, label
        assert session.calls == 1, label
        # Same score the per-window reference computes -> same thresholds ->
        # same decision. (ALLOW results carry no score; the score-equality
        # proofs live in the _reference tests above.)
        reference, _ = _reference_per_window_score(_RecordingSession(), session.feeds[0])
        if expected is not ScanOutcome.ALLOW:
            assert res.score == reference, label


def test_pg_batched_feed_shape_and_dtypes():
    """The batched feed keeps the pinned-graph contract: (batch, seq) int64
    tensors, all-ones attention mask, zeros token_type_ids, seq == window."""
    session = _RecordingSession()
    scanner = _scanner(session)
    scanner._score("a" * 100000)
    assert session.calls == 1
    feed = session.feeds[0]
    assert feed["input_ids"].shape == (scanner.max_windows, scanner.window_tokens)
    assert feed["input_ids"].dtype.name == "int64"
    assert feed["attention_mask"].shape == (scanner.max_windows, scanner.window_tokens)
    assert feed["attention_mask"].dtype.name == "int64"
    assert feed["attention_mask"].all()
    assert feed["token_type_ids"].shape == (scanner.max_windows, scanner.window_tokens)
    assert feed["token_type_ids"].dtype.name == "int64"
    assert not feed["token_type_ids"].any()


def test_pg_batched_feed_respects_declared_inputs():
    """Exports that omit token_type_ids/attention_mask get only what they declare."""
    session = _RecordingSession(input_names=("input_ids",))
    scanner = _scanner(session)
    scanner._score("a" * 5000)
    assert session.calls == 1
    assert set(session.feeds[0]) == {"input_ids"}


def _pad_to_bytes(head: str, tail: str = "", total: int = _BAD631B3_BYTES) -> str:
    """Pad with benign single-byte filler to exactly ``total`` UTF-8 bytes."""
    fill = total - len(head.encode()) - len(tail.encode())
    assert fill >= 0
    return head + "a" * fill + tail


def test_pg_long_response_bad631b3_size_balanced_windows_benign():
    """A 42,649-byte benign response uses four full-coverage windows, each
    scored in one batched run capped at PG_MAX_WINDOWS rows."""
    session = _RecordingSession()
    scanner = _scanner(session)
    text = _pad_to_bytes("")
    assert len(text.encode()) == _BAD631B3_BYTES
    chunks, truncated = scan_windows(text, 32 * 1024, 11 * 1024)
    assert truncated is True
    assert len(chunks) == 4
    assert "".join(chunks) == text
    scores = [scanner._score(chunk) for chunk in chunks]
    assert max(scores) < 0.1
    assert session.calls == 4
    assert all(
        feed["input_ids"].shape[0] <= scanner.max_windows for feed in session.feeds
    )


@pytest.mark.parametrize("position", ["head", "middle", "tail"])
def test_pg_long_response_bad631b3_size_marker_controls(position):
    """Every marker position is detected across four full-coverage windows,
    with one batched inference per window."""
    session = _RecordingSession()
    scanner = _scanner(session)
    marker = chr(250)
    if position == "head":
        text = _pad_to_bytes(marker)
    elif position == "middle":
        text = _pad_to_bytes("a" * 6000 + marker)
    else:
        text = _pad_to_bytes("", tail=marker)
    assert len(text.encode()) == _BAD631B3_BYTES
    chunks, truncated = scan_windows(text, 32 * 1024, 11 * 1024)
    assert truncated is True
    assert len(chunks) == 4
    score = max(scanner._score(chunk) for chunk in chunks)
    assert score > 0.9, position
    assert session.calls == 4, position


@pytest.mark.asyncio
async def test_awarm_completes_full_response_windows_before_ready():
    """Readiness includes full-size response windows, not only model loading."""
    session = _RecordingSession()
    scanner = _scanner(session)
    engine = GuardrailEngine(
        GuardrailConfig(enable_redaction=False, scan_tail_bytes=11 * 1024),
        EngineComponents(
            response_scanners=[scanner],
            observability=Observability(audit_path="/dev/null"),
        ),
    )
    await engine.awarm()
    assert engine.ready is True
    # One empty scan plus four balanced full-response windows.
    assert session.calls == 4 + 1
    assert any(
        feed["input_ids"].shape[0] == scanner.max_windows for feed in session.feeds
    )
