"""Hypothesis property tests for the pure policy core.

Invariants that must hold for ANY input:

* ``scan_windows`` — chunks are always valid UTF-8-decodable strings (they
  are ``str`` already, but every chunk must re-encode to a byte slice of the
  original), cover head (and tail when over budget), and the ``truncated``
  flag must agree with the payload/budget sizes.
* ``extract_text`` — never raises on arbitrary JSON-able structures and
  always returns a ``str``.
* ``servicer._safe_json_loads`` — never raises on arbitrary bytes; it
  returns ``(value, "")`` or ``(None, error)``.
* ``RedactionScanner.redact_value`` — preserves structure (only string
  values may change) and the output stays JSON-serialisable whenever the
  input was.

Hypothesis is a dev-only dependency; the whole module skips gracefully when
it is not installed.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

hypothesis = pytest.importorskip("hypothesis", reason="hypothesis not installed (dev extra)")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from guardrails.redaction import RedactionScanner  # noqa: E402
from guardrails.scanners import extract_text, scan_windows  # noqa: E402
from guardrails.servicer import _safe_json_loads  # noqa: E402

JSON_SCALARS = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text()
)
JSON_VALUES = st.recursive(
    JSON_SCALARS,
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(st.text(max_size=8), children, max_size=5)
    ),
    max_leaves=25,
)

_MAX_EXAMPLES = 60


# ---------------------------------------------------------------------------
# scan_windows
# ---------------------------------------------------------------------------


@given(
    text=st.text(),
    max_bytes=st.integers(min_value=1, max_value=4096),
    tail_bytes=st.integers(min_value=0, max_value=1024),
)
@settings(max_examples=_MAX_EXAMPLES)
def test_scan_windows_properties(text: str, max_bytes: int, tail_bytes: int) -> None:
    chunks, truncated = scan_windows(text, max_bytes, tail_bytes)

    assert chunks, "scan_windows must always return at least one chunk"
    # Every chunk is a str that re-encodes cleanly (UTF-8-safe splits).
    encoded = text.encode("utf-8", errors="ignore")
    for chunk in chunks:
        assert isinstance(chunk, str)
        chunk.encode("utf-8")  # must not raise

    total = len(encoded)
    if total <= max_bytes:
        # In-budget: single chunk, no truncation, head is the whole text.
        assert truncated is False
        assert chunks == [text]
    else:
        assert truncated is True
        # Head window covers the (UTF-8-safe) payload prefix.
        head_bytes = chunks[0].encode("utf-8", errors="ignore")
        assert encoded[: len(head_bytes)] == head_bytes
        assert len(head_bytes) <= max_bytes
        if tail_bytes > 0:
            # Tail coverage: the UTF-8-safe suffix window is either scanned
            # as its own chunk or coincides with an already-returned chunk.
            exp_tail = encoded[-tail_bytes:].decode("utf-8", errors="ignore")
            if exp_tail and exp_tail != chunks[0]:
                assert exp_tail in chunks
            if len(chunks) > 1:
                last = chunks[-1].encode("utf-8", errors="ignore")
                assert encoded.endswith(last) or last in encoded


# ---------------------------------------------------------------------------
# extract_text
# ---------------------------------------------------------------------------


@given(payload=JSON_VALUES)
@settings(max_examples=_MAX_EXAMPLES)
def test_extract_text_never_raises(payload: Any) -> None:
    out = extract_text(payload)
    assert isinstance(out, str)


# ---------------------------------------------------------------------------
# _safe_json_loads
# ---------------------------------------------------------------------------


@given(raw=st.binary())
@settings(max_examples=_MAX_EXAMPLES)
def test_safe_json_loads_never_raises(raw: bytes) -> None:
    value, error = _safe_json_loads(raw)
    if error:
        assert value is None
    else:
        # Successful parse: re-serialisable JSON.
        json.dumps(value, default=str)


@given(raw=st.binary(), allow_absent=st.booleans())
@settings(max_examples=_MAX_EXAMPLES)
def test_safe_json_loads_allow_absent(raw: bytes, allow_absent: bool) -> None:
    value, error = _safe_json_loads(raw, allow_absent=allow_absent)
    if not raw and allow_absent:
        assert value == {} and error == ""
    elif error:
        assert value is None


# ---------------------------------------------------------------------------
# redact_value
# ---------------------------------------------------------------------------


def _shape(value: Any) -> Any:
    """Structural fingerprint: containers recurse, leaves keep only type."""
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_shape(v) for v in value]
    return type(value).__name__


@given(value=JSON_VALUES)
@settings(max_examples=_MAX_EXAMPLES)
def test_redact_value_preserves_structure(value: Any) -> None:
    redacted, n = RedactionScanner().redact_value(value)
    assert isinstance(n, int) and n >= 0
    # Structure (keys, list lengths, leaf types) is preserved — only string
    # VALUES may differ (replaced by [REDACTED:<TYPE>] placeholders).
    assert _shape(redacted) == _shape(value)
    # Output stays JSON-serialisable whenever the input was.
    json.dumps(redacted)
