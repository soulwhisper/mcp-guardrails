"""Redaction transformer — the mutation-producing stage of the pipeline.

Unlike the content scanners in :mod:`guardrails.scanners` (which return
:class:`ScanResult` verdicts), the :class:`RedactionScanner` is a pure
**transformer**: it rewrites secret / PII material in place, replacing each
match with a fixed ``[REDACTED:<TYPE>]`` placeholder, and reports the number
of substitutions made. It never BLOCKs — anything BLOCK-worthy (hidden
ASCII, format injection, private keys, tokens) is already denied by the
``RegexScanner`` upstream. Redaction only runs when every content scanner
allowed the exchange, so it is the defence-in-depth layer for the PII and
credentials that scanners deliberately do not hard-deny (emails are ALLOW,
credit cards are HUMAN_REVIEW-pass by default), plus a second chance to mask
block-grade secrets when the regex scanner is disabled.

The engine applies it **structurally**: it walks the params / result JSON
tree and rewrites only string values, so the mutated payload it hands to the
aggregator is guaranteed to be valid JSON with the same shape as the
original (only string contents change).

Known limitations (deliberate, documented for operators):

* **Mapping keys are not redacted.** Only *values* are rewritten; PII
  embedded in a string key survives. This keeps the output shape stable
  (rewriting keys could collide or break downstream lookups) and matches
  the scanner-side behaviour, which also extracts values, not keys.
* **Tuples become lists.** ``redact_value`` rebuilds every sequence as a
  ``list`` — correct for JSON-shaped payloads (the wire format has no
  tuple), but callers passing Python-native structures should not expect
  the tuple type to survive.
* **Request-side ``arguments`` as an embedded JSON string is redacted as
  plain text.** Some MCP clients encode ``params.arguments`` as a *string*
  containing JSON rather than a structured object. Redaction runs the
  plain-text substitution over that string; a secret that appears as an
  unquoted numeric literal (e.g. a credit-card-shaped number) is replaced
  by the ``[REDACTED:...]`` placeholder without surrounding quotes, which
  can invalidate the *inner* JSON document. The outer payload stays valid,
  and the response side is unaffected (``result`` is traversed
  structurally). Deployments with string-encoded arguments and numeric
  secrets should rely on the RegexScanner verdict instead.
* **The PEM-header fallback is best-effort.** ``_PRIVATE_KEY_HEADER``
  masks a truncated private-key block (BEGIN marker, no END in the
  scanned text). In practice this path rarely fires: with the RegexScanner
  enabled, any payload containing a BEGIN marker is already BLOCKed
  upstream, so redaction only sees PEM material when the regex scanner is
  disabled.

Zero dependencies — regexes are shared with :mod:`guardrails.scanners` so a
pattern tuned in one place applies to both verdicts and redactions.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .scanners import (
    _AWS_KEY,
    _AWS_TEMP_KEY,
    _CREDIT_CARD,
    _EMAIL,
    _GITHUB_PAT,
    _GITLAB_PAT,
    _GOOGLE_API_KEY,
    _LLM_API_KEY,
    _SLACK_TOKEN,
)

# Full PEM block (header .. footer). The RegexScanner only needs the BEGIN
# marker to BLOCK, but for redaction we want to mask the whole key body so no
# key material survives in the mutated payload.
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.DOTALL,
)
# Fallback when the block is truncated (no END marker in the scanned text).
# Best-effort: with the RegexScanner enabled a BEGIN marker is already
# BLOCKed upstream, so this only masks PEM material when the regex scanner
# is disabled and the payload is otherwise allowed through.
_PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")


@dataclass(frozen=True)
class RedactionPattern:
    """A named regex whose matches are replaced with ``[REDACTED:<NAME>]``."""

    name: str
    regex: re.Pattern[str]

    @property
    def placeholder(self) -> str:
        return f"[REDACTED:{self.name.upper()}]"


def default_redaction_patterns() -> list[RedactionPattern]:
    """Built-in redaction set.

    Ordered most-specific first (PEM block before bare header, block-grade
    secret shapes before generic PII). Patterns unsuitable for substitution
    (hidden ASCII — there is no meaningful replacement for a zero-width
    character — and the HUMAN_REVIEW-grade key=value / high-entropy /
    connection-string shapes, which are too false-positive-prone to rewrite
    blindly) are deliberately excluded; those remain BLOCK / review
    verdicts on the RegexScanner side.
    """
    return [
        RedactionPattern("private_key", _PRIVATE_KEY_BLOCK),
        RedactionPattern("private_key", _PRIVATE_KEY_HEADER),
        RedactionPattern("aws_access_key", _AWS_KEY),
        RedactionPattern("aws_temp_key", _AWS_TEMP_KEY),
        RedactionPattern("google_api_key", _GOOGLE_API_KEY),
        RedactionPattern("github_pat", _GITHUB_PAT),
        RedactionPattern("gitlab_pat", _GITLAB_PAT),
        RedactionPattern("slack_token", _SLACK_TOKEN),
        RedactionPattern("llm_api_key", _LLM_API_KEY),
        RedactionPattern("email", _EMAIL),
        RedactionPattern("credit_card", _CREDIT_CARD),
    ]


class RedactionScanner:
    """Regex-driven transformer that masks secrets/PII in text.

    Not a :class:`~guardrails.scanners.Scanner` — it produces no verdict,
    only rewritten text plus a hit count. The engine calls it after the
    content scanners have all ALLOWed the exchange.
    """

    name = "redaction"

    def __init__(self, patterns: Sequence[RedactionPattern] | None = None):
        self._patterns: list[RedactionPattern] = (
            list(patterns) if patterns is not None else default_redaction_patterns()
        )

    @property
    def patterns(self) -> tuple[RedactionPattern, ...]:
        return tuple(self._patterns)

    def redact_text(self, text: str) -> tuple[str, int]:
        """Return ``(redacted_text, substitutions)`` for a single string."""
        hits = 0
        for pat in self._patterns:
            text, n = pat.regex.subn(pat.placeholder, text)
            hits += n
        return text, hits

    def redact_value(self, value: Any) -> tuple[Any, int]:
        """Recursively redact every string in a JSON-shaped value.

        Returns ``(new_value, total_substitutions)``. Mappings, sequences and
        strings are rebuilt only when something changed; scalars pass through
        untouched. The output keeps the exact structure of the input, so
        ``json.dumps`` of the result is always valid when the input was.
        """
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, Mapping):
            total = 0
            out: dict[Any, Any] = {}
            for k, v in value.items():
                new_v, n = self.redact_value(v)
                total += n
                out[k] = new_v if n else v
            return out, total
        if isinstance(value, (list, tuple)):
            total = 0
            items: list[Any] = []
            for item in value:
                new_item, n = self.redact_value(item)
                total += n
                items.append(new_item if n else item)
            return items, total
        return value, 0
