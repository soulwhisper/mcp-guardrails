"""Default Invariant toxic-flow rule pack.

These rules are intentionally conservative and homelab-flavoured — they target
the highest-leverage exfiltration / privilege-escalation patterns that a
compromised agent could attempt once it has tool access. Override or extend by
mounting a custom rules module at ``INVARIANT_RULES_PATH`` (see
:mod:`guardrails.rules`).
"""

from __future__ import annotations

import re

from ..invariant import FlowStep, LoopRule, RateLimitRule, ToxicFlowRule

# Matches any address that does NOT end with a small set of internal suffixes.
# Used to flag "external" recipients in the inbox->email exfil pattern.
_EXTERNAL_EMAIL = re.compile(
    r"^[^@\s]+@(?!(internal\.local|corp\.local|example\.org)$)[^@\s]+\.[^@\s]+$"
)

RULES = [
    ToxicFlowRule(
        name="inbox-to-external-email",
        description="Read an inbox then send email to an external recipient (data exfiltration)",
        steps=[
            FlowStep(tool="inbox_read"),
            FlowStep(
                tool="email_send",
                args={"to": lambda v: isinstance(v, str) and bool(_EXTERNAL_EMAIL.search(v))},
            ),
        ],
    ),
    ToxicFlowRule(
        name="secret-read-then-exfil",
        description="Read a secret then push it to an external HTTP endpoint",
        steps=[
            # Matches tools like vault_read, k8s_secret_read, aws_secrets_get
            FlowStep(tool=re.compile(r"(secret|vault|kms)_?(read|get).*", re.IGNORECASE)),
            FlowStep(
                tool=re.compile(r"(http|curl|fetch|webhook).*post", re.IGNORECASE),
                args={
                    "url": re.compile(
                        r"^https?://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|.*\.svc\.cluster\.local)"
                    )
                },
            ),
        ],
    ),
    ToxicFlowRule(
        name="shell-read-then-k8s-apply",
        description="Run a shell command then apply a privileged k8s manifest (privilege escalation)",
        steps=[
            FlowStep(tool=re.compile(r"(shell|bash|exec|terminal).*", re.IGNORECASE)),
            FlowStep(
                tool=re.compile(r"(kubernetes|k8s|kubectl).*apply", re.IGNORECASE),
                args={
                    "manifest": lambda v: (
                        isinstance(v, str)
                        and any(
                            tok in v
                            for tok in ("cluster-admin", "privileged", "hostPath", "hostPID")
                        )
                    )
                },
            ),
        ],
    ),
    LoopRule(
        name="denied-tool-retry-loop",
        threshold=3,
        description="Same tool+args call repeated 3+ times in the window (injection retry loop)",
    ),
    # Volumetric backstop: any single tool called >30 times within 60s in one
    # trace key. Counting is per tool name (the wildcard does NOT pool all
    # tools into one budget). Deliberately conservative so normal agent
    # exploration stays well under the line — this catches enumeration /
    # spray behaviour, not bursty-but-sane plans.
    RateLimitRule(
        name="per-tool-rate-limit",
        tool="*",
        window_s=60.0,
        max_calls=30,
        description="Same tool called >30 times within 60s (volumetric abuse)",
    ),
]
