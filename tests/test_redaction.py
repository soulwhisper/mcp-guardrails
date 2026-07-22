"""Tests for the redaction / mutation pipeline (RedactionScanner + engine wiring)."""

from __future__ import annotations

import json

import pytest

from guardrails.aggregator import DecisionAggregator
from guardrails.config import GuardrailConfig
from guardrails.engine import EngineComponents, GuardrailEngine
from guardrails.models import FailureMode, HumanReviewMode, ScanResult
from guardrails.otel import Observability
from guardrails.proto_bridge import pb
from guardrails.redaction import RedactionScanner, default_redaction_patterns
from guardrails.scanners import RegexScanner, StubScanner
from guardrails.servicer import ExtMcpServicer
from tests.helpers import ScriptedScanner

AWS_KEY = "AKIA" + "B" * 16
GH_PAT = "ghp_" + "a" * 36
SLACK = "xoxb-" + "1234567890-abcdef"
EMAIL = "alice@example.com"
CC = "4111 1111 1111 1111"
PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n"
    "-----END PRIVATE KEY-----"
)


def _engine(components: EngineComponents, config: GuardrailConfig | None = None) -> GuardrailEngine:
    config = config or GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        max_content_bytes=4096,
        scanner_timeout_ms=500,
    )
    return GuardrailEngine(config, components)


def _response_engine(
    scanners, *, config: GuardrailConfig | None = None, observability=None
) -> GuardrailEngine:
    comps = EngineComponents(
        response_scanners=list(scanners),
        aggregator=DecisionAggregator(),
        observability=observability,
    )
    return _engine(comps, config)


# ---------------------------------------------------------------------------
# Pattern-level substitution
# ---------------------------------------------------------------------------


def test_redact_email():
    text, n = RedactionScanner().redact_text(f"contact {EMAIL} now")
    assert n == 1
    assert EMAIL not in text
    assert "[REDACTED:EMAIL]" in text


def test_redact_credit_card():
    text, n = RedactionScanner().redact_text(f"card {CC}")
    assert n == 1
    assert "4111" not in text
    assert "[REDACTED:CREDIT_CARD]" in text


def test_redact_aws_key():
    text, n = RedactionScanner().redact_text(f"key {AWS_KEY} leaked")
    assert n == 1
    assert AWS_KEY not in text
    assert "[REDACTED:AWS_ACCESS_KEY]" in text


@pytest.mark.parametrize("token,placeholder", [(GH_PAT, "GITHUB_PAT"), (SLACK, "SLACK_TOKEN")])
def test_redact_tokens(token, placeholder):
    text, n = RedactionScanner().redact_text(f"token {token}")
    assert n == 1
    assert token not in text
    assert f"[REDACTED:{placeholder}]" in text


def test_redact_private_key_block():
    text, n = RedactionScanner().redact_text(f"leaked:\n{PEM}\nend")
    assert n == 1
    assert "MIIBVwIBADAN" not in text
    assert "BEGIN PRIVATE KEY" not in text
    assert "[REDACTED:PRIVATE_KEY]" in text


def test_redact_truncated_private_key_header_only():
    text, n = RedactionScanner().redact_text("-----BEGIN RSA PRIVATE KEY-----\npartial")
    assert n == 1
    assert "BEGIN RSA PRIVATE KEY" not in text


def test_redact_multiple_hits_counted():
    text, n = RedactionScanner().redact_text(f"{EMAIL} and {EMAIL} and {AWS_KEY}")
    assert n == 3
    assert EMAIL not in text and AWS_KEY not in text


def test_redact_no_match_is_identity():
    redactor = RedactionScanner()
    text = "nothing sensitive here"
    assert redactor.redact_text(text) == (text, 0)


def test_default_patterns_cover_expected_types():
    names = {p.name for p in default_redaction_patterns()}
    assert {
        "email",
        "credit_card",
        "aws_access_key",
        "github_pat",
        "slack_token",
        "private_key",
    } <= names
    # hidden_ascii is deliberately NOT redactable (no meaningful replacement).
    assert "hidden_ascii" not in names


# ---------------------------------------------------------------------------
# Structural recursion
# ---------------------------------------------------------------------------


def test_redact_value_recurses_nested_structures():
    payload = {
        "content": [{"type": "text", "text": f"mail {EMAIL}"}],
        "nested": {"list": [f"key={AWS_KEY}", 42, None, {"deep": GH_PAT}]},
        "untouched": 3.14,
    }
    redacted, n = RedactionScanner().redact_value(payload)
    assert n == 3
    assert redacted["content"][0]["text"] == "mail [REDACTED:EMAIL]"
    assert redacted["nested"]["list"][0] == "key=[REDACTED:AWS_ACCESS_KEY]"
    assert redacted["nested"]["list"][1] == 42
    assert redacted["nested"]["list"][3]["deep"] == "[REDACTED:GITHUB_PAT]"
    assert redacted["untouched"] == 3.14
    # input is not mutated in place
    assert payload["content"][0]["text"] == f"mail {EMAIL}"


def test_redacted_value_is_valid_json_with_same_structure():
    payload = {"a": [EMAIL, {"b": AWS_KEY}], "c": {"d": CC}}
    redacted, n = RedactionScanner().redact_value(payload)
    assert n == 3
    dumped = json.dumps(redacted)
    reparsed = json.loads(dumped)

    def shape(v):
        if isinstance(v, dict):
            return {k: shape(x) for k, x in v.items()}
        if isinstance(v, list):
            return [shape(x) for x in v]
        return type(v).__name__

    assert shape(reparsed) == shape(payload)


# ---------------------------------------------------------------------------
# Engine wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_response_produces_mutated_decision():
    engine = _response_engine([StubScanner("stub")])
    result = {"content": [{"type": "text", "text": f"reach {EMAIL}"}], "isError": False}
    decision = await engine.check_response(
        method="tools/call", service_names=["svc"], result=result
    )
    assert not decision.deny
    assert decision.is_mutated
    mutated = decision.mutated
    assert mutated["content"][0]["text"] == "reach [REDACTED:EMAIL]"
    assert mutated["isError"] is False
    # mutated payload must round-trip as valid JSON with identical structure
    assert list(json.loads(json.dumps(mutated)).keys()) == list(result.keys())
    # audit marker in the reason
    assert "redaction:1 substitution(s)" in decision.reason


@pytest.mark.asyncio
async def test_check_response_no_hits_no_mutation():
    engine = _response_engine([StubScanner("stub")])
    decision = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": "all clean"}]},
    )
    assert not decision.deny
    assert not decision.is_mutated


@pytest.mark.asyncio
async def test_block_wins_over_redaction():
    """Payload carries a BLOCK-worthy hidden char AND a redactable email."""
    engine = _response_engine([RegexScanner()])
    decision = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": f"{EMAIL} ‮"}]},
    )
    assert decision.deny
    assert not decision.is_mutated


@pytest.mark.asyncio
async def test_human_review_suppresses_mutation():
    """REDACT_ON_REVIEW=0: HUMAN_REVIEW payloads pass+warn WITHOUT redaction
    (legacy behaviour — review semantics win)."""
    config = GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        max_content_bytes=4096,
        scanner_timeout_ms=500,
        redact_on_review=False,
    )
    engine = _response_engine(
        [ScriptedScanner("sus", [ScanResult.review("sus", "sketchy")])], config=config
    )
    decision = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": f"mail {EMAIL}"}]},
    )
    assert not decision.deny
    assert decision.human_review
    assert not decision.is_mutated


@pytest.mark.asyncio
async def test_human_review_still_redacts_by_default():
    """S-H3 / REDACT_ON_REVIEW=1 (default): a HUMAN_REVIEW payload keeps its
    review verdict AND is redacted — review-grade PII no longer passes
    through verbatim."""
    engine = _response_engine([ScriptedScanner("sus", [ScanResult.review("sus", "sketchy")])])
    decision = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": f"mail {EMAIL}"}]},
    )
    assert not decision.deny
    assert decision.human_review  # review semantics preserved
    assert decision.is_mutated  # ...and the payload is redacted
    text = decision.mutated["content"][0]["text"]
    assert EMAIL not in text
    assert "[REDACTED:EMAIL]" in text


@pytest.mark.asyncio
async def test_redaction_disabled_by_config():
    config = GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        enable_redaction=False,
    )
    engine = _response_engine([StubScanner("stub")], config=config)
    decision = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": f"mail {EMAIL}"}]},
    )
    assert not decision.is_mutated


@pytest.mark.asyncio
async def test_request_side_redaction_opt_in():
    config = GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        redact_request_params=True,
    )
    engine = _engine(
        EngineComponents(request_scanners=[StubScanner("stub")], aggregator=DecisionAggregator()),
        config,
    )
    decision = await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="send",
        params={"name": "send", "arguments": {"to": EMAIL, "body": "hi"}},
        headers={},
    )
    assert not decision.deny
    assert decision.is_mutated
    assert decision.mutated["arguments"]["to"] == "[REDACTED:EMAIL]"
    assert decision.mutated["name"] == "send"


@pytest.mark.asyncio
async def test_request_side_redaction_off_by_default():
    engine = _engine(
        EngineComponents(request_scanners=[StubScanner("stub")], aggregator=DecisionAggregator())
    )
    decision = await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="send",
        params={"name": "send", "arguments": {"to": EMAIL}},
        headers={},
    )
    assert not decision.is_mutated


# ---------------------------------------------------------------------------
# Config env wiring
# ---------------------------------------------------------------------------


def test_config_env_defaults(monkeypatch):
    monkeypatch.delenv("ENABLE_REDACTION", raising=False)
    monkeypatch.delenv("REDACT_REQUEST_PARAMS", raising=False)
    cfg = GuardrailConfig.from_env()
    assert cfg.enable_redaction is True
    assert cfg.redact_request_params is False


def test_config_env_disable(monkeypatch):
    monkeypatch.setenv("ENABLE_REDACTION", "0")
    monkeypatch.setenv("REDACT_REQUEST_PARAMS", "1")
    cfg = GuardrailConfig.from_env()
    assert cfg.enable_redaction is False
    assert cfg.redact_request_params is True


# ---------------------------------------------------------------------------
# Servicer + audit observability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_servicer_emits_mutated_oneof_bytes():
    engine = _response_engine([StubScanner("stub")])
    servicer = ExtMcpServicer(engine)
    result = {"content": [{"type": "text", "text": f"mail {EMAIL}"}]}
    req = pb.McpResponse(method="tools/call", mcp_response=json.dumps(result).encode())
    wire = await servicer.CheckResponse(req, None)
    assert wire.WhichOneof("result") == "mutated"
    decoded = json.loads(wire.mutated.decode())
    assert decoded == {
        "content": [{"type": "text", "text": "mail [REDACTED:EMAIL]"}],
    }


@pytest.mark.asyncio
async def test_audit_marks_mutation(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    obs = Observability(audit_path=str(audit_path))
    engine = _response_engine([StubScanner("stub")], observability=obs)
    await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": f"mail {EMAIL}"}]},
    )
    lines = [json.loads(line) for line in audit_path.read_text().splitlines()]
    span = next(rec for rec in lines if rec.get("event") == "guardrail.check_response")
    assert span["outcome"] == "mutated"
    assert span["redactions"] == 1
    assert "redaction:1 substitution(s)" in span["reason"]
    decision_rec = next(rec for rec in lines if rec.get("phase") == "response")
    assert decision_rec["outcome"] == "mutated"
    assert "redaction:" in decision_rec["reason"]


# ---------------------------------------------------------------------------
# Top-level result shapes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_response_top_level_string_result():
    engine = _response_engine([StubScanner("stub")])
    decision = await engine.check_response(
        method="tools/call", service_names=["svc"], result=f"ping {EMAIL}"
    )
    assert decision.is_mutated
    assert decision.mutated == "ping [REDACTED:EMAIL]"


@pytest.mark.asyncio
async def test_check_response_top_level_array_result():
    engine = _response_engine([StubScanner("stub")])
    decision = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result=[f"mail {EMAIL}", {"safe": "ok"}, 7],
    )
    assert decision.is_mutated
    assert decision.mutated == ["mail [REDACTED:EMAIL]", {"safe": "ok"}, 7]
    # round-trips as valid JSON
    assert json.loads(json.dumps(decision.mutated)) == decision.mutated


@pytest.mark.asyncio
async def test_request_side_arguments_as_embedded_json_string():
    """params.arguments may be a *string* of JSON; redacted as plain text."""
    config = GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        redact_request_params=True,
    )
    engine = _engine(
        EngineComponents(request_scanners=[StubScanner("stub")], aggregator=DecisionAggregator()),
        config,
    )
    decision = await engine.check_request(
        method="tools/call",
        service_names=["svc"],
        tool_name="send",
        params={"name": "send", "arguments": json.dumps({"to": EMAIL, "body": "hi"})},
        headers={},
    )
    assert not decision.deny
    assert decision.is_mutated
    # quoted string secret -> inner JSON stays valid after substitution
    inner = json.loads(decision.mutated["arguments"])
    assert inner == {"to": "[REDACTED:EMAIL]", "body": "hi"}


# ---------------------------------------------------------------------------
# Size cap + thread offload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oversized_payload_skips_redaction_with_audit_marker(tmp_path):
    config = GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        max_content_bytes=4096,
        scanner_timeout_ms=500,
        redaction_max_bytes=64,
    )
    audit_path = tmp_path / "audit.jsonl"
    obs = Observability(audit_path=str(audit_path))
    engine = _response_engine([StubScanner("stub")], config=config, observability=obs)
    big = f"mail {EMAIL} " + "x" * 256
    decision = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": big}]},
    )
    # over-cap payload passes through UNCHANGED — no mutation
    assert not decision.deny
    assert not decision.is_mutated
    lines = [json.loads(line) for line in audit_path.read_text().splitlines()]
    span = next(rec for rec in lines if rec.get("event") == "guardrail.check_response")
    assert span["redaction_skipped"] == "size"
    assert span["outcome"] == "allow"
    assert "redactions" not in span


@pytest.mark.asyncio
async def test_under_cap_payload_still_redacted():
    config = GuardrailConfig(
        failure_mode=FailureMode.FAIL_CLOSED,
        human_review_mode=HumanReviewMode.PASS,
        redaction_max_bytes=1024,
    )
    engine = _response_engine([StubScanner("stub")], config=config)
    decision = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": f"mail {EMAIL}"}]},
    )
    assert decision.is_mutated


@pytest.mark.asyncio
async def test_redaction_runs_off_event_loop():
    """The regex sweep must be awaited via asyncio.to_thread, not run inline."""
    import threading

    engine = _response_engine([StubScanner("stub")])
    loop_thread = threading.get_ident()
    seen_threads: list[int] = []
    real_redact_value = engine._redactor.redact_value

    def spy(value):
        seen_threads.append(threading.get_ident())
        return real_redact_value(value)

    engine._redactor.redact_value = spy
    decision = await engine.check_response(
        method="tools/call",
        service_names=["svc"],
        result={"content": [{"type": "text", "text": f"mail {EMAIL}"}]},
    )
    assert decision.is_mutated
    assert seen_threads and all(t != loop_thread for t in seen_threads)


@pytest.mark.asyncio
async def test_size_cap_config_env(monkeypatch):
    monkeypatch.setenv("REDACTION_MAX_BYTES", "4096")
    cfg = GuardrailConfig.from_env()
    assert cfg.redaction_max_bytes == 4096
    monkeypatch.delenv("REDACTION_MAX_BYTES")
    assert GuardrailConfig.from_env().redaction_max_bytes == 256 * 1024
