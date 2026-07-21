"""Minimal stdio MCP upstream server for agentgateway guardrails e2e tests.

Tools:
- echo: returns the input text unchanged.
- pii_leak: returns a payload containing test PII (email + phone) that the
  guardrail sidecar redacts in-flight (mutation path).
- secret_leak: returns an AWS-style access key, which the sidecar blocks
  outright (deny path on the response side).

Run with a python that has the `mcp` package installed (stdio transport).
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("agw-e2e-upstream")


@mcp.tool()
def echo(text: str) -> str:
    """Echo the input text back unchanged."""
    return text


@mcp.tool()
def pii_leak() -> str:
    """Return a document containing test PII (for guardrail redaction tests)."""
    return (
        "Customer record:\n"
        "  name: John Doe\n"
        "  email: jdoe@example.com\n"
        "  note: This is synthetic test data for guardrail e2e testing."
    )


@mcp.tool()
def secret_leak() -> str:
    """Return a document containing an AWS-style key (guardrail block tests)."""
    return " leaked aws_access_key_id: AKIAIOSFODNN7EXAMPLE (synthetic test data)"


if __name__ == "__main__":
    mcp.run()  # stdio transport
