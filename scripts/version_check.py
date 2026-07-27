#!/usr/bin/env python3
"""Fail when version strings drift across release-facing files.

release-please updates ``pyproject.toml`` and ``.release-please-manifest.json``
automatically. This check makes sure the runtime-reported version, the default
container tag, and the Kubernetes deployment image stay in lockstep with those
release versions.

Usage::

    python scripts/version_check.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _extract(pattern: str, text: str, label: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    if not match:
        raise RuntimeError(f"could not find version in {label}")
    return match.group(1)


def collect_versions() -> dict[str, str]:
    pyproject = _extract(
        r'^version = "([^"]+)"',
        (REPO / "pyproject.toml").read_text(encoding="utf-8"),
        "pyproject.toml",
    )
    package = _extract(
        r'^__version__ = "([^"]+)"',
        (REPO / "guardrails" / "__init__.py").read_text(encoding="utf-8"),
        "guardrails/__init__.py",
    )
    manifest = json.loads((REPO / ".release-please-manifest.json").read_text(encoding="utf-8"))["."]
    makefile = _extract(
        r"^TAG \?= ([^\s#]+)",
        (REPO / "Makefile").read_text(encoding="utf-8"),
        "Makefile",
    )
    deployment = _extract(
        r"ghcr\.io/soulwhisper/mcp-guardrails:([^\s]+)",
        (REPO / "deploy" / "k8s" / "deployment.yaml").read_text(encoding="utf-8"),
        "deploy/k8s/deployment.yaml",
    )
    return {
        "pyproject.toml": pyproject,
        "guardrails/__init__.py": package,
        ".release-please-manifest.json": manifest,
        "Makefile TAG": makefile,
        "deploy/k8s image": deployment,
    }


def main() -> int:
    versions = collect_versions()
    expected = versions["pyproject.toml"]
    mismatched = {name: version for name, version in versions.items() if version != expected}
    if mismatched:
        print("Version consistency check failed:", file=sys.stderr)
        for name, version in versions.items():
            marker = "OK" if version == expected else "MISMATCH"
            print(f"  {marker:8} {name:35} {version}", file=sys.stderr)
        return 1
    print(f"OK: all release-facing versions are {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
