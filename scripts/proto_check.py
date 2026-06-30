#!/usr/bin/env python3
"""Proto stub sync check.

Regenerates the Python gRPC stubs from ``proto/ext_mcp.proto`` and compares
them against the committed stubs in ``proto/``.

Because ``grpcio-tools`` and ``protobuf`` emit slightly different *cosmetic*
output across versions — version stamps, ``class X(object):`` vs ``class X:``,
f-string vs plain-string literals — we **normalize** those cosmetic lines
before diffing. The check fails only when the SEMANTIC content (message
fields, service methods, oneof branches, RPC signatures) diverges from the
``.proto``.

This makes the check robust across patch/minor toolchain bumps while still
catching real contract drift — the property we actually care about for a
proto-check gate.

Usage::

    python scripts/proto_check.py
"""

from __future__ import annotations

import difflib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROTO_DIR = REPO / "proto"
PROTO_FILE = PROTO_DIR / "ext_mcp.proto"
COMMITTED = {
    "ext_mcp_pb2.py": PROTO_DIR / "ext_mcp_pb2.py",
    "ext_mcp_pb2_grpc.py": PROTO_DIR / "ext_mcp_pb2_grpc.py",
}


def normalize(text: str) -> list[str]:
    """Strip toolchain-version-dependent cosmetics from generated stub text.

    Returns a list of lines (``splitlines(keepends=True)``) suitable for
    :func:`difflib.unified_diff`.

    Order matters: the f-string -> plain-string normalization (step 1) MUST
    precede the version-string normalizations (steps 3-4), because older
    grpcio-tools emits some version literals as ``f'...'`` (no interpolation)
    and the version regexes match plain ``'...'`` only.
    """
    # 1. f-strings with no interpolation -> plain strings.
    #    Older grpcio-tools emits ``f'...'`` uniformly; newer emits ``'...'``
    #    for literals without ``{var}``. Normalize to plain FIRST so subsequent
    #    version-string regexes (which match ``'...'``) hit their targets.
    text = re.sub(r"f'([^'{}]*)'", r"'\1'", text)
    # 2. Protobuf gencode version stamp comment.
    text = re.sub(
        r"# Protobuf Python Version: [\d.]+",
        "# Protobuf Python Version: NORMALIZED",
        text,
    )
    # 3. _runtime_version.ValidateProtobufRuntimeVersion(..., MAJOR, MINOR, PATCH, ...)
    text = re.sub(
        r"_runtime_version\.ValidateProtobufRuntimeVersion\(\s*"
        r"_runtime_version\.Domain\.PUBLIC,\s*\d+,\s*\d+,\s*\d+,",
        "_runtime_version.ValidateProtobufRuntimeVersion(\n"
        "    _runtime_version.Domain.PUBLIC, 0, 0, 0,",
        text,
    )
    # 4. grpcio generated-version string.
    text = re.sub(
        r"GRPC_GENERATED_VERSION = '[\d.]+'",
        "GRPC_GENERATED_VERSION = 'NORMALIZED'",
        text,
    )
    # 5. Python-2-style ``class X(object):`` -> Python-3 ``class X:``.
    #    Newer grpcio-tools drops the ``(object)`` base; older keeps it.
    text = re.sub(r"^class (\w+)\(object\):", r"class \1:", text, flags=re.MULTILINE)
    return text.splitlines(keepends=True)


def regenerate(dest: Path) -> None:
    """Run grpc_tools.protoc to regenerate stubs into ``dest``."""
    subprocess.run(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            "-I",
            str(PROTO_DIR),
            f"--python_out={dest}",
            f"--grpc_python_out={dest}",
            str(PROTO_FILE),
        ],
        check=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td)
        regenerate(dest)
        diffs_found = False
        for name, committed_path in COMMITTED.items():
            if not committed_path.exists():
                print(f"Error: committed stub {committed_path} does not exist.", file=sys.stderr)
                return 1
            committed_norm = normalize(committed_path.read_text(encoding="utf-8"))
            generated_norm = normalize((dest / name).read_text(encoding="utf-8"))
            if committed_norm != generated_norm:
                diffs_found = True
                sys.stdout.writelines(
                    difflib.unified_diff(
                        committed_norm,
                        generated_norm,
                        fromfile=f"committed/{name} (normalized)",
                        tofile=f"generated/{name} (normalized)",
                    )
                )
        if diffs_found:
            print(
                "\nError: Committed proto stubs are semantically out of sync "
                "with proto/ext_mcp.proto.",
                file=sys.stderr,
            )
            print(
                "Error: Run 'make proto' locally and commit the regenerated files.",
                file=sys.stderr,
            )
            return 1
        print("Proto stubs are in sync (semantic check passed after normalization).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
