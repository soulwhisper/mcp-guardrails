#!/usr/bin/env bash
# gen_sbom.sh — generate SPDX + CycloneDX SBOMs for the sidecar image (or
# the source tree) with syft.
#
# Usage:
#   ./scripts/gen_sbom.sh                 # SBOM of the local source tree
#   IMAGE=ghcr.io/soulwhisper/mcp-guardrails:0.3.5 ./scripts/gen_sbom.sh
#                                         # SBOM of a built container image
#
# Output: sbom/spdx.json + sbom/cyclonedx.json (gitignored artifacts).
#
# Requires syft (https://github.com/anchore/syft):
#   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
#
# CI note: wiring this into a GitHub workflow (generate on release, attach
# to the release assets, sign with cosign) is intentionally NOT done here —
# it needs a workflow token with `packages:write` / release-asset scope,
# which is an org-level decision. The script is the CI-ready entrypoint:
# `IMAGE=<built image> ./scripts/gen_sbom.sh` then upload sbom/*.
set -euo pipefail

IMAGE="${IMAGE:-}"
OUT_DIR="${OUT_DIR:-sbom}"

if ! command -v syft >/dev/null 2>&1; then
    echo "error: syft not found on PATH." >&2
    echo "install: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

if [ -n "$IMAGE" ]; then
    SOURCE="$IMAGE"
else
    # Directory scan of the source tree (no image build required).
    SOURCE="dir:."
fi

echo "generating SBOMs for ${SOURCE} -> ${OUT_DIR}/"
syft "$SOURCE" -o "spdx-json=${OUT_DIR}/spdx.json"
syft "$SOURCE" -o "cyclonedx-json=${OUT_DIR}/cyclonedx.json"
echo "wrote ${OUT_DIR}/spdx.json and ${OUT_DIR}/cyclonedx.json"
