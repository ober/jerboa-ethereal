#!/bin/bash
# build-wafter-macos.sh — Build wafter as a macOS binary
#
# Prerequisites:
#   - Chez Scheme: brew install chezscheme
#   - Xcode Command Line Tools: xcode-select --install
#   - Jerboa libraries: sibling ../jerboa or JERBOA_HOME set
#
# The build compiles Scheme modules with WPO, then links the Chez
# runtime libraries (libkernel.a, liblz4.a, libz.a) into a macOS
# binary. No Chez install required at runtime.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Resolve Jerboa ──────────────────────────────────────────────────────────
if [ -n "${JERBOA_HOME:-}" ]; then
    JERBOA_LIB="${JERBOA_HOME}/lib"
elif [ -d "${SCRIPT_DIR}/../jerboa/lib" ]; then
    JERBOA_LIB="$(realpath "${SCRIPT_DIR}/../jerboa/lib")"
elif [ -d "${HOME}/mine/jerboa/lib" ]; then
    JERBOA_LIB="${HOME}/mine/jerboa/lib"
else
    echo "ERROR: Cannot find Jerboa. Set JERBOA_HOME."
    exit 1
fi
export JERBOA_HOME="${JERBOA_HOME:-$(dirname "$JERBOA_LIB")}"

echo "==================================="
echo "Building wafter-macos"
echo "==================================="
echo ""
echo "Jerboa: $JERBOA_LIB"
echo ""

# ── Check prerequisites ────────────────────────────────────────────────────
if ! command -v scheme &>/dev/null; then
    echo "ERROR: Chez Scheme not found"
    echo "Install: brew install chezscheme"
    exit 1
fi

if ! command -v cc &>/dev/null; then
    echo "ERROR: cc not found"
    echo "Install: xcode-select --install"
    exit 1
fi

echo "[1/2] Validating toolchain..."
echo "  scheme: $(command -v scheme)"
echo "  cc:     $(command -v cc)"
echo "  Chez version: $(scheme --version 2>&1 || true)"
echo ""

echo "[2/2] Running macOS build..."
scheme -q --libdirs "${SCRIPT_DIR}:${JERBOA_LIB}" --script build-wafter-macos.ss

# ── Verify ──────────────────────────────────────────────────────────────────
if [ -f "wafter-macos" ]; then
    echo ""
    echo "==================================="
    echo "wafter-macos built successfully!"
    echo "==================================="
    ls -lh wafter-macos
    echo ""
    file wafter-macos
    echo ""
    otool -L wafter-macos 2>/dev/null || true
    echo ""
    echo "Test: ./wafter-macos --version"
else
    echo "ERROR: wafter-macos not created"
    exit 1
fi
