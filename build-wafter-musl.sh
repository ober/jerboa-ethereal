#!/bin/bash
# build-wafter-musl.sh — Build wafter as a fully static binary using musl libc
#
# Prerequisites:
#   - musl-gcc installed (apt install musl-tools)
#   - Chez Scheme built with: ./configure --threads --static CC=musl-gcc
#     and installed to ~/chez-musl (or set JERBOA_MUSL_CHEZ_PREFIX)
#   - Jerboa libraries available
#
# The build uses stock scheme (glibc) for compilation steps,
# then musl-gcc for C compilation and linking.

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
echo "Building wafter-musl (static)"
echo "==================================="
echo ""
echo "Jerboa: $JERBOA_LIB"
echo ""

# ── Check musl availability ────────────────────────────────────────────────
if ! command -v musl-gcc &>/dev/null; then
    echo "ERROR: musl-gcc not found"
    echo "Install: sudo apt install musl-tools"
    exit 1
fi

echo "[1/2] Validating musl toolchain..."
echo "  musl-gcc: $(command -v musl-gcc)"
echo ""

echo "[2/2] Running musl build..."
scheme -q --libdirs "${SCRIPT_DIR}:${JERBOA_LIB}" --script build-wafter-musl.ss

# ── Verify ──────────────────────────────────────────────────────────────────
if [ -f "wafter-musl" ]; then
    echo ""
    echo "==================================="
    echo "wafter-musl built successfully!"
    echo "==================================="
    ls -lh wafter-musl
    echo ""
    file wafter-musl
    echo ""
    ldd wafter-musl 2>&1 || echo "  (Fully static — no dynamic dependencies)"
    echo ""
    echo "Test: ./wafter-musl --version"
else
    echo "ERROR: wafter-musl not created"
    exit 1
fi
