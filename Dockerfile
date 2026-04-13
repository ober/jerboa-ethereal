# Dockerfile — Build wafter-musl using the jerboa21/jerboa base image
#
# Produces a fully static binary with zero runtime dependencies.
# No Chez Scheme or Jerboa installation needed on the target host.
#
# The base image (jerboa21/jerboa) provides:
#   - Stock Chez Scheme (glibc)
#   - musl-built Chez Scheme (for static linking)
#   - Jerboa libraries
#   - Build dependencies (musl-gcc, etc.)
#
# Usage:
#   make linux          # Build via Docker (canonical)
#   make linux-local    # Build directly on host (requires musl-gcc)
#
# Or manually:
#   docker build -t wafter-builder .
#   id=$(docker create wafter-builder)
#   docker cp $id:/out/wafter-musl ./wafter-musl
#   docker cp $id:/out/wafter-musl.sha256 ./wafter-musl.sha256
#   docker rm $id

FROM jerboa21/jerboa AS builder

# ── Copy source ─────────────────────────────────────────────────────────────
COPY . /build/mine/jerboa-ethereal

# ── Build wafter-musl ────────────────────────────────────────────────────────
WORKDIR /build/mine/jerboa-ethereal
RUN make linux-local

# ── Smoke test ───────────────────────────────────────────────────────────────
RUN ./wafter-musl --version

RUN echo "--- Binary info ---" && \
    ls -lh wafter-musl && \
    file wafter-musl && \
    echo "--- Hardening checks ---" && \
    { file wafter-musl | grep -qE 'stripped|no section header' && echo "  PASS: stripped" || echo "  FAIL: not stripped"; } && \
    { test -f wafter-musl.sha256 && echo "  PASS: integrity hash present" || echo "  FAIL: no hash"; } && \
    echo "--- Path leak check ---" && \
    count=$(strings wafter-musl | grep -c '/home/' || true) && \
    { [ "$count" -gt 0 ] && echo "  WARNING: home paths found ($count)" || echo "  PASS: no home path leaks"; }

# ── Output: minimal image with only the binary ──────────────────────────────────
FROM ubuntu:24.04
COPY --from=builder /build/mine/jerboa-ethereal/wafter-musl /out/wafter-musl
COPY --from=builder /build/mine/jerboa-ethereal/wafter-musl.sha256 /out/wafter-musl.sha256

# Minimal entrypoint to output binary
CMD ["cat", "/out/wafter-musl"]
