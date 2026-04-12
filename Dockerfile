# Dockerfile — Build ethereal-musl using the jerboa21/jerboa base image
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
#   docker build -t ethereal-builder .
#   id=$(docker create ethereal-builder)
#   docker cp $id:/out/ethereal-musl ./ethereal-musl
#   docker cp $id:/out/ethereal-musl.sha256 ./ethereal-musl.sha256
#   docker rm $id

FROM jerboa21/jerboa AS builder

# ── Copy jerboa-ethereal source ─────────────────────────────────────────────
COPY . /build/mine/jerboa-ethereal

# ── Build ethereal-musl ───────────────────────────────────────────────────────
WORKDIR /build/mine/jerboa-ethereal
RUN make linux-local

# ── Verify binary ───────────────────────────────────────────────────────────────
RUN ./ethereal-musl --version

RUN echo "--- Binary info ---" && \
    ls -lh ethereal-musl && \
    file ethereal-musl && \
    echo "--- Hardening checks ---" && \
    { file ethereal-musl | grep -qE 'stripped|no section header' && echo "  PASS: stripped" || echo "  FAIL: not stripped"; } && \
    { test -f ethereal-musl.sha256 && echo "  PASS: integrity hash present" || echo "  FAIL: no hash"; } && \
    echo "--- Path leak check ---" && \
    count=$(strings ethereal-musl | grep -c '/home/' || true) && \
    { [ "$count" -gt 0 ] && echo "  WARNING: home paths found ($count)" || echo "  PASS: no home path leaks"; }

# ── Output: minimal image with only the binary ──────────────────────────────────
FROM ubuntu:24.04
COPY --from=builder /build/mine/jerboa-ethereal/ethereal-musl /out/ethereal-musl
COPY --from=builder /build/mine/jerboa-ethereal/ethereal-musl.sha256 /out/ethereal-musl.sha256

# Minimal entrypoint to output binary
CMD ["cat", "/out/ethereal-musl"]
