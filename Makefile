.PHONY: build test clean help check linux linux-local docker verify-harden

help:
	@echo "jerboa-ethereal - Packet dissection system"
	@echo ""
	@echo "Development:"
	@echo "  make build         - Compile all Jerboa modules to .so"
	@echo "  make test          - Run test suite"
	@echo "  make check         - Run static checks (verify, lint, security)"
	@echo ""
	@echo "Static binary (Linux):"
	@echo "  make linux         - Build static binary via Docker (canonical)"
	@echo "  make linux-local   - Build static binary locally (requires musl-gcc)"
	@echo "  make docker        - Run Docker build directly"
	@echo "  make verify-harden - Verify binary hardening after build"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean         - Remove compiled artifacts"
	@echo ""
	@echo "See docs/BUILD_STATIC.md for static binary build details."

build:
	scheme --libdirs lib --script build.ss

test:
	scheme --libdirs lib --script test-runner.ss

check:
	@echo "Checking dissector DSL..."
	scheme --libdirs lib --script check.ss

clean:
	find lib -name "*.so" -delete
	find lib -name "*.wpo" -delete
	find . -name "*~" -delete
	rm -f ethereal-musl ethereal-musl.sha256

# ── Static Binary Builds (Linux) ────────────────────────────────────────────
# See docs/BUILD_STATIC.md for detailed documentation

JERBOA_HOME ?= $(realpath $(CURDIR)/../jerboa)

# Build in Docker (canonical, reproducible)
linux: docker

# Build locally (requires musl-gcc + musl-built Chez at ~/chez-musl)
linux-local:
	JERBOA_HOME=$(JERBOA_HOME) ./build-ethereal-musl.sh

# Docker build and extract
docker:
	@echo "=== Building ethereal-musl in Docker ==="
	docker build --platform linux/amd64 -t ethereal-builder .
	@id=$$(docker create --platform linux/amd64 ethereal-builder) && \
	docker cp $$id:/out/ethereal-musl ./ethereal-musl && \
	docker cp $$id:/out/ethereal-musl.sha256 ./ethereal-musl.sha256 && \
	docker rm $$id >/dev/null && \
	chmod +x ethereal-musl
	@echo ""
	@ls -lh ethereal-musl

# Verify binary hardening
verify-harden: linux
	@echo "=== Binary Hardening Verification ==="
	@(file ethereal-musl | grep -qE 'stripped|no section header') && echo "  PASS: binary is stripped" || echo "  FAIL: not stripped"
	@if strings ethereal-musl | grep -q "$(HOME)"; then echo "  WARN: home paths found"; else echo "  PASS: no home paths"; fi
	@[ -f ethereal-musl.sha256 ] && echo "  PASS: SHA256 hash exists" || echo "  FAIL: no hash"
	@./ethereal-musl --version >/dev/null 2>&1 && echo "  PASS: binary runs" || echo "  FAIL: doesn't run"

.DEFAULT_GOAL := help
