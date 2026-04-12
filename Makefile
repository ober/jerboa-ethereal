.PHONY: build test clean help check linux linux-local docker verify-harden status

help:
	@echo "jerboa-ethereal - PCAP packet analyzer"
	@echo "════════════════════════════════════════════════════════"
	@echo "Phase 6 Complete: 13 protocols, full DNS, flows, statistics"
	@echo "Phase 7 In Progress: Static binary, Docker, advanced features"
	@echo ""
	@echo "Development:"
	@echo "  make build         - Compile all modules"
	@echo "  make test          - Run test suite"
	@echo "  make check         - Run static checks"
	@echo "  make status        - Show project status"
	@echo ""
	@echo "Static binary (Linux, Phase 7):"
	@echo "  make linux         - Build static binary via Docker"
	@echo "  make linux-local   - Build locally (requires musl-gcc)"
	@echo "  make docker        - Docker build"
	@echo "  make verify-harden - Verify binary hardening"
	@echo ""
	@echo "Tools:"
	@echo "  scheme wafter.ss <pcap> stats"
	@echo "  scheme wafter.ss <pcap> list 10"
	@echo "  scheme wafter.ss <pcap> protocols"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean         - Remove artifacts"
	@echo ""
	@echo "See docs/BUILD_STATIC.md and docs/IMPLEMENTATION_ROADMAP.md"

status:
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "jerboa-ethereal - PCAP Packet Analyzer"
	@echo "═══════════════════════════════════════════════════════════════"
	@echo ""
	@echo "Phase 6: Extended Protocols & Features ✓ COMPLETE"
	@echo "  Dissectors:"
	@echo "    ✓ Ethernet, IPv4, IPv6, ARP, TCP, UDP"
	@echo "    ✓ ICMP, ICMPv6, IGMP"
	@echo "    ✓ DNS (with RFC 1035 decompression)"
	@echo "    ✓ DHCP, NTP, SSH"
	@echo "  Features:"
	@echo "    ✓ Flow analysis module"
	@echo "    ✓ Statistics aggregation"
	@echo "    ✓ Tool renamed: ethereal → wafter"
	@echo ""
	@echo "Phase 7: Production Tools & Static Binary (In Progress)"
	@echo "  Tasks:"
	@echo "    - Static binary build (musl)"
	@echo "    - Docker build system"
	@echo "    - Performance benchmarking"
	@echo "    - CI/CD integration"
	@echo ""
	@echo "Code Statistics:"
	@echo "  - Total protocols: 13"
	@echo "  - Lines of Scheme: ~2500"
	@echo "  - Code reduction vs Wireshark: 75-90%"
	@echo ""

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
