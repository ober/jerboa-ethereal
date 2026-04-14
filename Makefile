.PHONY: build test clean help check linux linux-local docker verify-harden status \
        qt-shim qt qt-offscreen qt-screenshot qt-repl \
        macos macos-local verify-harden-macos \
        native native-install

help:
	@echo "jerboa-ethereal - PCAP packet analyzer"
	@echo "════════════════════════════════════════════════════════"
	@echo ""
	@echo "Development:"
	@echo "  make build              - Compile all modules"
	@echo "  make test               - Run test suite"
	@echo "  make check              - Run static checks"
	@echo "  make status             - Show project status"
	@echo ""
	@echo "Qt GUI (wafter-qt):"
	@echo "  make qt-shim            - Build qt/tcp_repl_shim.so"
	@echo "  make qt                 - Launch Qt GUI (needs X11/Wayland)"
	@echo "  make qt-offscreen       - Launch Qt GUI headless"
	@echo "  make qt-screenshot      - Headless, save PNG to /tmp/wafter-snap.png"
	@echo "  make qt-repl            - Headless with auto-assigned TCP REPL"
	@echo "  make qt-screenshot-pcap PCAP=file.pcap OUT=/tmp/snap.png"
	@echo ""
	@echo "Static binary (Linux):"
	@echo "  make linux              - Build static binary via Docker"
	@echo "  make linux-local        - Build locally (requires musl-gcc)"
	@echo "  make docker             - Docker build"
	@echo "  make verify-harden      - Verify binary hardening"
	@echo ""
	@echo "macOS binary:"
	@echo "  make macos              - Build macOS binary (requires brew install chezscheme)"
	@echo "  make verify-harden-macos - Verify macOS binary"
	@echo ""
	@echo "Tools (TUI):"
	@echo "  scheme wafter.ss <pcap> stats"
	@echo "  scheme wafter.ss <pcap> list 10"
	@echo "  scheme wafter.ss <pcap> protocols"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean              - Remove artifacts"
	@echo ""
	@echo "See docs/BUILD_STATIC.md"

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
	@echo "    ✓ Static binary build (musl/Linux)"
	@echo "    ✓ macOS binary build"
	@echo "    ✓ Docker build system"
	@echo "    ✓ CI/CD integration"
	@echo "    - Performance benchmarking"
	@echo ""
	@echo "Code Statistics:"
	@echo "  - Dissectors ported from Wireshark: 1688"
	@echo "  - Additional hand-written dissectors: 4"
	@echo "  - Code reduction vs Wireshark: 75-90%"
	@echo ""

JERBOA_LIB_DEV ?= $(HOME)/mine/jerboa/lib

build:
	scheme --libdirs lib:$(JERBOA_LIB_DEV) --script build.ss

test:
	scheme --libdirs lib:$(JERBOA_LIB_DEV) --script test-phase2.ss

check:
	@echo "Checking dissector DSL..."
	scheme --libdirs lib:$(JERBOA_LIB_DEV) --script check.ss

# ── Local Rust native library ─────────────────────────────────────────────
# Builds native/src/{panic,pcap_capture}.rs → lib/libwafter_native.dylib (macOS)
# or lib/libwafter_native.so (Linux).  Required for live capture commands.

native:
	@echo "=== Building wafter-native (Rust pcap library) ==="
	cd native && cargo build --release
	@echo "=== Installing to lib/ ==="
	@if [ -f native/target/release/libwafter_native.dylib ]; then \
	  cp native/target/release/libwafter_native.dylib lib/libwafter_native.dylib; \
	  echo "  ✓ lib/libwafter_native.dylib"; \
	elif [ -f native/target/release/libwafter_native.so ]; then \
	  cp native/target/release/libwafter_native.so lib/libwafter_native.so; \
	  echo "  ✓ lib/libwafter_native.so"; \
	fi

native-install: native

clean:
	find lib -name "*.so" -delete
	find lib -name "*.wpo" -delete
	find . -name "*~" -delete
	rm -f wafter-musl wafter-musl.sha256
	rm -f wafter-macos wafter-macos.sha256
	rm -f lib/libwafter_native.dylib lib/libwafter_native.so
	rm -f qt/tcp_repl_shim.so qt/libqt_shim.so

# ── macOS Binary Build ───────────────────────────────────────────────────────
# Requires: Chez Scheme (brew install chezscheme) + Xcode Command Line Tools
# Produces: ./wafter-macos (dynamically linked against libSystem.dylib only)

# Build macOS binary locally (no Docker needed)
macos: macos-local

macos-local: native
	./build-wafter-macos.sh

# Verify macOS binary
verify-harden-macos: macos
	@echo "=== macOS Binary Verification ==="
	@file wafter-macos
	@echo ""
	@otool -L wafter-macos
	@echo ""
	@[ -f wafter-macos.sha256 ] && echo "  PASS: SHA256 hash exists" || echo "  FAIL: no hash"
	@./wafter-macos --version >/dev/null 2>&1 && echo "  PASS: binary runs" || echo "  FAIL: doesn't run"

# ── Static Binary Builds (Linux) ────────────────────────────────────────────
# See docs/BUILD_STATIC.md for detailed documentation

JERBOA_HOME ?= $(realpath $(CURDIR)/../jerboa)

# Build in Docker (canonical, reproducible)
linux: docker

# Build locally (requires musl-gcc + musl-built Chez at ~/chez-musl)
linux-local:
	JERBOA_HOME=$(JERBOA_HOME) ./build-wafter-musl.sh

# Docker build and extract
docker:
	@echo "=== Building wafter-musl in Docker ==="
	docker build --platform linux/amd64 -t ethereal-builder .
	@id=$$(docker create --platform linux/amd64 ethereal-builder) && \
	docker cp $$id:/out/wafter-musl ./wafter-musl && \
	docker cp $$id:/out/wafter-musl.sha256 ./wafter-musl.sha256 && \
	docker rm $$id >/dev/null && \
	chmod +x wafter-musl
	@echo ""
	@ls -lh wafter-musl

# Verify binary hardening
verify-harden: linux
	@echo "=== Binary Hardening Verification ==="
	@(file wafter-musl | grep -qE 'stripped|no section header') && echo "  PASS: binary is stripped" || echo "  FAIL: not stripped"
	@if strings wafter-musl | grep -q "$(HOME)"; then echo "  WARN: home paths found"; else echo "  PASS: no home paths"; fi
	@[ -f wafter-musl.sha256 ] && echo "  PASS: SHA256 hash exists" || echo "  FAIL: no hash"
	@./wafter-musl --version >/dev/null 2>&1 && echo "  PASS: binary runs" || echo "  FAIL: doesn't run"

# ── Qt GUI (wafter-qt) ───────────────────────────────────────────────────────
# Requires: chez-qt at ~/mine/chez-qt and Qt6 dev libraries.
# libqt_shim.so is compiled from jerboa-emacs/vendor/qt_shim.cpp — it provides
# the modern threading model (qt_application_is_running) used by chez-qt.

CHEZ_QT_DIR   ?= $(HOME)/mine/chez-qt
JEMACS_VENDOR ?= $(HOME)/mine/jerboa-emacs/vendor
QT_INC        ?= /usr/include/x86_64-linux-gnu/qt6

QT_ENV = \
	CHEZ_QT_LIB=$(CHEZ_QT_DIR) \
	CHEZ_QT_SHIM_DIR=qt \
	LD_PRELOAD=$(CHEZ_QT_DIR)/qt_chez_shim.so \
	LD_LIBRARY_PATH=qt:$(CHEZ_QT_DIR):$(LD_LIBRARY_PATH)

JERBOA_LIB ?= $(HOME)/mine/jerboa/lib
QT_SCHEME = scheme --libdirs $(CHEZ_QT_DIR):$(JERBOA_LIB):lib

# Build both shims into qt/
qt-shim: qt/tcp_repl_shim.so qt/libqt_shim.so

qt/tcp_repl_shim.so: qt/tcp_repl_shim.c
	gcc -shared -fPIC -O2 -o qt/tcp_repl_shim.so qt/tcp_repl_shim.c

qt/libqt_shim.so: $(JEMACS_VENDOR)/qt_shim.cpp
	g++ -shared -fPIC -std=c++17 -O2 \
	  -DJEMACS_CHEZ_SMP \
	  -I$(JEMACS_VENDOR) \
	  -I$(QT_INC) -I$(QT_INC)/QtCore -I$(QT_INC)/QtGui -I$(QT_INC)/QtWidgets \
	  $(JEMACS_VENDOR)/qt_shim.cpp \
	  -o qt/libqt_shim.so \
	  -lQt6Core -lQt6Gui -lQt6Widgets -lvterm -lutil

# Interactive Qt window (requires X11 or Wayland)
qt: qt-shim
	$(QT_ENV) QT_QPA_PLATFORM=xcb \
	$(QT_SCHEME) --script wafter-qt.ss

# Headless (no display needed — offscreen renderer)
qt-offscreen: qt-shim
	$(QT_ENV) QT_QPA_PLATFORM=offscreen \
	$(QT_SCHEME) --script wafter-qt.ss

# Save screenshot to /tmp/wafter-snap.png then exit (for automated review)
qt-screenshot: qt-shim
	$(QT_ENV) QT_QPA_PLATFORM=offscreen \
	$(QT_SCHEME) --script wafter-qt.ss --screenshot /tmp/wafter-snap.png
	@echo ""
	@echo "Screenshot: /tmp/wafter-snap.png"

# Load a specific pcap and screenshot it
# Usage: make qt-screenshot-pcap PCAP=/path/to/file.pcap OUT=/tmp/snap.png
qt-screenshot-pcap: qt-shim
	$(QT_ENV) QT_QPA_PLATFORM=offscreen \
	$(QT_SCHEME) --script wafter-qt.ss --screenshot $(OUT) $(PCAP)
	@echo "Screenshot: $(OUT)"

# Launch headless with auto-assigned REPL for LLM debugging
# After launch: nc localhost <port printed on stdout>
qt-repl: qt-shim
	$(QT_ENV) QT_QPA_PLATFORM=offscreen \
	$(QT_SCHEME) --script wafter-qt.ss --repl 0

.DEFAULT_GOAL := help
