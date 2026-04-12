# Static Binary Build Plan

**Phase: Post-Phase 5** (after core dissection tools are complete)

Build fully static, zero-dependency Linux binaries for `ethereal` CLI using Docker + musl libc.

---

## Vision

Users can download a single `wafter-musl` binary and immediately:
```bash
$ ./wafter-musl dissect capture.pcap
$ ./wafter-musl search "GET" capture.pcap
$ ./wafter-musl edit capture.pcap --set ip.dst-ip 10.0.0.2 -o edited.pcap
```

No Chez Scheme installation, no Jerboa libraries, no libc version mismatches. Pure ELF binary.

---

## Architecture

### Two Build Paths

1. **Docker (Canonical)**: `make linux`
   - Reproducible builds
   - No host dependencies
   - CI-friendly
   - Can be automated (GitHub Actions, etc.)

2. **Local (Optional)**: `make linux-local`
   - For developers
   - Requires musl-gcc and musl-built Chez
   - Faster iteration

### Build Flow

```
[Source Code]
    ↓
[Phase 1: Compile all modules → .so/.wpo]
    ↓
[Phase 2: Generate C entry point]
    ↓
[Phase 3: C compilation + static linking]
    ↓
[Phase 4: Strip + verify + hash]
    ↓
[Final: wafter-musl (ELF binary)]
```

---

## Phase 1: Docker Setup

### Dockerfile

Based on `jerboa21/jerboa` base image (includes Chez + Jerboa + build tools).

```dockerfile
FROM jerboa21/jerboa AS builder

# Copy jerboa-ethereal source
COPY . /build/mine/jerboa-ethereal

# Build wafter-musl
WORKDIR /build/mine/jerboa-ethereal
RUN make linux-local

# Verify
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

# Output
FROM ubuntu:24.04
COPY --from=builder /build/mine/jerboa-ethereal/wafter-musl /out/wafter-musl
COPY --from=builder /build/mine/jerboa-ethereal/wafter-musl.sha256 /out/wafter-musl.sha256
CMD ["cat", "/out/wafter-musl"]
```

**Key points**:
- Multi-stage: compile in `jerboa21/jerboa`, extract to minimal `ubuntu:24.04`
- Verify in builder: binary works before extraction
- Extract via docker cp (no stdout needed)
- Hash for integrity verification

---

## Phase 2: Build Scripts

### `build-wafter-musl.sh`

Orchestrates the build process:

```bash
#!/bin/bash
# build-wafter-musl.sh — Build ethereal as a fully static binary

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Resolve Jerboa
JERBOA_LIB="${JERBOA_HOME:-${HOME}/mine/jerboa}/lib"
[ -d "$JERBOA_LIB" ] || { echo "ERROR: Cannot find Jerboa"; exit 1; }

# Check musl toolchain
command -v musl-gcc >/dev/null || { echo "ERROR: musl-gcc not found. Install: sudo apt install musl-tools"; exit 1; }

echo "[1/2] Validating musl toolchain..."
echo "  musl-gcc: $(command -v musl-gcc)"

echo "[2/2] Running musl build..."
scheme -q --libdirs "${SCRIPT_DIR}:${JERBOA_LIB}" --script build-wafter-musl.ss

# Verify
[ -f "wafter-musl" ] || { echo "ERROR: wafter-musl not created"; exit 1; }

echo ""
echo "=== wafter-musl built successfully! ==="
ls -lh wafter-musl
file wafter-musl
ldd wafter-musl 2>&1 || echo "  (Fully static — no dynamic dependencies)"
echo ""
echo "Test: ./wafter-musl --version"
```

### `build-wafter-musl.ss`

Chez Scheme build orchestrator (similar to gitsafe pattern):

```scheme
#!chezscheme
;; Build ethereal as a fully static binary using musl libc
;; This is a Chez script (not Jerboa) because it controls the build process.
;; See: JERBOA_ONLY.md exemption for build scripts.

(import (chezscheme))

;; [Steps from gitsafe adapted for ethereal]
;; 1. Locate musl Chez + Jerboa
;; 2. Compile all modules to .so/.wpo (optimize-level 3)
;; 3. Generate C entry point (ethereal-main.c)
;; 4. Invoke musl-gcc to compile C + link static
;; 5. Strip binary
;; 6. Generate SHA256 hash
```

**Why this is Chez, not Jerboa:**
- Build scripts must run in *stock* Chez (glibc)
- They invoke the Jerboa compiler but aren't user-facing code
- Exception to `JERBOA_ONLY.md` for build infrastructure

---

## Phase 3: Makefile Integration

Add targets to `Makefile`:

```makefile
# Static binary builds
.PHONY: linux linux-local docker verify-harden

# Build in Docker (canonical, reproducible)
linux: docker

# Build locally (requires musl-gcc + musl Chez)
linux-local:
	JERBOA_HOME=$(JERBOA_HOME) ./build-wafter-musl.sh

# Docker build
docker:
	docker build --platform linux/amd64 -t ethereal-builder .
	id=$$(docker create --platform linux/amd64 ethereal-builder) && \
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
```

---

## Phase 4: CLI Entry Point

### `tools/ethereal.ss` (Jerboa)

The main CLI tool that gets compiled into the binary:

```scheme
(import (jerboa prelude))

;; Command-line interface: ethereal dissect, search, edit, merge, split

(def (main args)
  (match args
    [("dissect" pcap-file)
     (dissect-pcap-file pcap-file)]
    [("search" pattern pcap-file)
     (search-pcap-file pattern pcap-file)]
    [("edit" pcap-file "--set" field-value "-o" output)
     (edit-and-save pcap-file field-value output)]
    ...
    [_ (show-help)]))

(main (vector->list (command-line)))
```

This Jerboa code is compiled to `.so`, then embedded in the static binary.

### `ethereal-main.c` (Generated)

Generated by `build-wafter-musl.ss`:

```c
/* Auto-generated by build process */

/* Chez runtime initialization */
void init_chez();

/* Main entry point */
int main(int argc, char** argv) {
    init_chez();                        /* Start Chez runtime */
    boot_from_embedded_image();         /* Load compiled libs */
    call_scheme_main(argc, argv);       /* Call (main ...) */
    return 0;
}
```

The actual dissectors/pcap/search/edit code is in `.so` files, loaded at startup.

---

## Phase 5: Build Workflow

### Local Development (no binary needed)

```bash
$ make test              # Test in interpreter (fast)
$ make build             # Compile to .so
```

### Before Release

```bash
$ make linux             # Build static binary via Docker
$ make verify-harden     # Verify hardening (stripped, no leaks, runs)
$ ./wafter-musl --version
$ ./wafter-musl dissect test-pcap.pcap  # Smoke test
```

---

## Phase 6: CI/CD Integration

### GitHub Actions Example

```yaml
name: Build Static Binary

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build wafter-musl
        run: make docker
      - name: Verify binary
        run: make verify-harden
      - name: Upload to release
        uses: actions/upload-release-asset@v1
        with:
          asset_path: ./wafter-musl
          asset_name: wafter-musl-x86_64
```

---

## Phase 7: Distribution & Verification

### Binary Artifacts

```
releases/
├── v1.0.0/
│   ├── wafter-musl                  # Executable binary
│   ├── wafter-musl.sha256           # Integrity hash
│   ├── wafter-musl.asc              # GPG signature (future)
│   └── CHECKSUMS                      # All hashes
```

### User Verification

```bash
$ curl -O https://github.com/.../releases/wafter-musl
$ curl -O https://github.com/.../releases/wafter-musl.sha256
$ sha256sum -c wafter-musl.sha256
$ chmod +x wafter-musl
$ ./wafter-musl --version
```

---

## Implementation Checklist

### Before Starting Phase (Phase 5 completion)

- [ ] `tools/ethereal.ss` is feature-complete (dissect, search, edit, etc.)
- [ ] All dissector modules compile to `.so`
- [ ] CLI works in interpreter mode: `make run`
- [ ] Test suite passes: `make test`

### Build Infrastructure

- [ ] Create `Dockerfile` (multi-stage, jerboa21/jerboa base)
- [ ] Create `build-wafter-musl.sh` (shell orchestrator)
- [ ] Create `build-wafter-musl.ss` (Chez build script)
- [ ] Create `ethereal-main.c` template (or generate dynamically)
- [ ] Add Makefile targets: `linux`, `linux-local`, `docker`, `verify-harden`

### Verification

- [ ] Build locally: `make linux-local` (requires musl-gcc, musl Chez)
- [ ] Build in Docker: `make docker`
- [ ] Verify binary: `make verify-harden`
  - [ ] Binary is stripped (no debug symbols)
  - [ ] No home directory paths leaked
  - [ ] SHA256 hash matches
  - [ ] Binary runs on target system (Ubuntu 24.04, etc.)

### CI/CD

- [ ] GitHub Actions workflow for tagged releases
- [ ] Automatic binary upload to releases
- [ ] SHA256 checksums published
- [ ] GPG signature support (optional, Phase 7+)

---

## Performance & Size

### Expectations

| Metric | Expected |
|--------|----------|
| Binary size | 30-50 MB (stripped) |
| Start time | < 1 sec (cold) |
| Dissection throughput | 100k+ packets/sec (Chez native compilation) |
| Startup dependency check | Instant (no external deps) |

### Optimization

If binary is too large:
- Use `strip -s` aggressively
- Compress with upx (optional, trade off portability)
- Lazy-load dissectors (load only for used protocols)
- Consider tree-shaking unused protocols

---

## Future Enhancements

### Phase 8+ (Optional)

1. **macOS static binary**
   - Similar pattern to Linux
   - Link against system frameworks statically
   - See `build-ethereal-macos.sh` pattern in gitsafe

2. **Windows static executable** (Low priority)
   - Different build process (Visual Studio or cross-compile)
   - Deferred to Phase 9+

3. **Incremental builds**
   - Cache compiled modules between builds
   - Only recompile changed source files

4. **Code signing**
   - GPG sign binaries for distribution
   - Verify signatures in CI/CD

5. **Release automation**
   - GitHub Actions releases on git tag
   - Auto-generate release notes from commits

---

## Notes & Assumptions

### Docker Base Image

Uses `jerboa21/jerboa` (community-maintained).
- Includes: Chez Scheme (stock + musl), Jerboa, build tools, musl-gcc
- Source: `docker pull jerboa21/jerboa`
- If unavailable, can build custom base image

### musl-built Chez

Required for static linking.
```bash
# One-time setup (outside jerboa-ethereal repo)
cd ~/chez-scheme
./configure --threads --static CC=musl-gcc
make install DESTDIR=~/chez-musl
```

Or use `JERBOA_MUSL_CHEZ_PREFIX` env var to override.

### Platform Support

Initial: Linux x86_64 (amd64) only
- Docker image: `--platform linux/amd64`
- Other platforms: macOS (Phase 8+), Windows (Phase 9+)

---

## Comparison: Local vs Docker

| Aspect | Local | Docker |
|--------|-------|--------|
| **Speed** | Fast (cached) | Slower (full rebuild) |
| **Setup** | musl-gcc, musl Chez | Docker only |
| **Reproducibility** | Depends on host | Guaranteed |
| **CI/CD** | Difficult | Easy |
| **Recommended for** | Developers | Releases, CI |

---

## See Also

- gitsafe build: `~/mine/jerboa-gitsafe/Dockerfile`, `build-gitsafe-musl.sh`
- Chez Scheme static build: https://github.com/ober/ChezScheme
- musl libc: https://www.musl-libc.org/
- JERBOA_ONLY.md: Exception for build scripts
