# jerboa-ethereal: Jerboa-Only Codebase

**CRITICAL CONVENTION**: This is a `jerboa-*` project, not a `chez-*` project.

## The Rule

```
┌─────────────────────────────────────────────────────┐
│ ✓ Write .ss files (Jerboa Scheme)                   │
│ ✓ Import (jerboa prelude)                           │
│ ✓ Use def, defstruct, match, etc                    │
│ ✓ Build system compiles .ss → .sls                  │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ ✗ NEVER write .sls files (Chez R6RS)                │
│ ✗ NEVER use (library ...) forms                     │
│ ✗ NEVER use (define ...) instead of def            │
│ ✗ NEVER commit .sls - generated only               │
└─────────────────────────────────────────────────────┘
```

---

## File Organization

### User-Facing Code (All .ss files)

```
dissectors/*.ss          ← Protocol implementations (Jerboa Scheme)
  ethereum.ss            ← def (dissect-ethernet buffer) ...
  ipv4.ss                ← def (dissect-ipv4 buffer) ...
  tcp.ss                 ← def (dissect-tcp buffer) ...
  ... (13 total)

lib/dissector/*.ss       ← Dissector infrastructure (Jerboa Scheme)
  registry.ss            ← Protocol registry
  pipeline.ss            ← Protocol chaining
  flows.ss               ← Connection tracking
  statistics.ss          ← Aggregation
  loader.ss              ← Dissector loading
  manifest.ss            ← Metadata about dissectors
  protocol.ss            ← Safe reading helpers (shared utilities)

tools/*.ss               ← CLI tools (Jerboa Scheme)
  wafter.ss              ← Main analyzer
  analysis.ss            ← Integrated analysis

lib/dsl/*.ss             ← DSL system (Jerboa Scheme)
  defprotocol.ss
  formatters.ss
  parser.ss
```

### Generated (NOT committed)

```
lib/dissector/*.sls      ← Generated: compiled from *.ss
dissectors/*.sls         ← Generated: compiled from *.ss
```

---

## Dissector Pattern

### ✗ WRONG (hand-written .sls)

```scheme
;; WRONG: Never write this
(library (dissectors ipv4)
  (export dissect-ipv4)
  (import (chezscheme) (jerboa prelude))
  (define (dissect-ipv4 buffer) ...))
```

### ✓ CORRECT (Jerboa .ss with inlined helpers)

```scheme
;; dissectors/ipv4.ss - Pure Jerboa Scheme

(import (jerboa prelude))

;; Inline helpers from lib/dissector/protocol.ss
(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

;; Actual dissector
(def (dissect-ipv4 buffer)
  "Parse IPv4 packet from bytevector"
  (try-result
    (let* ((b0-res (read-u8 buffer 0))
           (b0 (unwrap b0-res))
           (version (extract-bits b0 #xF0 4))
           ;; ... rest of dissection
           )
      ...)))
```

---

## Build Process (Phase 7)

### Step 1: Source → Bytecode

```
dissectors/ipv4.ss --[build system]--> lib/dissector/ipv4.sls
                        ↓
              (Chez compiler with jerboa prelude)
                        ↓
                    compiled bytecode
```

### Step 2: Static Binary

```
All .ss files compiled → .sls files
All .sls files → linked into static binary (wafter-musl)
Result: Single ELF executable with zero external deps
```

---

## What Jerboa Provides

When you write `(import (jerboa prelude))`, you get:

```scheme
;; Definitions
(def x val)
(def (f x y) body)
(defstruct name (fields ...))
(defmethod (name obj) body)

;; Pattern matching
(match value (pattern ...) ...)

;; Error handling
(try expr (catch (e) handler))
(ok val) (err msg) (ok? r) (unwrap r)

;; Iteration
(for ((x lst)) ...) (for/collect ((x lst)) ...)

;; Functional
(map f lst) (filter p lst) (reduce f init lst)

;; Strings
(str "a" "b" 42) (string-split str #\,)

;; Hash tables
(make-hash-table) (hash-put! h k v) (hash-ref h k)

;; ... and 100+ more functions
```

**You do NOT get**:
- `(define ...)` - use `def`
- `(library ...)` - use `.ss` files
- `(lambda ...)` - use `(lambda ...)` is fine, but prefer `(fn ...)` or inline
- Chez-specific syntax

---

## Protocol Helper Functions

Because Jerboa doesn't use library imports in .ss files, dissectors inline protocol helpers:

### lib/dissector/protocol.ss (Reference)

```scheme
(import (jerboa prelude))

(def (read-u8 buf offset) ...)
(def (read-u16be buf offset) ...)
(def (read-u32be buf offset) ...)
(def (read-u16le buf offset) ...)
(def (read-u32le buf offset) ...)
(def (slice buf offset len) ...)
(def (extract-bits val mask shift) ...)
(def (validate pred msg) ...)
(def (fmt-ipv4 addr) ...)
(def (fmt-mac bytes) ...)
(def (fmt-hex val) ...)
```

### Each dissector (Example: dissectors/ipv4.ss)

1. Import prelude: `(import (jerboa prelude))`
2. Inline needed helpers from protocol.ss
3. Define dissector: `(def (dissect-ipv4 buffer) ...)`

This is DRY enough - the helpers are short and stable, and dissectors only use a subset.

---

## Checking Your Code

Before committing:

```bash
# ✓ These are OK
find . -name "*.ss" | head

# ✗ SHOULD NOT EXIST (generated files, not committed)
find . -name "*.sls" -not -path "./build/*"

# ✓ VERIFY: All dissectors import (jerboa prelude)
grep "import (jerboa prelude)" dissectors/*.ss

# ✗ VERIFY: No dissectors use (library ...) or (define ...)
grep -r "^(library" dissectors/
grep "^(define " dissectors/
# ^ Both should be empty

# ✓ VERIFY: No hand-written .sls files
git ls-files | grep "\.sls$"
# ^ Should only show auto-generated, not in git
```

---

## Testing Code

**In interpreter** (for development):

```bash
# Load protocol helpers globally, then test
JERBOA_HOME=/path/to/jerboa scheme --libdirs lib --script dissectors/ipv4.ss
```

**In static binary** (Phase 7):

```bash
# All dissectors pre-compiled and linked
./wafter-musl capture.pcap stats
```

---

## Refactoring to Jerboa Convention

### If you find .sls files:

1. Delete them (they're generated, not source)
2. Convert to .ss equivalents
3. Remove `(library ...)` wrapper
4. Change `(define ` → `(def `
5. Add `(import (jerboa prelude))` at top

### Example: Converting protocol.sls → protocol.ss

**Before** (WRONG):
```scheme
(library (lib dissector protocol)
  (export read-u8 read-u16be ...)
  (import (chezscheme) (jerboa prelude))
  (define (read-u8 buf offset) ...))
```

**After** (CORRECT):
```scheme
;; lib/dissector/protocol.ss
(import (jerboa prelude))

(def (read-u8 buf offset) ...)
(def (read-u16be buf offset) ...)
;; ... other helpers
```

Dissectors then inline what they need.

---

## Why This Matters for Phase 7

The static binary build process:

1. **Source Phase**: All .ss files exist in git
2. **Compile Phase**: Build system compiles .ss → .sls (internal only)
3. **Link Phase**: Chez compiler links .sls into static binary
4. **Distribute Phase**: Users get single `wafter-musl` binary

**Key insight**: Users never see .sls files. The build system handles the compilation transparently.

---

## Questions?

- **"Can I use (library ...)"** → No. Use .ss files only.
- **"Can I import a .sls"** → No. Import (jerboa prelude) only, or inline helpers.
- **"Why not just use Chez?"** → Because Jerboa provides safer, cleaner syntax. Use what the language provides.
- **"When will .sls files be generated?"** → Phase 7, during the static binary build.

---

**Last Updated**: 2026-04-12  
**Status**: All dissectors fixed to follow convention  
**Next**: Update remaining dissectors to follow IPv4 pattern (inlined helpers)
