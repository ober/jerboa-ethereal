# ⚠️ JERBOA ONLY — No Chez, No .sls Files

This project is **100% Jerboa Scheme**. All user-facing code is `.ss` files.

## Rules

1. **All files are `.ss` (Jerboa source)**
   - Never write `.sls` files (those are Chez internals, not user code)
   - Never use `(library ...)` forms
   - Never expose `(chezscheme)` or Chez-specific APIs

2. **Always start with:**
   ```scheme
   (import (jerboa prelude))
   ```
   This gives you the entire Jerboa language in one import.

3. **Use Jerboa syntax:**
   ```scheme
   ;; Definitions
   (def x 42)
   (def (f x y) (+ x y))
   (def (f x (y 10)) body)          ;; optional params
   (def (f x . rest) body)           ;; rest args
   (def* f ((x) ...) ((x y) ...))    ;; multi-arity

   ;; Operators
   [...]                → (...)      brackets = parens
   {obj method args}    → (~ obj 'method args)
   name:                → #:name     keywords
   :std/sort            → (std sort) module paths

   ;; Control
   (try expr (catch (e) handler) (finally cleanup))
   (for ((x (in-range 5))) (displayln x))
   (match value (pat body) ...)
   (cond [test expr] ...)
   ```

4. **Available from prelude:**
   - Core types: structs, classes, records
   - Data: lists, hashes, strings, regex, JSON, CSV
   - I/O: files, ports, display, formatting
   - Functional: map, filter, fold, compose, partial
   - Concurrency: actors, async/await (via `(std ...)` imports)
   - See `(jerboa prelude)` exports for full list

5. **What's NOT available without extra imports:**
   - `(std net request)` — HTTP client
   - `(std net httpd)` — HTTP server
   - `(std db sqlite)` — SQLite
   - `(std actor)` — Actor system
   - `(std crypto digest)` — Hashing
   - `(std async)` — Async/await

6. **Never:**
   - ~~`(library ...)` blocks~~
   - ~~`#!chezscheme` pragmas~~
   - ~~Raw `foreign-procedure` without safe wrapper~~
   - ~~`(chezscheme)` imports~~
   - ~~`.sls` files~~

## Tools to Verify

- `jerboa_verify file.ss` — Check syntax + compile
- `jerboa_check_syntax code` — Parse only
- `jerboa_compile_check file.ss` — Expand and compile
- `make check` — Run all checks

## Examples

### ✓ Correct: Pure Jerboa

```scheme
(import (jerboa prelude))

(def (parse-packet buf)
  (let* ([version (read-u8 buf 0)]
         [ihl (read-u8 buf 0)])
    (+ version ihl)))

(def packet-data (read-file-bytes "capture.pcap"))
(displayln (parse-packet packet-data))
```

### ✗ Wrong: Chez internals

```scheme
;; DON'T DO THIS
(import (chezscheme))
(library (my-lib) ...)
(foreign-procedure "c_func" ...)
```

## Questions?

- Check `CLAUDE.md` for Jerboa quick reference
- Check `(jerboa prelude)` exports: `jerboa_module_exports '(jerboa prelude)`
- Use `jerboa_doc symbol-name` to look up any function
- Use `jerboa_apropos pattern` to search by keyword

---

**tl;dr**: Only `.ss` files. Only `(import (jerboa prelude))`. Never `.sls`, never `(library ...)`, never Chez internals.
