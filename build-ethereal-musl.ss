#!chezscheme
;; build-ethereal-musl.ss — Build ethereal as a fully static binary using musl libc
;;
;; NOTE: This is a Chez Scheme script (#!chezscheme, not Jerboa .ss).
;; Build scripts are exempt from JERBOA_ONLY.md constraints because they
;; orchestrate compilation and must run in stock Chez.
;; See JERBOA_ONLY.md for exception details.
;;
;; Usage: scheme --libdirs lib:JERBOA_HOME/lib --script build-ethereal-musl.ss
;;
;; Prerequisites:
;;   - musl-gcc installed (apt install musl-tools)
;;   - Chez Scheme built with musl: ./configure --threads --static CC=musl-gcc
;;     installed to ~/chez-musl (or set JERBOA_MUSL_CHEZ_PREFIX)
;;   - Jerboa libraries available (JERBOA_HOME)
;;
;; Build steps:
;;   1. Locate musl Chez and Jerboa
;;   2. Compile all dissector modules (optimize-level 3, WPO)
;;   3. Generate C entry point (ethereal-main.c)
;;   4. Invoke musl-gcc to compile C + link static
;;   5. Strip binary
;;   6. Generate SHA256 hash

(import (chezscheme))

;; ── Configuration ─────────────────────────────────────────────────────────

(define jerboa-home (or (getenv "JERBOA_HOME") (format "~a/mine/jerboa" (getenv "HOME"))))
(define musl-chez-prefix (or (getenv "JERBOA_MUSL_CHEZ_PREFIX") (format "~a/chez-musl" (getenv "HOME"))))
(define script-dir (path-directory (car (command-line))))

;; ── Utility Functions ──────────────────────────────────────────────────────

(define (log-info msg)
  (format (current-output-port) "[INFO] ~a~n" msg)
  (flush-output-port))

(define (log-error msg)
  (format (current-error-port) "[ERROR] ~a~n" msg)
  (flush-output-port))

(define (log-step n total msg)
  (log-info (format "[~a/~a] ~a" n total msg)))

(define (system-check cmd description)
  "Run command and check for success"
  (log-info (format "Checking ~a..." description))
  (let ((result (system cmd)))
    (if (zero? result)
        (begin
          (log-info (format "✓ ~a found" description))
          #t)
        (begin
          (log-error (format "✗ ~a not found or failed" description))
          #f))))

(define (file-exists? path)
  (with-output-to-string
    (lambda ()
      (zero? (system (format "test -f ~a" path))))))

;; ── Build Steps ────────────────────────────────────────────────────────────

(define (check-prerequisites)
  "Verify build prerequisites are available"
  (log-step 1 6 "Checking prerequisites")
  (displayln "")

  (let ((checks '(
    ("musl-gcc --version" "musl-gcc toolchain")
    ((format "test -d ~a" jerboa-home) "JERBOA_HOME")
    ((format "test -d ~a" musl-chez-prefix) "musl-built Chez"))))

    (let ((all-ok (for-all (lambda (check)
                             (system-check (car check) (cadr check)))
                           checks)))
      (if all-ok
          (log-info "✓ All prerequisites met")
          (begin
            (log-error "Prerequisites missing. See docs/BUILD_STATIC.md for setup.")
            (exit 1))))))

(define (compile-dissectors)
  "Compile all dissectors using manifest"
  (log-step 2 6 "Compiling dissectors")
  (displayln "")

  ;; Read manifest to get dissector list
  (log-info "Reading dissector manifest...")
  (log-info "Dissectors to compile: 13")
  (log-info "  • Ethernet, IPv4, IPv6, ARP")
  (log-info "  • TCP, UDP, ICMP, ICMPv6, IGMP")
  (log-info "  • DNS, DHCP, NTP, SSH")
  (displayln ""))

(define (generate-c-entry-point)
  "Generate C entry point (wafter-main.c)"
  (log-step 3 6 "Generating C entry point")
  (displayln "")
  (log-info "Generating wafter-main.c..."))

(define (link-static-binary)
  "Invoke musl-gcc to create static binary"
  (log-step 4 6 "Linking static binary")
  (displayln "")
  (log-info "Linking with musl-gcc..."))

(define (strip-binary)
  "Strip debug symbols from binary"
  (log-step 5 6 "Stripping binary")
  (displayln "")
  (log-info "Stripping debug symbols..."))

(define (generate-checksum)
  "Generate SHA256 checksum"
  (log-step 6 6 "Generating checksum")
  (displayln "")
  (log-info "Generating SHA256 hash..."))

;; ── Main Build Process ──────────────────────────────────────────────────────

(define (main args)
  (displayln "")
  (displayln "═══════════════════════════════════════════════════════════════")
  (displayln "wafter Static Binary Build (Phase 7)")
  (displayln "═══════════════════════════════════════════════════════════════")
  (displayln "")

  ;; Step 1: Check prerequisites
  (check-prerequisites)
  (displayln "")

  ;; Step 2-6: Build steps (currently logged, not yet implemented)
  (compile-dissectors)
  (generate-c-entry-point)
  (link-static-binary)
  (strip-binary)
  (generate-checksum)

  (displayln "")
  (displayln "═══════════════════════════════════════════════════════════════")
  (displayln "Build Status: IMPLEMENTATION IN PROGRESS (Phase 7)")
  (displayln "═══════════════════════════════════════════════════════════════")
  (displayln "")
  (displayln "Next steps:")
  (displayln "  1. Implement dissector compilation (Step 2)")
  (displayln "  2. Generate C entry point (Step 3)")
  (displayln "  3. Link static binary (Step 4)")
  (displayln "  4. Verify binary with: make verify-harden")
  (displayln "")
  (displayln "See: docs/BUILD_STATIC.md")
  (displayln ""))

(main (command-line))
