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

;; TODO: Phase 5+ implementation
;; - Locate musl Chez at ~/chez-musl
;; - Compile lib/dissector, lib/dsl, lib/pcap, lib/search, lib/name-resolver
;; - Compile dissectors/*.ss
;; - Generate ethereal-main.c with embedded boot image
;; - Run: musl-gcc ethereal-main.c -o ethereal-musl -static -lm
;; - Run: strip -s ethereal-musl
;; - Generate: sha256sum ethereal-musl > ethereal-musl.sha256

(define (main args)
  (display "TODO: Implement ethereal-musl static build\n")
  (display "See: docs/BUILD_STATIC.md\n")
  (exit 1))

(main (command-line))
