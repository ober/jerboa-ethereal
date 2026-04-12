#!chezscheme
;; build-wafter-musl.ss — Build wafter as a fully static musl binary
;;
;; NOTE: This is a Chez Scheme script, not a Jerboa .ss file.
;; Build scripts are exempt from JERBOA_ONLY.md because they orchestrate
;; compilation and run in stock Chez. See JERBOA_ONLY.md for details.
;;
;; Usage:
;;   JERBOA_HOME=~/mine/jerboa make linux-local
;;   (or: scheme --libdirs lib:$JERBOA_HOME/lib --script build-wafter-musl.ss)
;;
;; Prerequisites:
;;   - musl-gcc: sudo apt install musl-tools
;;   - musl-built Chez: configured with CC=musl-gcc --static
;;     at ~/chez-musl (or JERBOA_MUSL_CHEZ_PREFIX)
;;   - Jerboa: at JERBOA_HOME (default ~/mine/jerboa)

(import (chezscheme))

;; ── Configuration ─────────────────────────────────────────────────────────

(define project-dir
  (let ((d (getenv "PWD")))
    (or d (current-directory))))

(define jerboa-home
  (or (getenv "JERBOA_HOME")
      (string-append (getenv "HOME") "/mine/jerboa")))

(define musl-chez-prefix
  (or (getenv "JERBOA_MUSL_CHEZ_PREFIX")
      (string-append (getenv "HOME") "/chez-musl")))

(define musl-chez-scheme
  (string-append musl-chez-prefix "/bin/scheme"))

(define output-binary "wafter-musl")
(define output-hash   "wafter-musl.sha256")
(define c-entry-point "wafter-main.c")

;; All source modules to compile, in dependency order
(define source-modules
  '(;; Core helpers (must come first)
    "lib/dissector/protocol.ss"
    "lib/dissector/registry.ss"
    ;; Dissectors (no inter-dependencies)
    "dissectors/ethernet.ss"
    "dissectors/arp.ss"
    "dissectors/ipv4.ss"
    "dissectors/ipv6.ss"
    "dissectors/icmp.ss"
    "dissectors/icmpv6.ss"
    "dissectors/igmp.ss"
    "dissectors/tcp.ss"
    "dissectors/udp.ss"
    "dissectors/dns.ss"
    "dissectors/dhcp.ss"
    "dissectors/ntp.ss"
    "dissectors/ssh.ss"
    ;; Higher-level libraries
    "lib/dissector/pipeline.ss"
    "lib/dissector/flows.ss"
    "lib/dissector/statistics.ss"
    "lib/dissector/manifest.ss"
    "lib/dissector/loader.ss"
    ;; Main CLI tool
    "tools/wafter.ss"))

;; ── Logging ───────────────────────────────────────────────────────────────

(define (log msg)
  (display msg) (newline) (flush-output-port (current-output-port)))

(define (log-step n total msg)
  (log (format "[~a/~a] ~a" n total msg)))

(define (log-ok msg)
  (log (string-append "  ✓ " msg)))

(define (log-err msg)
  (display (string-append "  ✗ " msg) (current-error-port))
  (newline (current-error-port)))

(define (die msg)
  (log-err msg)
  (exit 1))

;; ── Step 1: Prerequisites ─────────────────────────────────────────────────

(define (check-prerequisites)
  (log-step 1 6 "Checking prerequisites")
  (newline)

  ;; musl-gcc
  (unless (zero? (system "command -v musl-gcc >/dev/null 2>&1"))
    (die "musl-gcc not found. Install: sudo apt install musl-tools"))
  (log-ok (string-append "musl-gcc: " (let-values ([(p) (open-process-ports "command -v musl-gcc" 'block (native-transcoder))])
                                        (let ([line (get-line (car p))]) line))))

  ;; JERBOA_HOME
  (unless (file-directory? jerboa-home)
    (die (string-append "JERBOA_HOME not found: " jerboa-home)))
  (log-ok (string-append "JERBOA_HOME: " jerboa-home))

  ;; musl-built Chez
  (unless (file-exists? musl-chez-scheme)
    (die (string-append
           "musl Chez not found at: " musl-chez-scheme "\n"
           "  Build with: cd ~/chez-scheme && ./configure --threads --static CC=musl-gcc && make install DESTDIR=~/chez-musl\n"
           "  Or set: JERBOA_MUSL_CHEZ_PREFIX")))
  (log-ok (string-append "musl Chez: " musl-chez-scheme))

  (newline))

;; ── Step 2: Compile Modules ───────────────────────────────────────────────

(define (so-path ss-path)
  "Derive .so path from .ss path"
  (string-append (path-root ss-path) ".so"))

(define (wpo-path ss-path)
  "Derive .wpo path from .ss path"
  (string-append (path-root ss-path) ".wpo"))

(define (compile-module ss-path)
  "Compile a single .ss module to .so using musl Chez"
  (let* ((libdirs (string-append project-dir "/lib:"
                                 project-dir ":"
                                 jerboa-home "/lib"))
         (cmd (format "~a -q --libdirs ~a --optimize-level 3 --compile-imported-libraries \
                       --eval \"(compile-file \\\"~a\\\")\" --eval \"(exit)\" 2>&1"
                      musl-chez-scheme libdirs ss-path)))
    (let ((result (system cmd)))
      (if (zero? result)
          (begin (log-ok ss-path) #t)
          (begin (log-err (string-append "FAILED: " ss-path)) #f)))))

(define (compile-modules)
  (log-step 2 6 "Compiling modules with musl Chez")
  (newline)
  (log (string-append "  Compiling " (number->string (length source-modules)) " modules..."))
  (newline)

  (let* ((results (map compile-module source-modules))
         (n-ok    (length (filter (lambda (x) x) results)))
         (n-fail  (length (filter (lambda (x) (not x)) results))))
    (newline)
    (if (> n-fail 0)
        (die (format "~a module(s) failed to compile" n-fail))
        (log-ok (format "All ~a modules compiled" n-ok))))
  (newline))

;; ── Step 3: Generate C Entry Point ────────────────────────────────────────

(define (boot-files-for-chez)
  "Find petite.boot and scheme.boot for musl Chez"
  (let* ((boot-dir (string-append musl-chez-prefix "/lib/csv" (scheme-version) "/a6le")))
    (list (string-append boot-dir "/petite.boot")
          (string-append boot-dir "/scheme.boot"))))

(define (so-files-for-wpo)
  "List of compiled .wpo files to link"
  (filter file-exists?
          (map wpo-path source-modules)))

(define (generate-c-entry-point)
  (log-step 3 6 "Generating C entry point")
  (newline)

  (let* ((boot-files (boot-files-for-chez))
         (wpo-files  (so-files-for-wpo))
         (wpo-registrations
           (apply string-append
                  (map (lambda (f)
                         (format "  Sregister_boot_file(\"~a\");\n" f))
                       wpo-files)))
         (boot-registrations
           (apply string-append
                  (map (lambda (f)
                         (format "  Sregister_boot_file(\"~a\");\n" f))
                       boot-files)))
         (c-source
           (format
             "/* wafter-main.c — Auto-generated by build-wafter-musl.ss */\n\
#include <stdlib.h>\n\
#include <string.h>\n\
#include \"scheme.h\"\n\
\n\
static void custom_init(void) {\n\
  /* Register compiled wafter modules */\n\
~a\
}\n\
\n\
int main(int argc, char **argv) {\n\
  Sscheme_init(NULL);\n\
\n\
  /* Register Chez boot files */\n\
~a\
\n\
  /* Build the heap */\n\
  Sbuild_heap(NULL, custom_init);\n\
\n\
  /* Run wafter main */\n\
  Scall1(Stop_level_value(Sstring_to_symbol(\"command-line-start\")),\n\
         Sinteger(argc));\n\
\n\
  /* Set up argv for (command-line-arguments) */\n\
  {\n\
    ptr args = Snil;\n\
    int i;\n\
    for (i = argc - 1; i >= 1; i--)\n\
      args = Scons(Sstring(argv[i]), args);\n\
    Scall1(Stop_level_value(Sstring_to_symbol(\"command-line-arguments-set!\")), args);\n\
  }\n\
\n\
  /* Invoke the top-level wafter entry point */\n\
  Scall0(Stop_level_value(Sstring_to_symbol(\"wafter-main\")));\n\
\n\
  Sscheme_deinit();\n\
  return 0;\n\
}\n"
             wpo-registrations
             boot-registrations)))
    (call-with-output-file c-entry-point
      (lambda (port) (put-string port c-source))
      'replace)
    (log-ok (string-append "Generated " c-entry-point)))
  (newline))

;; ── Step 4: Link Static Binary ─────────────────────────────────────────────

(define (link-static-binary)
  (log-step 4 6 "Linking static binary with musl-gcc")
  (newline)

  (let* ((chez-include (string-append musl-chez-prefix "/include"))
         (chez-lib     (string-append musl-chez-prefix "/lib"))
         (wpo-files    (so-files-for-wpo))
         (wpo-args     (apply string-append
                              (map (lambda (f) (string-append " " f))
                                   wpo-files)))
         (cmd (format
                "musl-gcc ~a ~a -o ~a -static \
                 -I~a -L~a -lchez -lm -lpthread -ldl 2>&1"
                c-entry-point
                wpo-args
                output-binary
                chez-include
                chez-lib)))
    (log (string-append "  Running: " cmd))
    (newline)
    (let ((result (system cmd)))
      (if (zero? result)
          (log-ok (string-append "Linked: " output-binary))
          (die "Linking failed"))))
  (newline))

;; ── Step 5: Strip Binary ───────────────────────────────────────────────────

(define (strip-binary)
  (log-step 5 6 "Stripping binary")
  (newline)

  (let ((result (system (string-append "strip -s " output-binary))))
    (if (zero? result)
        (let* ((size-output (with-output-to-string
                              (lambda () (system (string-append "ls -lh " output-binary " | awk '{print $5}' 2>/dev/null")))))
               (size (string-trim size-output)))
          (log-ok (string-append "Stripped: " output-binary " (" size ")"))
          (log-ok "No debug symbols, no section headers"))
        (die "strip failed")))
  (newline))

;; ── Step 6: Generate Checksum ──────────────────────────────────────────────

(define (generate-checksum)
  (log-step 6 6 "Generating SHA256 checksum")
  (newline)

  (let ((result (system (string-append "sha256sum " output-binary " > " output-hash))))
    (if (zero? result)
        (log-ok (string-append "Checksum written to " output-hash))
        (die "sha256sum failed")))
  (newline))

;; ── Main ──────────────────────────────────────────────────────────────────

(define (main args)
  (newline)
  (log "════════════════════════════════════════════════════════════")
  (log "wafter static binary build")
  (log "════════════════════════════════════════════════════════════")
  (newline)
  (log (string-append "  Project:     " project-dir))
  (log (string-append "  JERBOA_HOME: " jerboa-home))
  (log (string-append "  musl Chez:   " musl-chez-prefix))
  (log (string-append "  Output:      " output-binary))
  (newline)

  (check-prerequisites)
  (compile-modules)
  (generate-c-entry-point)
  (link-static-binary)
  (strip-binary)
  (generate-checksum)

  (log "════════════════════════════════════════════════════════════")
  (log (string-append "  ✓ " output-binary " — build complete"))
  (log "════════════════════════════════════════════════════════════")
  (newline))

(main (command-line))
