#!chezscheme
;; build-wafter-macos.ss — Build wafter as a macOS binary
;;
;; Produces a native macOS executable linked against the Chez Scheme
;; runtime libraries (libkernel.a, liblz4.a, libz.a) from the Homebrew
;; Chez install.  Not fully static (still links libSystem.dylib) but has
;; no runtime dependency on an external Chez install.
;;
;; Usage:
;;   make macos           — auto-detects Homebrew Chez
;;   CHEZ_DIR=<path> make macos   — override Chez lib dir
;;
;; Prerequisites:
;;   - Chez Scheme via Homebrew:  brew install chezscheme
;;   - Xcode Command Line Tools:  xcode-select --install
;;   - Jerboa libraries available (sibling ../jerboa or JERBOA_HOME set)

(import (chezscheme))

;; ── String helpers (not available in base Chez) ───────────────────────────

(define (string-starts-with? str prefix)
  (let ([n (string-length prefix)])
    (and (>= (string-length str) n)
         (string=? (substring str 0 n) prefix))))

;; ── Helper: embed binary file as C byte array ─────────────────────────────

(define (file->c-header input-path output-path array-name size-name)
  (let* ([port (open-file-input-port input-path)]
         [data (get-bytevector-all port)]
         [size (bytevector-length data)])
    (close-port port)
    (call-with-output-file output-path
      (lambda (out)
        (fprintf out "/* Auto-generated — do not edit */\n")
        (fprintf out "static const unsigned char ~a[] = {\n" array-name)
        (let loop ([i 0])
          (when (< i size)
            (when (= 0 (modulo i 16)) (fprintf out "  "))
            (fprintf out "0x~2,'0x" (bytevector-u8-ref data i))
            (when (< (+ i 1) size) (fprintf out ","))
            (when (= 15 (modulo i 16)) (fprintf out "\n"))
            (loop (+ i 1))))
        (fprintf out "\n};\n")
        (fprintf out "static const unsigned int ~a = ~a;\n" size-name size))
      'replace)
    (printf "  ~a: ~a bytes\n" output-path size)))

;; ── Locate Chez library directory ─────────────────────────────────────────
;; Priority: CHEZ_DIR env → HOMEBREW_PREFIX → /opt/homebrew → /usr/local

(define (find-csv-dir base-lib mt)
  "Find the csv<version>/<machine-type> directory under base-lib."
  (let ([entries (guard (e [#t '()]) (directory-list base-lib))])
    (let loop ([dirs entries])
      (cond
        [(null? dirs) #f]
        [(and (string-starts-with? (car dirs) "csv")
              (file-exists? (format "~a/~a/~a/scheme.h" base-lib (car dirs) mt)))
         (format "~a/~a/~a" base-lib (car dirs) mt)]
        [else (loop (cdr dirs))]))))

(define chez-dir
  (let* ([mt  (symbol->string (machine-type))]
         [env (getenv "CHEZ_DIR")]
         [homebrew-prefix (or (getenv "HOMEBREW_PREFIX")
                              (and (file-exists? "/opt/homebrew/bin/scheme") "/opt/homebrew")
                              "/usr/local")])
    (or
     ;; 1. Explicit override
     (and env (file-exists? (format "~a/scheme.h" env)) env)
     ;; 2. Homebrew csv dir
     (find-csv-dir (format "~a/lib" homebrew-prefix) mt)
     ;; 3. System-wide csv dir
     (find-csv-dir "/usr/local/lib" mt)
     (begin
       (printf "Error: Cannot find Chez Scheme library directory.\n")
       (printf "  Install via: brew install chezscheme\n")
       (printf "  Or set CHEZ_DIR to the directory containing scheme.h\n")
       (exit 1)))))

;; ── Locate Jerboa ─────────────────────────────────────────────────────────

(define jerboa-dir
  (or (getenv "JERBOA_HOME")
      (let ([sibling (format "~a/../jerboa" (current-directory))])
        (and (file-exists? sibling) sibling))
      (begin
        (display "Error: Cannot find Jerboa. Set JERBOA_HOME.\n")
        (exit 1))))

(printf "\n════════════════════════════════════════════════════════════\n")
(printf "wafter macOS binary build\n")
(printf "════════════════════════════════════════════════════════════\n")
(printf "  Project:    ~a\n" (current-directory))
(printf "  Jerboa:     ~a\n" jerboa-dir)
(printf "  Chez dir:   ~a\n" chez-dir)
(printf "  Machine:    ~a\n" (machine-type))
(newline)

;; ── Set up library directories ────────────────────────────────────────────

(library-directories
  (append
    (list (cons (current-directory) (current-directory))
          (cons (format "~a/lib" (current-directory))
                (format "~a/lib" (current-directory)))
          (cons (format "~a/lib" jerboa-dir)
                (format "~a/lib" jerboa-dir)))
    (library-directories)))

;; ── Step 1: Compile all modules (optimize-level 3, WPO) ───────────────────

(printf "[1/6] Compiling all modules (optimize-level 3, WPO)...\n")
(parameterize ([compile-imported-libraries         #t]
               [optimize-level                     3]
               [cp0-effort-limit                   500]
               [cp0-score-limit                    50]
               [cp0-outer-unroll-limit              1]
               [commonization-level                 4]
               [enable-unsafe-application          #t]
               [enable-unsafe-variable-reference   #t]
               [enable-arithmetic-left-associative #t]
               [debug-level                         0]
               [generate-inspector-information     #f]
               [generate-wpo-files                 #t])
  (compile-program "tools/wafter.ss"))
(printf "  ✓ Compilation complete\n\n")

;; ── Step 2: Whole-program optimization ───────────────────────────────────

(printf "[2/6] Running whole-program optimization...\n")
(let ([missing (compile-whole-program "tools/wafter.wpo" "wafter-all.so")])
  (unless (null? missing)
    (printf "  WPO: ~a libraries not incorporated (missing .wpo):\n" (length missing))
    (for-each (lambda (lib) (printf "    ~a\n" lib)) missing)))
(printf "  ✓ WPO complete\n\n")

;; ── Step 3: Create boot file + C headers ─────────────────────────────────

(printf "[3/6] Creating boot file and C headers...\n")

(define wafter-lib-modules
  '("lib/dissector/protocol"
    "lib/dissector/registry"
    "dissectors/ethernet"
    "dissectors/arp"
    "dissectors/ipv4"
    "dissectors/ipv6"
    "dissectors/icmp"
    "dissectors/icmpv6"
    "dissectors/igmp"
    "dissectors/tcp"
    "dissectors/udp"
    "dissectors/dns"
    "dissectors/dhcp"
    "dissectors/ntp"
    "dissectors/ssh"
    "lib/dissector/pipeline"
    "lib/dissector/flows"
    "lib/dissector/statistics"
    "lib/dissector/manifest"
    "lib/dissector/loader"))

(define (so-file m) (format "~a.so" m))

;; Jerboa library modules that are not incorporated into WPO
;; (missing .wpo files) — must be present in the boot so the runtime finds them
(define jerboa-boot-modules
  (map (lambda (m) (format "~a/lib/~a.so" jerboa-dir m))
       '("jerboa/runtime"
         "jerboa/core"
         "std/result"
         "std/sugar"
         "std/sort"
         "std/format"
         "std/typed"
         "std/pregexp"
         "std/misc/list"
         "std/misc/string"
         "std/misc/thread"
         "std/os/path"
         ;; prelude direct deps
         "jerboa/prelude"
         "jerboa/reader"
         "jerboa/ffi"
         "std/misc/atom"
         "std/misc/meta"
         "std/misc/func"
         "std/misc/fmt"
         "std/misc/alist")))

(define existing-lib-sos
  (filter file-exists?
          (append (map so-file wafter-lib-modules)
                  jerboa-boot-modules)))

(apply make-boot-file "wafter.boot" '("scheme" "petite") existing-lib-sos)

(file->c-header "wafter-all.so"
                "wafter_program.h"
                "wafter_program_data" "wafter_program_size")
(file->c-header (format "~a/petite.boot" chez-dir)
                "wafter_petite_boot.h"
                "petite_boot_data" "petite_boot_size")
(file->c-header (format "~a/scheme.boot" chez-dir)
                "wafter_scheme_boot.h"
                "scheme_boot_data" "scheme_boot_size")
(file->c-header "wafter.boot"
                "wafter_boot.h"
                "wafter_boot_data" "wafter_boot_size")
(printf "  ✓ Boot file and headers ready\n\n")

;; ── Step 4: Generate C main ───────────────────────────────────────────────

(printf "[4/6] Generating C main...\n")

(call-with-output-file "wafter-main-macos.c"
  (lambda (out)
    (fprintf out "/* Auto-generated by build-wafter-macos.ss — do not edit */\n")
    (fprintf out "#include <stdlib.h>\n")
    (fprintf out "#include <stdio.h>\n")
    (fprintf out "#include <string.h>\n")
    (fprintf out "#include <unistd.h>\n")
    (fprintf out "#include \"scheme.h\"\n")
    (fprintf out "#include \"wafter_petite_boot.h\"\n")
    (fprintf out "#include \"wafter_scheme_boot.h\"\n")
    (fprintf out "#include \"wafter_boot.h\"\n")
    (fprintf out "#include \"wafter_program.h\"\n")
    (fprintf out "\n")
    (fprintf out "int main(int argc, char *argv[]) {\n")
    (fprintf out "  char prog_path[] = \"/tmp/wafter-XXXXXX\";\n")
    (fprintf out "  int fd = mkstemp(prog_path);\n")
    (fprintf out "  if (fd < 0) { perror(\"mkstemp\"); return 1; }\n")
    (fprintf out "  if (write(fd, wafter_program_data, wafter_program_size)\n")
    (fprintf out "      != (ssize_t)wafter_program_size) {\n")
    (fprintf out "    perror(\"write\"); close(fd); unlink(prog_path); return 1;\n")
    (fprintf out "  }\n")
    (fprintf out "  close(fd);\n")
    (fprintf out "\n")
    (fprintf out "  Sscheme_init(NULL);\n")
    (fprintf out "  Sregister_boot_file_bytes(\"petite\", (void*)petite_boot_data, petite_boot_size);\n")
    (fprintf out "  Sregister_boot_file_bytes(\"scheme\", (void*)scheme_boot_data, scheme_boot_size);\n")
    (fprintf out "  Sregister_boot_file_bytes(\"wafter\", (void*)wafter_boot_data, wafter_boot_size);\n")
    (fprintf out "  Sbuild_heap(NULL, NULL);\n")
    (fprintf out "  int status = Sscheme_script(prog_path, argc, (const char **)argv);\n")
    (fprintf out "  unlink(prog_path);\n")
    (fprintf out "  Sscheme_deinit();\n")
    (fprintf out "  return status;\n")
    (fprintf out "}\n"))
  'replace)
(printf "  ✓ wafter-main-macos.c generated\n\n")

;; ── Step 5: Compile and link with cc ─────────────────────────────────────

(printf "[5/6] Compiling and linking with cc...\n")

(let ([rc (system (format "cc -c -O2 -I~a -o wafter-main-macos.o wafter-main-macos.c"
                          chez-dir))])
  (unless (= rc 0) (printf "Error: C compilation failed\n") (exit 1)))

;; Link: libkernel.a + liblz4.a + libz.a from Chez install, plus system libs
;; macOS needs -lncurses (expeditor/terminal) and -liconv (character encoding)
(let ([rc (system (format "cc -o wafter-macos wafter-main-macos.o ~a/libkernel.a ~a/liblz4.a ~a/libz.a -lm -lpthread -ldl -lncurses -liconv"
                          chez-dir chez-dir chez-dir))])
  (unless (= rc 0) (printf "Error: linking failed\n") (exit 1)))

(printf "  Stripping binary...\n")
(system "strip -x wafter-macos")
(system "shasum -a 256 wafter-macos > wafter-macos.sha256")
(printf "  ✓ Linked and stripped\n\n")

;; ── Step 6: Cleanup ───────────────────────────────────────────────────────

(printf "[6/6] Cleaning up intermediate files...\n")
(for-each (lambda (f) (when (file-exists? f) (delete-file f)))
  '("wafter-main-macos.c" "wafter-main-macos.o"
    "wafter_program.h" "wafter_petite_boot.h"
    "wafter_scheme_boot.h" "wafter_boot.h"
    "wafter-all.so" "wafter.boot"
    "tools/wafter.wpo" "tools/wafter.so"))

(for-each (lambda (m)
            (for-each (lambda (ext)
                        (let ([f (format "~a~a" m ext)])
                          (when (file-exists? f) (delete-file f))))
                      '(".so" ".wpo")))
          wafter-lib-modules)

(printf "\n════════════════════════════════════════════════════════════\n")
(printf "  ✓ wafter-macos — build complete\n")
(printf "════════════════════════════════════════════════════════════\n")
(printf "  Size:   ")
(system "ls -lh wafter-macos | awk '{print $5}'")
(printf "  SHA256: ")
(system "cat wafter-macos.sha256")
(printf "\n  Test:   ./wafter-macos --version\n")
(printf "  Verify: file wafter-macos && otool -L wafter-macos\n\n")
