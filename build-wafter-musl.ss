#!chezscheme
;; build-wafter-musl.ss — Build wafter as a fully static musl binary
;;
;; Follows the same approach as jerboa-gitsafe/build-gitsafe-musl.ss:
;;   1. Compile all modules with STOCK Chez (optimize-level 3, WPO)
;;   2. Whole-program optimization → wafter-all.so
;;   3. Create wafter.boot from individual module .so files
;;   4. Embed boot files + program as C byte arrays
;;   5. Link with musl-gcc -static
;;
;; Usage:
;;   JERBOA_HOME=~/mine/jerboa make linux-local
;;
;; Prerequisites:
;;   - musl-gcc: sudo apt install musl-tools
;;   - musl-built Chez at ~/chez-musl (or set JERBOA_MUSL_CHEZ_PREFIX)
;;     build with: ./configure --threads --static CC=musl-gcc

(import (chezscheme))

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

;; ── Locate musl Chez ──────────────────────────────────────────────────────

(define musl-chez-prefix
  (or (getenv "JERBOA_MUSL_CHEZ_PREFIX")
      (let* ([home (getenv "HOME")]
             [p (format "~a/chez-musl" home)])
        (and (file-exists? p) p))))

(unless musl-chez-prefix
  (display "Error: Cannot find musl Chez install.\n")
  (display "  Set JERBOA_MUSL_CHEZ_PREFIX or install to ~/chez-musl\n")
  (exit 1))

(define (find-csv-dir lib-dir mt)
  (let ([csv-dir
          (let lp ([dirs (guard (e [#t '()]) (directory-list lib-dir))])
            (cond
              [(null? dirs) #f]
              [(and (> (string-length (car dirs)) 3)
                    (string=? "csv" (substring (car dirs) 0 3)))
               (format "~a/~a/~a" lib-dir (car dirs) mt)]
              [else (lp (cdr dirs))]))])
    (and csv-dir
         (file-exists? (format "~a/main.o" csv-dir))
         csv-dir)))

(define musl-chez-dir
  (let ([mt (symbol->string (machine-type))])
    (or (find-csv-dir (format "~a/lib" musl-chez-prefix) mt)
        (begin
          (printf "Error: Cannot find Chez ~a dir under ~a/lib\n"
                  (machine-type) musl-chez-prefix)
          (printf "  Expected: ~a/lib/csv<version>/~a/main.o\n"
                  musl-chez-prefix mt)
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
(printf "wafter static binary build\n")
(printf "════════════════════════════════════════════════════════════\n")
(printf "  Project:     ~a\n" (current-directory))
(printf "  Jerboa:      ~a\n" jerboa-dir)
(printf "  musl Chez:   ~a\n" musl-chez-dir)
(printf "  Machine:     ~a\n" (machine-type))
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

;; ── Step 1: Compile all modules (stock Chez, optimize-level 3, WPO) ──────

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

;; Library modules (compiled by step 1 via compile-imported-libraries)
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

(define existing-lib-sos
  (filter file-exists? (map so-file wafter-lib-modules)))

(apply make-boot-file "wafter.boot" '("scheme" "petite") existing-lib-sos)

(file->c-header "wafter-all.so"
                "wafter_program.h"
                "wafter_program_data" "wafter_program_size")
(file->c-header (format "~a/petite.boot" musl-chez-dir)
                "wafter_petite_boot.h"
                "petite_boot_data" "petite_boot_size")
(file->c-header (format "~a/scheme.boot" musl-chez-dir)
                "wafter_scheme_boot.h"
                "scheme_boot_data" "scheme_boot_size")
(file->c-header "wafter.boot"
                "wafter_boot.h"
                "wafter_boot_data" "wafter_boot_size")
(printf "  ✓ Boot file and headers ready\n\n")

;; ── Step 4: Generate C main ───────────────────────────────────────────────

(printf "[4/6] Generating C main...\n")

(call-with-output-file "wafter-main-musl.c"
  (lambda (out)
    (fprintf out "/* Auto-generated by build-wafter-musl.ss — do not edit */\n")
    (fprintf out "#define _GNU_SOURCE\n")
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
    (fprintf out "/* dlopen/dlsym stubs — no shared libraries in static binary */\n")
    (fprintf out "void *dlopen(const char *f, int m) { (void)f; (void)m; return (void*)1; }\n")
    (fprintf out "void *dlsym(void *h, const char *s) { (void)h; (void)s; return NULL; }\n")
    (fprintf out "int dlclose(void *h) { (void)h; return 0; }\n")
    (fprintf out "char *dlerror(void) { return \"static build\"; }\n")
    (fprintf out "\n")
    (fprintf out "int main(int argc, char *argv[]) {\n")
    (fprintf out "  char prog_path[256];\n")
    (fprintf out "  const char *tmpdir = getenv(\"TMPDIR\");\n")
    (fprintf out "  if (!tmpdir) tmpdir = \"/tmp\";\n")
    (display  "  snprintf(prog_path, sizeof(prog_path), \"%s/wafter-XXXXXX\", tmpdir);\n" out)
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
(printf "  ✓ wafter-main-musl.c generated\n\n")

;; ── Step 5: Compile and link with musl-gcc ────────────────────────────────

(printf "[5/6] Compiling and linking with musl-gcc (static)...\n")

(define link-libs "-lkernel -llz4 -lz -lm -ldl -lpthread")

(let ([rc (system (format "musl-gcc -c -O2 -I~a -o wafter-main-musl.o wafter-main-musl.c"
                          musl-chez-dir))])
  (unless (= rc 0) (printf "Error: C compilation failed\n") (exit 1)))

(let ([rc (system (format "musl-gcc -o wafter-musl wafter-main-musl.o -L~a ~a -static -Wl,--allow-multiple-definition"
                          musl-chez-dir link-libs))])
  (unless (= rc 0) (printf "Error: linking failed\n") (exit 1)))

(printf "  Stripping binary...\n")
(system "strip --strip-all wafter-musl")
(system "sha256sum wafter-musl > wafter-musl.sha256")
(printf "  ✓ Linked and stripped\n\n")

;; ── Step 6: Cleanup ───────────────────────────────────────────────────────

(printf "[6/6] Cleaning up intermediate files...\n")
(for-each (lambda (f) (when (file-exists? f) (delete-file f)))
  '("wafter-main-musl.c" "wafter-main-musl.o"
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
(printf "  ✓ wafter-musl — build complete\n")
(printf "════════════════════════════════════════════════════════════\n")
(printf "  Size:   ")
(system "ls -lh wafter-musl | awk '{print $5}'")
(printf "  SHA256: ")
(system "cat wafter-musl.sha256")
(printf "\n  Test:   ./wafter-musl --version\n")
(printf "  Verify: file wafter-musl && ldd wafter-musl\n\n")
