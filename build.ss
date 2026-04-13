#!/usr/bin/env scheme
;; build.ss - Compile dissectors and pipeline to .so libraries

(import (jerboa prelude))

(define jerboa-lib
  (or (getenv "JERBOA_HOME") (format "~a/../jerboa" (current-directory))))

(define (compile-module path)
  "Syntax-check a .ss module by loading it"
  (display (str "Checking " path "..."))
  (flush-output-port)
  (try
    (let ((result (system (format "scheme --libdirs ~a/lib:lib --script ~a > /dev/null 2>&1"
                                  jerboa-lib path))))
      (if (zero? result)
          (displayln " OK")
          (displayln (format " FAILED (exit ~a)" result))))
    (catch (e)
      (displayln (format " ERROR: ~a" e)))))

;; Compile all dissectors
(compile-module "dissectors/ethernet.ss")
(compile-module "dissectors/ipv4.ss")
(compile-module "dissectors/udp.ss")
(compile-module "dissectors/tcp.ss")

;; Compile pipeline
(compile-module "lib/dissector/pipeline.ss")
(compile-module "lib/dissector/protocol.ss")

(displayln "")
(displayln "Build complete.")
