#!/usr/bin/env scheme
;; build.ss - Compile dissectors and pipeline to .so libraries

(import (jerboa prelude)
        (chezscheme))

(define (compile-module path)
  "Compile a single .ss module to .so"
  (let ((so-path (string-replace path ".ss" ".so")))
    (display (str "Compiling " path " → " so-path "..."))
    (flush-output-port)
    (try
      (let ((result (system (str "scheme --libdirs lib --script -c " path))))
        (if (zero? result)
            (displayln " OK")
            (displayln (str " FAILED (exit code: " result ")"))))
      (catch (e)
        (displayln (str " ERROR: " e))))))

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
