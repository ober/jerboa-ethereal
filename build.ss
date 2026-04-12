#!/usr/bin/env scheme
;; build.ss - Compile dissectors and pipeline to .so libraries

(import (jerboa prelude)
        (chezscheme))

(define (compile-module path)
  "Compile a single .ss module to .so"
  (let ((so-path (string-replace path #\. #\.)))  ;; just use .ss for now
    (display (str "Compiling " path "..."))
    (flush-output-port)
    (try
      (let ((result (system (str "scheme --libdirs " (or (getenv "JERBOA_HOME") ".") "/lib:lib --script " path " > /dev/null 2>&1"))))
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
