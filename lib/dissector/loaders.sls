;; jerboa-ethereal/lib/dissector/loaders.sls
;; Load and register all dissectors
;;
;; This library loads the dissector scripts and registers them

(library (lib dissector loaders)
  (export load-all-dissectors register-dissector! get-dissector)

  (import (jerboa prelude))

  ;; Protocol dissector registry
  (define protocol-dissectors (make-hash-table))

  (define (register-dissector! proto-name dissector-fn)
    "Register a dissector function for a protocol"
    (hash-put! protocol-dissectors proto-name dissector-fn))

  (define (get-dissector proto-name)
    "Look up dissector for protocol, returns #f if not registered"
    (hash-get protocol-dissectors proto-name))

  ;; Load all dissector scripts
  (define (load-all-dissectors)
    "Load all dissector modules and register them"
    (let ((base-dir (path-directory (current-source-location))))
      ;; We'll load these dynamically via the script
      #t))
)
