;; jerboa-ethereal/lib/dsl/parser.ss
;; DSL parser: convert s-expression protocol definitions to executable dissectors
;;
;; Protocol definitions are Jerboa s-expressions:
;;   (defprotocol name
;;     :description "..."
;;     :fields [
;;       (field-name type :mask #x... :formatter f :desc "...")
;;       ...
;;     ])

(import (jerboa prelude))

;; TODO: Phase 2 implementation
;; - Implement parse-protocol-def
;; - Implement type validation
;; - Implement formatter registry
;; - Implement conditional field handling

(define-syntax TODO-dsl-parser
  (syntax-rules ()
    [(_ msg)
     (error 'dsl-parser "Not yet implemented: ~a" msg)]))

;; Placeholder exports
(export)
