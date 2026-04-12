;; jerboa-ethereal/lib/search/filter.ss
;; Packet filtering and searching (ngrep-like functionality)
;;
;; Search for strings/patterns in dissected packets
;; Filter by protocol, field values, regex patterns

(import (jerboa prelude))

;; TODO: Phase 5 implementation
;; - Implement (payload-contains str)
;; - Implement (src-ip pattern) matching
;; - Implement (protocol name) filtering
;; - Implement (field-equals name value)
;; - Implement (payload-regex pattern)

(define-syntax TODO-search-filter
  (syntax-rules ()
    [(_ msg)
     (error 'search-filter "Not yet implemented: ~a" msg)]))

;; Placeholder exports
(export)
