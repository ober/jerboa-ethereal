;; jerboa-ethereal/lib/name-resolver/resolver.ss
;; Actor-based DNS name resolver with persistent caching
;;
;; Concurrent DNS queries, IP↔hostname resolution, LRU cache

(import (jerboa prelude))

;; TODO: Phase 6 implementation
;; - Implement actor pool for concurrent DNS resolution
;; - Implement persistent cache (SQLite)
;; - Implement well-known name mappings (ports, protocols)

(define-syntax TODO-name-resolver
  (syntax-rules ()
    [(_ msg)
     (error 'name-resolver "Not yet implemented: ~a" msg)]))

;; Placeholder exports
(export)
