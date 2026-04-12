;; jerboa-ethereal/lib/dissector/pipeline.ss
;; Protocol dissection pipeline: chain protocols together
;;
;; Dissects packets recursively through multiple layers:
;; Ethernet → IPv4 → TCP/UDP → Application
;;
;; Returns either:
;; - (ok packet-tree): nested structure of dissected layers
;; - (err message): on any parsing error at any layer

(import (jerboa prelude))

;; ── Protocol Registry ──────────────────────────────────────────────────────
;; Maps protocol names to their dissection functions

(def protocol-registry (make-hash-table))

(def (register-protocol! name dissector-fn)
  "Register a protocol dissector function"
  (hash-put! protocol-registry name dissector-fn))

(def (get-dissector proto-name)
  "Look up dissector for protocol, returns #f if not registered"
  (hash-get protocol-registry proto-name))

;; ── Dissection Result Type ─────────────────────────────────────────────────

(defstruct dissected-layer
  (protocol-name
   fields
   payload-bytes))

;; ── Core Pipeline ─────────────────────────────────────────────────────────

(def (dissect-packet buffer (start-proto 'ethernet))
  "Dissect packet starting with given protocol
   Returns (ok layers) or (err message)

   layers is nested: ((ethernet (fields ...) (ipv4 (fields ...) ...)))

   Automatically chains protocols based on:
   - Ethernet EtherType field
   - IPv4 protocol field
   - TCP/UDP port-based detection"

  (dissect-protocol-chain buffer start-proto '()))

(def (dissect-protocol-chain buffer proto-name acc)
  "Recursively dissect protocol and its payloads
   acc: accumulated layers (for nested structure)"

  (let ((dissector (get-dissector proto-name)))
    (cond
      ;; Protocol not registered
      ((not dissector)
       (err (str "Unknown protocol: " proto-name)))

      ;; Dissect this layer
      (#t
       (try
         ;; Parse this protocol layer
         (let ((layer-result (dissector buffer)))
           (cond
             ;; Dissection failed
             ((err? layer-result)
              (err (unwrap-err layer-result)))

             ;; Dissection succeeded
             (#t
              (let* ((layer (unwrap-ok layer-result))
                     (payload (dissected-layer-payload-bytes layer))
                     (next-proto (find-next-protocol layer)))

                ;; Continue chaining if there's more to parse
                (if (and next-proto payload (> (bytevector-length payload) 0))
                    ;; Recursively dissect payload
                    (let ((rest (dissect-protocol-chain payload next-proto acc)))
                      (cond
                        ((err? rest) rest)
                        (#t (ok (cons layer (unwrap-ok rest))))))

                    ;; End of chain
                    (ok (cons layer acc)))))))

         ;; Catch unexpected errors
         (catch (e)
           (err (str "Dissection error in " proto-name ": " e))))))))

;; ── Find Next Protocol ─────────────────────────────────────────────────────

(def (find-next-protocol layer)
  "Look for protocol discovery field in dissected layer
   Returns protocol name or #f"

  (let ((fields (dissected-layer-fields layer)))
    ;; Search for field with 'next-protocol marker
    (let loop ((fields fields))
      (cond
        ((null? fields) #f)
        (#t
         (let ((field (car fields)))
           (if (and (pair? field)
                    (pair? (cdr field))
                    (pair? (cadr field)))
               ;; Check if this field has next-protocol info
               (let ((next-val (assoc-in (cadr field) 'next-protocol)))
                 (if next-val
                     (cdr next-val)
                     (loop (cdr fields))))
               (loop (cdr fields)))))))))

;; ── Display Dissected Packet ──────────────────────────────────────────────

(def (display-packet layers (indent 0))
  "Pretty-print dissected packet tree with indentation"

  (let ((spaces (make-string indent #\space)))
    (string-join
      (map (lambda (layer)
             (let ((proto (dissected-layer-protocol-name layer))
                   (fields (dissected-layer-fields layer)))
               (string-join
                 (cons (str spaces proto ":")
                       (map (lambda (f)
                              (str spaces "  " (display-field f)))
                            fields))
                 "\n")))
           layers)
      "\n")))

(def (display-field field)
  "Format a single field for display"
  (let ((name (car field))
        (val (cdr field)))
    (cond
      ;; Simple value
      ((not (pair? val))
       (str name " = " val))

      ;; Value with metadata
      ((pair? (car val))
       ;; Complex field with raw/formatted/next-protocol
       (let ((formatted (assoc-in val 'formatted)))
         (if formatted
             (str name " = " (cdr formatted))
             (str name " = " (assoc-in val 'raw)))))

      ;; Simple pair (raw . value)
      (#t
       (str name " = " (cdr val))))))

;; ── Error Handling ─────────────────────────────────────────────────────────

(def (dissection-success? result)
  "Check if dissection succeeded"
  (ok? result))

(def (dissection-error result)
  "Extract error message if dissection failed"
  (if (err? result)
      (unwrap-err result)
      #f))

(def (partial-dissection? layers)
  "Check if we got partial dissection (error at some layer)"
  (not (null? layers)))

;; ── Packet Statistics ──────────────────────────────────────────────────────

(def (packet-size-stats layers total-bytes)
  "Return statistics about packet structure"
  (let loop ((layers layers)
             (acc 0)
             (count 0))
    (if (null? layers)
        `((total-bytes . ,total-bytes)
          (layers . ,count)
          (parsed-bytes . ,acc)
          (unparsed-bytes . ,(max 0 (- total-bytes acc))))
        (let ((layer (car layers)))
          (loop (cdr layers)
                (+ acc (packet-layer-size layer))
                (+ count 1))))))

(def (packet-layer-size layer)
  "Estimate size of a dissected layer (rough)"
  ;; This is approximate - would need to track byte positions for exact size
  20)  ;; TODO: track actual positions during dissection