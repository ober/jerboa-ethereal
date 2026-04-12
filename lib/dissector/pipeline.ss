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

;; ── Core Pipeline ──────────────────────────────────────────────────────

(def (dissect-packet buffer (start-proto 'ethernet))
  "Dissect packet starting with given protocol
   Returns (ok layers) or (err message)

   layers is a list of dissected results from each protocol layer"

  (dissect-protocol-chain buffer start-proto '()))

(def (dissect-protocol-chain buffer proto-name layers)
  "Recursively dissect protocol and chain to next layer

   Params:
   - buffer: bytevector of packet data
   - proto-name: symbol like 'ethernet, 'ipv4, 'tcp
   - layers: accumulated layers (for final result list)

   Returns (ok layers) or (err message)"

  (let ((dissector (get-dissector proto-name)))
    (cond
      ;; Protocol not registered - return what we have so far
      ((not dissector)
       (if (null? layers)
           (err (str "Unknown protocol: " proto-name))
           (ok (reverse layers))))

      ;; Dissect this layer
      (else
       (try
         (let ((result (dissector buffer)))
           (cond
             ;; Dissection failed
             ((err? result)
              (if (null? layers)
                  result
                  ;; We have partial dissection
                  (ok (reverse layers))))

             ;; Dissection succeeded
             (else
              (let* ((fields (unwrap result))
                     (payload (assoc-get fields 'payload #f))
                     (next-proto (find-next-protocol proto-name fields)))

                ;; Continue chaining if there's more payload
                (if (and next-proto payload
                        (> (bytevector-length payload) 0))
                    ;; Recursively dissect payload with next protocol
                    (dissect-protocol-chain payload next-proto
                                           (cons (cons proto-name fields) layers))
                    ;; End of chain
                    (ok (reverse (cons (cons proto-name fields) layers))))))))

         ;; Catch unexpected errors
         (catch (e)
           (if (null? layers)
               (err (str "Dissection error in " proto-name ": " e))
               (ok (reverse layers)))))))))

;; ── Find Next Protocol ──────────────────────────────────────────────────

(def (find-next-protocol proto-name fields)
  "Determine next protocol in chain based on current protocol and fields
   Returns protocol name (symbol) or #f"

  (case proto-name
    ;; Ethernet: check EtherType
    ((ethernet)
     (let ((etype-field (assoc-get fields 'etype #f)))
       (if etype-field
           (let ((etype (assoc-get etype-field 'raw)))
             (ethertype->protocol etype))
           #f)))

    ;; IPv4: check protocol number
    ((ipv4)
     (let ((proto-field (assoc-get fields 'protocol #f)))
       (if proto-field
           (let ((proto-num (assoc-get proto-field 'raw)))
             (ip-protocol->protocol proto-num))
           #f)))

    ;; TCP/UDP: check destination port for DNS
    ((tcp udp)
     (let ((dst-port-field (assoc-get fields 'dst-port #f)))
       (if dst-port-field
           (let ((port (assoc-get dst-port-field 'raw)))
             (port->protocol port))
           #f)))

    ;; Other protocols: no chaining
    (else #f)))

;; ── Dissection Result Display ────────────────────────────────────────────

(def (display-dissected-packet layers)
  "Pretty-print dissected packet tree

   layers is ((proto-name . fields) (proto-name . fields) ...)"

  (string-join
    (map (lambda (layer)
           (let ((proto-name (car layer))
                 (fields (cdr layer)))
             (str (format-protocol-name proto-name) ":"
                  "\n"
                  (display-fields fields 2))))
         layers)
    "\n\n"))

(def (format-protocol-name name)
  "Format protocol name for display"
  (case name
    ((ethernet) "Ethernet")
    ((ipv4) "IPv4")
    ((ipv6) "IPv6")
    ((tcp) "TCP")
    ((udp) "UDP")
    ((icmp) "ICMP")
    ((icmpv6) "ICMPv6")
    ((igmp) "IGMP")
    ((arp) "ARP")
    ((dns) "DNS")
    (else (str name))))

(def (display-fields fields indent)
  "Format fields for display with indentation

   Fields can be:
   - (name . value) - simple field
   - (name . ((raw . val) (formatted . str))) - complex field with metadata"

  (let ((space (make-string indent #\space)))
    (string-join
      (map (lambda (field)
             (let ((name (car field))
                   (value (cdr field)))
               (cond
                 ;; Complex field with metadata
                 ((pair? value)
                  (let ((formatted (assoc-get value 'formatted #f)))
                    (if formatted
                        (str space (format-field-name name) " = " formatted)
                        (let ((raw (assoc-get value 'raw #f)))
                          (if raw
                              (str space (format-field-name name) " = " (truncate-value raw 60))
                              (str space (format-field-name name) " = ?"))))))
                 ;; Simple field
                 (else
                  (str space (format-field-name name) " = " (truncate-value value 60))))))
           fields)
      "\n")))

(def (format-field-name name)
  "Format field name for display"
  (string-replace (string-replace (str name) "-" " ") "_" " "))

(def (truncate-value val max-len)
  "Truncate value display to max length"
  (let ((str-val (str val)))
    (if (> (string-length str-val) max-len)
        (str (string-take str-val (- max-len 3)) "...")
        str-val)))

;; ── Exported API ───────────────────────────────────────────────────────────

;; dissect-packet: main entry point, start dissecting from a protocol
;; dissect-protocol-chain: recursive chain dissection
;; find-next-protocol: determine next protocol based on current layer fields
;; display-dissected-packet: pretty-print dissected packet layers
