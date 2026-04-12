;; jerboa-ethereal/lib/dissector/registry.ss
;; Protocol registry and discovery
;;
;; Maps protocol names to their dissector functions
;; Implements protocol chain discovery rules

(import (jerboa prelude))

;; ── Protocol Dissector Registry ────────────────────────────────────────────

(def protocol-dissectors (make-hash-table))

(def (register-dissector! proto-name dissector-fn)
  "Register a dissector function for a protocol"
  (hash-put! protocol-dissectors proto-name dissector-fn))

(def (get-dissector proto-name)
  "Look up dissector for protocol, returns #f if not registered"
  (hash-get protocol-dissectors proto-name))

(def (protocol-registered? proto-name)
  "Check if protocol is registered"
  (hash-key? protocol-dissectors proto-name))

(def (list-registered-protocols)
  "Get list of all registered protocol names"
  (hash-keys protocol-dissectors))

;; ── Protocol Discovery Rules ──────────────────────────────────────────────

(def (ethertype->protocol etype)
  "Map EtherType to next protocol layer
   Returns symbol or #f"
  (case etype
    ((#x0800) 'ipv4)
    ((#x0806) 'arp)
    ((#x86DD) 'ipv6)
    (else #f)))

(def (ip-protocol->protocol proto-num)
  "Map IP protocol number to next protocol layer
   Returns symbol or #f"
  (case proto-num
    ((1) 'icmp)
    ((2) 'igmp)
    ((6) 'tcp)
    ((17) 'udp)
    ((58) 'icmpv6)
    (else #f)))

(def (port->protocol port-num)
  "Map port to application protocol
   Returns symbol or #f"
  (case port-num
    ((53) 'dns)
    ((80) 'http)
    ((443) 'https)
    ((22) 'ssh)
    ((21) 'ftp)
    ((25 587) 'smtp)
    ((110) 'pop3)
    ((143) 'imap)
    (else #f)))

;; ── Helper: Extract Next Protocol from Dissected Layer ──────────────────

(def (extract-next-protocol-from-fields fields)
  "Search dissected fields for next-protocol marker
   Returns symbol or #f"
  (let loop ((fields fields))
    (cond
      ((null? fields) #f)
      (else
       (let ((field (car fields)))
         (if (pair? field)
             (let ((value (cdr field)))
               ;; Look for nested next-protocol field
               (if (pair? value)
                   (let loop2 ((v value))
                     (cond
                       ((null? v) (loop (cdr fields)))
                       ((and (pair? (car v))
                             (eq? (caar v) 'next-protocol))
                        (cdar v))
                       (else (loop2 (cdr v)))))
                   (loop (cdr fields))))
             (loop (cdr fields))))))))

;; ── Exported API ───────────────────────────────────────────────────────────

;; register-dissector!: register a dissector function
;; get-dissector: look up dissector function by protocol name
;; protocol-registered?: check if protocol is registered
;; list-registered-protocols: get all protocol names
;; ethertype->protocol: EtherType (0x0800) -> 'ipv4
;; ip-protocol->protocol: IP protocol number (6) -> 'tcp
;; port->protocol: port number (53) -> 'dns
;; extract-next-protocol-from-fields: extract next protocol from dissected fields
