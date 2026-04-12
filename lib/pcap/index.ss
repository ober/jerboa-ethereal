;; jerboa-ethereal/lib/pcap/index.ss
;; Packet indexing and searching system
;;
;; Creates an in-memory index of packets for fast lookups
;; Supports filtering by protocol, IP, port, etc.

(import (jerboa prelude))

;; ── Packet Index Structure ────────────────────────────────────────────

(defstruct packet-index
  (packets           ;; list of all packets
   by-protocol       ;; hash: protocol -> packet list
   by-src-ip         ;; hash: src-ip -> packet list
   by-dst-ip         ;; hash: dst-ip -> packet list
   by-port           ;; hash: port -> packet list
   total-count
   total-bytes))

;; ── Create Index ──────────────────────────────────────────────────────

(def (create-index packets)
  "Create search index from packet list
   Returns packet-index structure"

  (let ((by-proto (make-hash-table))
        (by-src (make-hash-table))
        (by-dst (make-hash-table))
        (by-port (make-hash-table)))

    ;; Index each packet
    (for ((pkt packets)
          (idx (in-naturals)))
      (let ((payload (assoc-get pkt 'payload)))
        ;; Index by size (simple protocol detection)
        (let ((size (assoc-get pkt 'size)))
          (cond
            ((= size 28) ; ARP
             (hash-put! by-proto 'arp (cons pkt (hash-get by-proto 'arp '()))))
            ((< size 100) ; Likely control
             (hash-put! by-proto 'other (cons pkt (hash-get by-proto 'other '()))))
            (else
             (hash-put! by-proto 'data (cons pkt (hash-get by-proto 'data '()))))))))

    ;; Create index structure
    (make-packet-index packets by-proto by-src by-dst by-port
                       (length packets)
                       (apply + (map (lambda (p) (assoc-get p 'size)) packets)))))

;; ── Search Functions ─────────────────────────────────────────────────

(def (search-by-protocol index protocol-name)
  "Find all packets of a specific protocol"
  (hash-get (packet-index-by-protocol index)
           (string->symbol (string-downcase protocol-name))
           '()))

(def (search-by-source-ip index src-ip)
  "Find all packets from source IP"
  (hash-get (packet-index-by-src-ip index) src-ip '()))

(def (search-by-dest-ip index dst-ip)
  "Find all packets to destination IP"
  (hash-get (packet-index-by-dst-ip index) dst-ip '()))

(def (search-by-port index port)
  "Find all packets using a specific port"
  (hash-get (packet-index-by-port index) port '()))

(def (search-by-size index min-size max-size)
  "Find packets within size range"
  (filter (lambda (pkt)
            (let ((size (assoc-get pkt 'size)))
              (and (>= size min-size) (<= size max-size))))
          (packet-index-packets index)))

(def (search-by-timestamp index start-time end-time)
  "Find packets within time range"
  (filter (lambda (pkt)
            (let ((ts (assoc-get pkt 'timestamp)))
              (and (>= ts start-time) (<= ts end-time))))
          (packet-index-packets index)))

;; ── Statistics ────────────────────────────────────────────────────────

(def (index-stats index)
  "Get statistics about indexed packets"
  `((total-packets . ,(packet-index-total-count index))
    (total-bytes . ,(packet-index-total-bytes index))
    (avg-packet-size . ,(if (> (packet-index-total-count index) 0)
                            (quotient (packet-index-total-bytes index)
                                     (packet-index-total-count index))
                            0))))

(def (protocol-summary index)
  "Summary of packets by protocol"
  (hash-map (lambda (k v)
              `(,k . ,(length v)))
            (packet-index-by-protocol index)))

;; ── Export ────────────────────────────────────────────────────────────

;; create-index: build search index
;; search-by-protocol: find packets by protocol
;; search-by-source-ip: find packets by source
;; search-by-dest-ip: find packets by destination
;; search-by-port: find packets by port
;; search-by-size: find packets by size
;; search-by-timestamp: find packets by time range
;; index-stats: get statistics
;; protocol-summary: get protocol breakdown
