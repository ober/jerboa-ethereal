#!/usr/bin/env scheme
;; analysis - Integrated PCAP analysis tool
;; Combines packet dissection with flow analysis and statistics

(import (jerboa prelude))

;; ── Packet Metadata ───────────────────────────────────────────────────────

(def (make-packet-metadata bytes-data)
  "Create packet metadata from raw bytes"
  `((size . ,(bytevector-length bytes-data))
    (timestamp . 0)))

(def (make-dissected-packet metadata layers)
  "Create dissected packet tuple (metadata . layers)"
  (cons metadata layers))

;; ── Protocol Detection ─────────────────────────────────────────────────────

(def (detect-protocol bytes-data)
  "Detect layer-2 protocol from Ethernet frame
   Returns symbol or #f"
  (if (>= (bytevector-length bytes-data) 14)
      (let ((etype (bytevector-u16-ref bytes-data 12 (endianness big))))
        (case etype
          ((#x0800) 'ipv4)
          ((#x0806) 'arp)
          ((#x86DD) 'ipv6)
          (else #f)))
      #f))

;; ── PCAP Reader ───────────────────────────────────────────────────────────

(def (read-pcap-packets file-path)
  (call-with-input-file file-path
    (lambda (port)
      ;; Skip PCAP global header (24 bytes)
      (read-bytevector 24 port)

      (let loop ((packets '()))
        (let ((pkt-header (read-bytevector 16 port)))
          (if (eof-object? pkt-header)
              (reverse packets)
              (let* ((ts-sec (bytevector-u32-ref pkt-header 0 (endianness little)))
                     (capt-len (bytevector-u32-ref pkt-header 8 (endianness little)))
                     (pkt-data (read-bytevector capt-len port)))

                (if (eof-object? pkt-data)
                    (reverse packets)
                    (let ((metadata (make-packet-metadata pkt-data)))
                      (loop (cons (make-dissected-packet metadata '())
                                 packets)))))))))))

;; ── Analysis Functions ─────────────────────────────────────────────────────

(def (analyze-protocols packets)
  "Count packets by detected protocol"
  (let ((proto-count (make-hash-table)))
    (for ((pkt packets))
      (let ((data-info (cdr pkt)))
        ;; Simple protocol detection from Ethernet frame
        (let ((proto (detect-protocol (bytevector 0))))
          (if proto
              (hash-put! proto-count proto
                        (+ 1 (hash-get proto-count proto 0)))))))
    proto-count))

(def (show-help)
  (displayln "")
  (displayln "analysis - Integrated PCAP analysis tool")
  (displayln "════════════════════════════════════════════════════════════")
  (displayln "")
  (displayln "Usage: scheme analysis.ss <pcap-file> <command>")
  (displayln "")
  (displayln "Commands:")
  (displayln "  summary     - Show packet summary")
  (displayln "  protocols   - Show protocol distribution")
  (displayln "  flows       - Show network flows")
  (displayln "  sizes       - Show packet size distribution")
  (displayln "")
  (displayln "Example:")
  (displayln "  scheme analysis.ss capture.pcap summary")
  (displayln "")
  (displayln "Phase 6: Integrated flow and statistics analysis")
  (displayln "")
  (displayln ""))

;; ── Main ────────────────────────────────────────────────────────────────

(let ((args (command-line-arguments)))
  (cond
    ((< (length args) 2)
     (show-help))

    (else
     (let ((pcap-file (car args))
           (command (cadr args)))

       (try
         (displayln (str "Reading PCAP: " pcap-file))
         (let ((packets (read-pcap-packets pcap-file)))
           (displayln (str "Loaded " (length packets) " packets\n"))

           (case (string->symbol command)
             ((summary)
              (displayln "Packet Summary")
              (displayln "════════════════════════════════════════════════════════════")
              (displayln (str "Total packets: " (length packets)))
              (let ((total-size (apply + (map (lambda (p)
                                              (assoc-get (car p) 'size 0))
                                            packets))))
                (displayln (str "Total bytes: " total-size))
                (if (> (length packets) 0)
                    (displayln (str "Avg packet: " (quotient total-size (length packets))))))
              (displayln ""))

             ((protocols)
              (displayln "Protocol Analysis")
              (displayln "════════════════════════════════════════════════════════════")
              (displayln "Layer 2 Protocol Distribution:")
              (displayln "  IPv4 packets: (detection pending)")
              (displayln "  IPv6 packets: (detection pending)")
              (displayln "  ARP packets: (detection pending)")
              (displayln ""))

             ((flows)
              (displayln "Network Flows")
              (displayln "════════════════════════════════════════════════════════════")
              (displayln "Flow analysis requires protocol-layer dissection")
              (displayln "Phase 6 feature: Coming soon")
              (displayln ""))

             ((sizes)
              (displayln "Packet Size Distribution")
              (displayln "════════════════════════════════════════════════════════════")
              (let ((size-dist (make-hash-table)))
                (for ((pkt packets))
                  (let ((size (assoc-get (car pkt) 'size 0)))
                    (let ((bucket (cond
                                    ((< size 64) "< 64B")
                                    ((< size 128) "64-128B")
                                    ((< size 256) "128-256B")
                                    ((< size 512) "256-512B")
                                    ((< size 1024) "512-1KB")
                                    ((< size 2048) "1-2KB")
                                    ((< size 4096) "2-4KB")
                                    ((< size 8192) "4-8KB")
                                    (else "> 8KB"))))
                      (hash-put! size-dist bucket
                                (+ 1 (hash-get size-dist bucket 0))))))

                (let ((sorted (sort (hash->list size-dist)
                                   (lambda (a b) (> (cdr a) (cdr b))))))
                  (for ((entry sorted))
                    (displayln (str (car entry) ": " (cdr entry)))))))
              (displayln ""))

             (else
              (displayln (str "Unknown command: " command))
              (show-help))))

         (catch (e)
           (displayln (str "Error: " e))
           (show-help)))))))
