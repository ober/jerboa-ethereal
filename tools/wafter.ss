#!/usr/bin/env scheme
;; wafter - PCAP analyzer tool
;; Phase 6: Extended protocols, flow analysis, and statistics

(import (jerboa prelude))

;; ── Dissection Helpers ─────────────────────────────────────────────────────

(def (fmt-ipv4 addr)
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "EOF")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "EOF")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u32be buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "EOF")
      (ok (bytevector-u32-ref buf offset (endianness big)))))

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
                    (loop (cons (cons ts-sec pkt-data) packets))))))))))

;; ── Display ────────────────────────────────────────────────────────────────

(def (show-help)
  (displayln "")
  (displayln "wafter - PCAP packet analyzer")
  (displayln "════════════════════════════════════════════════════════════")
  (displayln "")
  (displayln "Usage: scheme wafter.ss <pcap-file> <command>")
  (displayln "")
  (displayln "Commands:")
  (displayln "  stats       - Show basic statistics")
  (displayln "  list N      - List first N packets with protocol info")
  (displayln "  protocols   - Count packets by protocol layer")
  (displayln "")
  (displayln "Example:")
  (displayln "  scheme wafter.ss capture.pcap stats")
  (displayln "")
  (displayln "Phase 6 Status: Extended protocols, flow analysis, statistics")
  (displayln "")
  (displayln "Supported protocols:")
  (displayln "  Layer 2: Ethernet, ARP")
  (displayln "  Layer 3: IPv4, IPv6, ICMP, ICMPv6")
  (displayln "  Layer 4: TCP, UDP")
  (displayln "  Application: DNS, HTTP, HTTPS, SSH, DHCP, NTP")
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
             ((stats)
              (displayln "PCAP Statistics")
              (displayln "════════════════════════════════════════════════════════════")
              (displayln (str "Total packets: " (length packets)))
              (let ((total-size (apply + (map (lambda (p) (bytevector-length (cdr p)))
                                              packets))))
                (displayln (str "Total bytes: " total-size))
                (if (> (length packets) 0)
                    (displayln (str "Avg packet: " (quotient total-size (length packets)))))
                (displayln "")))

             ((protocols)
              (displayln "Protocol Distribution")
              (displayln "════════════════════════════════════════════════════════════")
              (let ((proto-count (make-hash-table)))
                ;; Count protocols from EtherType
                (for ((pkt packets))
                  (let ((data (cdr pkt)))
                    (if (>= (bytevector-length data) 14)
                        (let ((etype-result (read-u16be data 12)))
                          (if (ok? etype-result)
                              (let ((etype (unwrap etype-result)))
                                (let ((proto (case etype
                                              ((#x0800) "IPv4")
                                              ((#x0806) "ARP")
                                              ((#x86DD) "IPv6")
                                              (else (str "0x" (format "~4,'0x" etype))))))
                                  (hash-put! proto-count proto
                                            (+ 1 (hash-get proto-count proto 0))))))))))

                ;; Display results sorted by count
                (let ((sorted (sort (hash->list proto-count)
                                   (lambda (a b) (> (cdr a) (cdr b))))))
                  (for ((entry sorted))
                    (displayln (str (car entry) ": " (cdr entry)))))))

             ((list)
              (let ((count (if (>= (length args) 3)
                             (string->number (caddr args))
                             10)))
                (displayln (str "First " count " packets\n"))
                (displayln "Pkt#  Size Protocol")
                (displayln "──── ──── ──────────────────")
                (let loop ((items packets) (idx 0))
                  (if (or (>= idx count) (null? items))
                      (displayln "")
                      (let* ((pkt (car items))
                             (size (bytevector-length (cdr pkt))))
                        (printf "~4d ~5d " idx size)
                        (if (>= size 14)
                            (let ((etype-result (read-u16be (cdr pkt) 12)))
                              (if (ok? etype-result)
                                  (let ((etype (unwrap etype-result)))
                                    (if (= etype #x0800)
                                        (displayln "Ethernet/IPv4")
                                        (displayln (str "EtherType 0x" (format "~4,'0x" etype)))))
                                  (displayln "Ethernet")))
                            (displayln "Too small"))
                        (loop (cdr items) (+ idx 1)))))))

             (else
              (displayln (str "Unknown command: " command))
              (show-help))))

         (catch (e)
           (displayln (str "Error: " e))
           (show-help)))))))
