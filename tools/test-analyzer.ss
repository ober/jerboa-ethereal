#!/usr/bin/env scheme
;; Test Phase 2 analyzer - standalone version with all helpers inlined

(import (jerboa prelude))

;; ── Helper Functions (from protocol.ss) ────────────────────────────────────

(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u32be buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness big)))))

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

(def (validate pred msg)
  (if pred (ok #t) (err msg)))

(def (ethertype->protocol type)
  (case type
    ((#x0800) 'ipv4)
    ((#x0806) 'arp)
    ((#x86DD) 'ipv6)
    (else #f)))

(def (ip-protocol->protocol num)
  (case num
    ((1) 'icmp)
    ((6) 'tcp)
    ((17) 'udp)
    ((58) 'icmpv6)
    (else #f)))

(def (fmt-ipv4 addr)
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (fmt-mac bytes)
  (string-join
    (for/collect ((i (in-range 0 6)))
      (format "~2,'0x" (bytevector-u8-ref bytes i)))
    ":"))

(def (fmt-hex val)
  (if (integer? val)
      (format "0x~x" val)
      (str val)))

;; ── Ethernet Dissector ────────────────────────────────────────────────────

(def (dissect-ethernet buffer)
  (try
    (let* ((dest-mac (unwrap (slice buffer 0 6)))
           (src-mac (unwrap (slice buffer 6 6)))
           (etype-result (read-u16be buffer 12))
           (etype (unwrap etype-result))
           (payload (unwrap (slice buffer 14
                                   (max 0 (- (bytevector-length buffer) 14))))))

      (ok `((dest-mac . ((raw . ,dest-mac)
                        (formatted . ,(fmt-mac dest-mac))))
            (src-mac . ((raw . ,src-mac)
                       (formatted . ,(fmt-mac src-mac))))
            (etype . ((raw . ,etype)
                     (formatted . ,(format-ethertype etype))
                     (next-protocol . ,(ethertype->protocol etype))))
            (payload . ,payload))))

    (catch (e)
      (err (str "Ethernet parse error: " e)))))

(def (format-ethertype type)
  (cond
    ((= type #x0800) "IPv4 (0x0800)")
    ((= type #x0806) "ARP (0x0806)")
    ((= type #x86DD) "IPv6 (0x86DD)")
    (else (format "0x~4,'0x" type))))

;; ── IPv4 Dissector ────────────────────────────────────────────────────────

(def (dissect-ipv4 buffer)
  (try
    (let* ((version-ihl-res (read-u8 buffer 0))
           (version-ihl (unwrap version-ihl-res))
           (version (extract-bits version-ihl #xF0 4))
           (ihl (extract-bits version-ihl #x0F 0))
           (header-len (* ihl 4))

           (dscp-ecn-res (read-u8 buffer 1))
           (dscp-ecn (unwrap dscp-ecn-res))
           (dscp (extract-bits dscp-ecn #xFC 2))
           (ecn (extract-bits dscp-ecn #x03 0))

           (length-res (read-u16be buffer 2))
           (length (unwrap length-res))

           (protocol-res (read-u8 buffer 9))
           (protocol (unwrap protocol-res))

           (src-ip-res (read-u32be buffer 12))
           (src-ip (unwrap src-ip-res))

           (dst-ip-res (read-u32be buffer 16))
           (dst-ip (unwrap dst-ip-res))

           (payload (unwrap (slice buffer header-len
                                   (max 0 (- (bytevector-length buffer) header-len))))))

      (ok `((version . ,version)
            (ihl . ,ihl)
            (header-length . ,header-len)
            (dscp . ,dscp)
            (ecn . ,ecn)
            (total-length . ,length)
            (protocol . ((raw . ,protocol)
                        (formatted . ,(format-ip-protocol protocol))
                        (next-protocol . ,(ip-protocol->protocol protocol))))
            (src-ip . ((raw . ,src-ip)
                      (formatted . ,(fmt-ipv4 src-ip))))
            (dst-ip . ((raw . ,dst-ip)
                      (formatted . ,(fmt-ipv4 dst-ip))))
            (payload . ,payload))))

    (catch (e)
      (err (str "IPv4 parse error: " e)))))

(def (format-ip-protocol num)
  (case num
    ((1) "ICMP")
    ((6) "TCP")
    ((17) "UDP")
    ((58) "ICMPv6")
    (else (str "Proto " num))))

;; ── PCAP Reader ──────────────────────────────────────────────────────────

(def (read-pcap-packets file-path)
  (call-with-input-file file-path
    (lambda (port)
      (let ((skip-header (read-bytevector 24 port)))
        (if (eof-object? skip-header)
            (ok '())
            (let loop ((packets '())
                      (packet-num 0))
              (let ((packet-header (read-bytevector 16 port)))
                (if (or (eof-object? packet-header)
                       (< (bytevector-length packet-header) 16))
                    (ok (reverse packets))
                    (let* ((ts-sec (bytevector-u32-ref packet-header 0 (endianness little)))
                           (ts-usec (bytevector-u32-ref packet-header 4 (endianness little)))
                           (capt-len (bytevector-u32-ref packet-header 8 (endianness little)))
                           (orig-len (bytevector-u32-ref packet-header 12 (endianness little)))
                           (packet-data (read-bytevector capt-len port)))

                      (if (or (eof-object? packet-data)
                             (< (bytevector-length packet-data) capt-len))
                          (ok (reverse packets))
                          (loop (cons `((timestamp . ,ts-sec)
                                       (size . ,capt-len)
                                       (original-size . ,orig-len)
                                       (packet-number . ,packet-num)
                                       (payload . ,packet-data))
                                      packets)
                                (+ packet-num 1))))))))))))

;; ── Dissection Pipeline ───────────────────────────────────────────────────

(def protocol-dissectors (make-hash-table))

(hash-put! protocol-dissectors 'ethernet dissect-ethernet)
(hash-put! protocol-dissectors 'ipv4 dissect-ipv4)

(def (get-dissector name)
  (hash-get protocol-dissectors name))

(def (find-next-protocol proto-name fields)
  (case proto-name
    ((ethernet)
     (let ((etype-field (assoc-get fields 'etype #f)))
       (if etype-field
           (let ((etype (assoc-get etype-field 'raw)))
             (ethertype->protocol etype))
           #f)))
    (else #f)))

(def (dissect-packet buffer (start-proto 'ethernet))
  (dissect-protocol-chain buffer start-proto '()))

(def (dissect-protocol-chain buffer proto-name layers)
  (let ((dissector (get-dissector proto-name)))
    (cond
      ((not dissector)
       (if (null? layers)
           (err (str "Unknown protocol: " proto-name))
           (ok (reverse layers))))

      (else
       (try
         (let ((result (dissector buffer)))
           (cond
             ((err? result)
              (if (null? layers)
                  result
                  (ok (reverse layers))))

             (else
              (let* ((fields (unwrap result))
                     (payload (assoc-get fields 'payload #f))
                     (next-proto (find-next-protocol proto-name fields)))

                (if (and next-proto payload
                        (> (bytevector-length payload) 0))
                    (dissect-protocol-chain payload next-proto
                                           (cons (cons proto-name fields) layers))
                    (ok (reverse (cons (cons proto-name fields) layers))))))))

         (catch (e)
           (if (null? layers)
               (err (str "Dissection error: " e))
               (ok (reverse layers)))))))))

;; ── Main Test ─────────────────────────────────────────────────────────────

(displayln "Test: Phase 2 Analyzer")
(displayln "═══════════════════════════════════════════════════════════")
(displayln "")

;; Create a minimal test packet: 14-byte Ethernet header + 20-byte IPv4 header
(let ((test-pkt (make-bytevector 34)))
  ;; Ethernet: dest MAC, src MAC, EtherType
  (bytevector-u8-set! test-pkt 0 #x00)
  (bytevector-u8-set! test-pkt 1 #x11)
  (bytevector-u8-set! test-pkt 2 #x22)
  (bytevector-u8-set! test-pkt 3 #x33)
  (bytevector-u8-set! test-pkt 4 #x44)
  (bytevector-u8-set! test-pkt 5 #x55)
  (bytevector-u8-set! test-pkt 6 #xaa)
  (bytevector-u8-set! test-pkt 7 #xbb)
  (bytevector-u8-set! test-pkt 8 #xcc)
  (bytevector-u8-set! test-pkt 9 #xdd)
  (bytevector-u8-set! test-pkt 10 #xee)
  (bytevector-u8-set! test-pkt 11 #xff)
  ;; EtherType = 0x0800 (IPv4)
  (bytevector-u16-set! test-pkt 12 #x0800 (endianness big))

  ;; IPv4: Version/IHL = 0x45, DSCP/ECN, Length, Protocol, Src, Dst
  (bytevector-u8-set! test-pkt 14 #x45)  ; Version 4, IHL 5
  (bytevector-u8-set! test-pkt 15 #x00)  ; DSCP 0, ECN 0
  (bytevector-u16-set! test-pkt 16 20 (endianness big))  ; IPv4 header length
  (bytevector-u8-set! test-pkt 23 6)     ; Protocol = TCP
  (bytevector-u32-set! test-pkt 26 (+ (bitwise-arithmetic-shift-left 192 24)
                                      (bitwise-arithmetic-shift-left 168 16)
                                      (bitwise-arithmetic-shift-left 1 8)
                                      100)
                       (endianness big))  ; Src IP = 192.168.1.100
  (bytevector-u32-set! test-pkt 30 (+ (bitwise-arithmetic-shift-left 8 24)
                                      (bitwise-arithmetic-shift-left 8 16)
                                      (bitwise-arithmetic-shift-left 8 8)
                                      8)
                       (endianness big))  ; Dst IP = 8.8.8.8

  (displayln "Test packet created: 34 bytes (Ethernet + IPv4)")
  (displayln "Dissecting...")
  (displayln "")

  (let ((result (dissect-packet test-pkt)))
    (if (ok? result)
        (let ((layers (unwrap result)))
          (displayln "✓ Dissection succeeded!")
          (displayln (str "  Layers: " (map car layers)))
          (displayln "")
          (for ((layer layers))
            (displayln (str (car layer) ":"))
            (for ((field (cdr layer)))
              (let ((name (car field))
                    (value (cdr field)))
                (if (pair? value)
                    (let ((formatted (assoc-get value 'formatted #f)))
                      (if formatted
                          (displayln (str "  " name " = " formatted))))
                    (displayln (str "  " name " = " value)))))
            (displayln "")))
        (displayln (str "✗ Dissection failed: " (unwrap-err result))))))

(displayln "Test complete.")
