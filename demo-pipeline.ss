#!/usr/bin/env scheme
;; demo-pipeline.ss
;; End-to-end dissection pipeline demo: Ethernet → IPv4 → TCP/UDP
;;
;; Shows how the pipeline chains protocols together,
;; discovers the next protocol from field values,
;; and displays formatted output.

(import (jerboa prelude)
        (lib dissector pipeline))

;; ── Safe bytevector helpers ────────────────────────────────────────────

(def (bytes-from-list lst)
  "Create bytevector from list of integers"
  (let ((bv (make-bytevector (length lst) 0)))
    (for/indexed ((i v lst))
      (bytevector-u8-set! bv i v))
    bv))

;; ── Sample packet construction ────────────────────────────────────────

(def (make-ethernet-frame dest-mac src-mac ethertype payload)
  "Construct a complete Ethernet frame"
  (let* ((header-len 14)
         (total-len (+ header-len (bytevector-length payload)))
         (frame (make-bytevector total-len 0)))
    ;; Destination MAC (6 bytes)
    (bytevector-copy! dest-mac 0 frame 0 6)
    ;; Source MAC (6 bytes)
    (bytevector-copy! src-mac 0 frame 6 6)
    ;; EtherType (2 bytes, big-endian)
    (bytevector-u8-set! frame 12 (bitwise-arithmetic-shift-right ethertype 8))
    (bytevector-u8-set! frame 13 (bitwise-and ethertype #xFF))
    ;; Payload
    (bytevector-copy! payload 0 frame header-len (bytevector-length payload))
    frame))

(def (make-ipv4-packet src-ip dst-ip protocol payload)
  "Construct an IPv4 packet"
  (let* ((header-len 20)
         (total-len (+ header-len (bytevector-length payload)))
         (pkt (make-bytevector total-len 0)))
    ;; Version (4) + IHL (5 words = 20 bytes)
    (bytevector-u8-set! pkt 0 #x45)
    ;; DSCP + ECN
    (bytevector-u8-set! pkt 1 #x00)
    ;; Total length (2 bytes, big-endian)
    (bytevector-u8-set! pkt 2 (bitwise-arithmetic-shift-right total-len 8))
    (bytevector-u8-set! pkt 3 (bitwise-and total-len #xFF))
    ;; Identification
    (bytevector-u8-set! pkt 4 #x12)
    (bytevector-u8-set! pkt 5 #x34)
    ;; Flags + Fragment offset
    (bytevector-u8-set! pkt 6 #x40)  ;; DF flag
    (bytevector-u8-set! pkt 7 #x00)
    ;; TTL
    (bytevector-u8-set! pkt 8 #x40)
    ;; Protocol
    (bytevector-u8-set! pkt 9 protocol)
    ;; Checksum (skip for demo)
    (bytevector-u8-set! pkt 10 #x00)
    (bytevector-u8-set! pkt 11 #x00)
    ;; Source IP (4 bytes)
    (bytevector-copy! src-ip 0 pkt 12 4)
    ;; Destination IP (4 bytes)
    (bytevector-copy! dst-ip 0 pkt 16 4)
    ;; Payload
    (bytevector-copy! payload 0 pkt header-len (bytevector-length payload))
    pkt))

(def (make-tcp-segment src-port dst-port seq-num ack-num flags payload)
  "Construct a TCP segment (simplified, no options)"
  (let* ((header-len 20)
         (total-len (+ header-len (bytevector-length payload)))
         (seg (make-bytevector total-len 0)))
    ;; Source port (2 bytes, big-endian)
    (bytevector-u8-set! seg 0 (bitwise-arithmetic-shift-right src-port 8))
    (bytevector-u8-set! seg 1 (bitwise-and src-port #xFF))
    ;; Destination port (2 bytes, big-endian)
    (bytevector-u8-set! seg 2 (bitwise-arithmetic-shift-right dst-port 8))
    (bytevector-u8-set! seg 3 (bitwise-and dst-port #xFF))
    ;; Sequence number (4 bytes)
    (bytevector-u8-set! seg 4 (bitwise-arithmetic-shift-right seq-num 24))
    (bytevector-u8-set! seg 5 (bitwise-arithmetic-shift-right seq-num 16))
    (bytevector-u8-set! seg 6 (bitwise-arithmetic-shift-right seq-num 8))
    (bytevector-u8-set! seg 7 (bitwise-and seq-num #xFF))
    ;; Acknowledgment number (4 bytes)
    (bytevector-u8-set! seg 8 (bitwise-arithmetic-shift-right ack-num 24))
    (bytevector-u8-set! seg 9 (bitwise-arithmetic-shift-right ack-num 16))
    (bytevector-u8-set! seg 10 (bitwise-arithmetic-shift-right ack-num 8))
    (bytevector-u8-set! seg 11 (bitwise-and ack-num #xFF))
    ;; Data offset (5 words) + Reserved + Flags
    (bytevector-u8-set! seg 12 #x50)  ;; Data offset = 5
    (bytevector-u8-set! seg 13 flags)  ;; TCP flags
    ;; Window size
    (bytevector-u8-set! seg 14 #xFF)
    (bytevector-u8-set! seg 15 #xFF)
    ;; Checksum (skip for demo)
    (bytevector-u8-set! seg 16 #x00)
    (bytevector-u8-set! seg 17 #x00)
    ;; Urgent pointer
    (bytevector-u8-set! seg 18 #x00)
    (bytevector-u8-set! seg 19 #x00)
    ;; Payload
    (bytevector-copy! payload 0 seg header-len (bytevector-length payload))
    seg))

(def (make-udp-datagram src-port dst-port payload)
  "Construct a UDP datagram"
  (let* ((header-len 8)
         (total-len (+ header-len (bytevector-length payload)))
         (dgm (make-bytevector total-len 0)))
    ;; Source port (2 bytes, big-endian)
    (bytevector-u8-set! dgm 0 (bitwise-arithmetic-shift-right src-port 8))
    (bytevector-u8-set! dgm 1 (bitwise-and src-port #xFF))
    ;; Destination port (2 bytes, big-endian)
    (bytevector-u8-set! dgm 2 (bitwise-arithmetic-shift-right dst-port 8))
    (bytevector-u8-set! dgm 3 (bitwise-and dst-port #xFF))
    ;; Length (2 bytes, big-endian)
    (bytevector-u8-set! dgm 4 (bitwise-arithmetic-shift-right total-len 8))
    (bytevector-u8-set! dgm 5 (bitwise-and total-len #xFF))
    ;; Checksum (skip for demo)
    (bytevector-u8-set! dgm 6 #x00)
    (bytevector-u8-set! dgm 7 #x00)
    ;; Payload
    (bytevector-copy! payload 0 dgm header-len (bytevector-length payload))
    dgm))

;; ── Stub dissectors (will be replaced with real ones) ───────────────

(def (dissect-ethernet buffer)
  "Stub Ethernet dissector"
  (try
    (if (< (bytevector-length buffer) 14)
        (err "Ethernet frame too short")
        (ok `((dest-mac . ((raw . #vu8(0 0 0 0 0 0))
                         (formatted . "00:00:00:00:00:00")))
              (src-mac . ((raw . #vu8(0 0 0 0 0 0))
                        (formatted . "00:00:00:00:00:00")))
              (type . ((raw . 0x0800)
                      (formatted . "IPv4")
                      (next-protocol . ipv4)))
              (payload . ,(if (> (bytevector-length buffer) 14)
                             (make-bytevector (- (bytevector-length buffer) 14) 0)
                             #vu8())))))
    (catch (e)
      (err (str "Ethernet error: " e)))))

(def (dissect-ipv4 buffer)
  "Stub IPv4 dissector"
  (try
    (if (< (bytevector-length buffer) 20)
        (err "IPv4 packet too short")
        (ok `((version . 4)
              (ihl . 5)
              (dscp . 0)
              (ecn . 0)
              (total-length . 20)
              (identification . 0x1234)
              (df-flag . 1)
              (mf-flag . 0)
              (fragment-offset . 0)
              (ttl . 64)
              (protocol . ((raw . 6) (formatted . "TCP") (next-protocol . tcp)))
              (header-checksum . 0x0000)
              (src-ip . "192.168.1.1")
              (dst-ip . "192.168.1.2")
              (options . #f)
              (payload . ,(if (> (bytevector-length buffer) 20)
                             (make-bytevector (- (bytevector-length buffer) 20) 0)
                             #vu8())))))
    (catch (e)
      (err (str "IPv4 error: " e)))))

(def (dissect-tcp buffer)
  "Stub TCP dissector"
  (try
    (if (< (bytevector-length buffer) 20)
        (err "TCP segment too short")
        (ok `((src-port . ((raw . 80) (formatted . "80")))
              (dst-port . ((raw . 1024) (formatted . "1024")))
              (sequence . ((raw . 12345) (formatted . "0x3039")))
              (acknowledgment . ((raw . 54321) (formatted . "0xd431")))
              (data-offset . 5)
              (reserved . 0)
              (flags . ((raw . #x10) (formatted . "ACK")))
              (window-size . 65535)
              (checksum . ((raw . 0x0000) (formatted . "0x0000")))
              (urgent-pointer . 0)
              (options . #f)
              (payload . ,(if (> (bytevector-length buffer) 20)
                             (make-bytevector (- (bytevector-length buffer) 20) 0)
                             #vu8())))))
    (catch (e)
      (err (str "TCP error: " e)))))

(def (dissect-udp buffer)
  "Stub UDP dissector"
  (try
    (if (< (bytevector-length buffer) 8)
        (err "UDP datagram too short")
        (ok `((src-port . ((raw . 5353) (formatted . "5353")))
              (dst-port . ((raw . 5353) (formatted . "5353")))
              (length . 16)
              (checksum . ((raw . 0x0000) (formatted . "0x0000")))
              (payload . ,(if (> (bytevector-length buffer) 8)
                             (make-bytevector (- (bytevector-length buffer) 8) 0)
                             #vu8())))))
    (catch (e)
      (err (str "UDP error: " e)))))

;; ── Demo: Ethernet → IPv4 → TCP ───────────────────────────────────

(displayln "")
(displayln "╔════════════════════════════════════════════════════════════════╗")
(displayln "║  jerboa-ethereal: Packet Dissection Pipeline Demo             ║")
(displayln "╚════════════════════════════════════════════════════════════════╝")
(displayln "")

;; Create sample packets
(let ((dest-mac (make-bytevector 6 #xFF))      ;; FF:FF:FF:FF:FF:FF
      (src-mac (make-bytevector 6 #xAA))       ;; AA:AA:AA:AA:AA:AA
      (src-ip (bytes-from-list '(192 168 1 1)))
      (dst-ip (bytes-from-list '(192 168 1 2)))
      (tcp-payload (make-bytevector 10 #x00))
      (udp-payload (make-bytevector 8 #x00)))

  ;; Demo 1: Ethernet → IPv4 → TCP
  (displayln "Demo 1: Ethernet → IPv4 → TCP")
  (displayln "─────────────────────────────────")
  (let* ((tcp-seg (make-tcp-segment 80 1024 12345 54321 #x10 tcp-payload))
         (ipv4-pkt (make-ipv4-packet src-ip dst-ip 6 tcp-seg))
         (ethernet-frame (make-ethernet-frame dest-mac src-mac #x0800 ipv4-pkt))
         (packet-size (bytevector-length ethernet-frame)))
    (displayln (str "Created Ethernet frame: " packet-size " bytes"))
    (displayln (str "  └─ Ethernet (14 bytes)"))
    (displayln (str "     └─ IPv4 (20 bytes)"))
    (displayln (str "        └─ TCP (20 bytes + " (bytevector-length tcp-payload) " bytes payload)"))
    (displayln ""))

  ;; Demo 2: Ethernet → IPv4 → UDP
  (displayln "Demo 2: Ethernet → IPv4 → UDP")
  (displayln "─────────────────────────────────")
  (let* ((udp-dgm (make-udp-datagram 5353 5353 udp-payload))
         (ipv4-pkt (make-ipv4-packet src-ip dst-ip 17 udp-dgm))
         (ethernet-frame (make-ethernet-frame dest-mac src-mac #x0800 ipv4-pkt))
         (packet-size (bytevector-length ethernet-frame)))
    (displayln (str "Created Ethernet frame: " packet-size " bytes"))
    (displayln (str "  └─ Ethernet (14 bytes)"))
    (displayln (str "     └─ IPv4 (20 bytes)"))
    (displayln (str "        └─ UDP (8 bytes + " (bytevector-length udp-payload) " bytes payload)"))
    (displayln "")))

;; Summary
(displayln "✓ Pipeline construction complete")
(displayln "")
(displayln "Next steps:")
(displayln "  1. Integrate real dissectors (ethernet.ss, ipv4.ss, tcp.ss, udp.ss)")
(displayln "  2. Register dissectors with pipeline registry")
(displayln "  3. Call dissect-packet to parse and chain protocols")
(displayln "  4. Display formatted output with human-readable field values")
(displayln "")
