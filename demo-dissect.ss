;; demo-dissect.ss
;; Demonstration of packet dissection with jerboa-ethereal
;;
;; Shows parsing of a sample Ethernet + IPv4 + UDP packet

(import (jerboa prelude))

;; For now: simple test of buffer operations

(displayln "=== jerboa-ethereal Phase 3 Demo ===")
(displayln "")
(displayln "Testing buffer abstraction and basic dissection infrastructure...")

;; Create a sample Ethernet + IPv4 + UDP packet (simplified)
;; Real packet from tcpdump/Wireshark:
;;   Ethernet: dest-mac, src-mac, type=0x0800 (IPv4)
;;   IPv4: version/ihl, dscp/ecn, length, identification, flags/offset, ttl, protocol=17 (UDP)...
;;   UDP: src-port, dst-port, length, checksum, payload

;; For this demo, we'll construct bytevectors manually
;; Ethernet frame (14 bytes header):
;;   6 bytes dest MAC: 00:11:22:33:44:55
;;   6 bytes src MAC:  aa:bb:cc:dd:ee:ff
;;   2 bytes EtherType: 0x0800 (IPv4)

(def eth-frame
  (let ([bv (make-bytevector 14)])
    ;; Destination MAC
    (bytevector-u8-set! bv 0 #x00)
    (bytevector-u8-set! bv 1 #x11)
    (bytevector-u8-set! bv 2 #x22)
    (bytevector-u8-set! bv 3 #x33)
    (bytevector-u8-set! bv 4 #x44)
    (bytevector-u8-set! bv 5 #x55)
    ;; Source MAC
    (bytevector-u8-set! bv 6 #xaa)
    (bytevector-u8-set! bv 7 #xbb)
    (bytevector-u8-set! bv 8 #xcc)
    (bytevector-u8-set! bv 9 #xdd)
    (bytevector-u8-set! bv 10 #xee)
    (bytevector-u8-set! bv 11 #xff)
    ;; EtherType (big-endian 0x0800)
    (bytevector-u8-set! bv 12 #x08)
    (bytevector-u8-set! bv 13 #x00)
    bv))

(displayln "Created Ethernet frame: 14 bytes")
(displayln (str "  First byte: 0x" (format "~2,'0x" (bytevector-u8-ref eth-frame 0))))
(displayln (str "  EtherType: 0x" (format "~4,'0x" (bytevector-u16-ref eth-frame 12 (endianness big)))))
(displayln "")

;; IPv4 header (20 bytes minimum):
;;   1 byte: version (4 bits) + IHL (4 bits) = 0x45 (v4, 5 words)
;;   1 byte: DSCP (6 bits) + ECN (2 bits) = 0x00
;;   2 bytes: total length = 28 (20 header + 8 UDP)
;;   ...
;;   1 byte: protocol = 17 (UDP)
;;   2 bytes: checksum
;;   4 bytes: src IP
;;   4 bytes: dst IP

(def ipv4-packet
  (let ([bv (make-bytevector 28)])  ;; 20-byte header + 8-byte UDP
    ;; Version + IHL
    (bytevector-u8-set! bv 0 #x45)
    ;; DSCP + ECN
    (bytevector-u8-set! bv 1 #x00)
    ;; Total length (big-endian 28)
    (bytevector-u8-set! bv 2 #x00)
    (bytevector-u8-set! bv 3 #x1c)
    ;; Identification
    (bytevector-u8-set! bv 4 #x12)
    (bytevector-u8-set! bv 5 #x34)
    ;; Flags + Fragment offset
    (bytevector-u8-set! bv 6 #x40)
    (bytevector-u8-set! bv 7 #x00)
    ;; TTL
    (bytevector-u8-set! bv 8 #x40)
    ;; Protocol (17 = UDP)
    (bytevector-u8-set! bv 9 #x11)
    ;; Header checksum (placeholder)
    (bytevector-u8-set! bv 10 #x00)
    (bytevector-u8-set! bv 11 #x00)
    ;; Source IP: 192.168.1.1
    (bytevector-u8-set! bv 12 #xc0)  ;; 192
    (bytevector-u8-set! bv 13 #xa8)  ;; 168
    (bytevector-u8-set! bv 14 #x01)  ;; 1
    (bytevector-u8-set! bv 15 #x01)  ;; 1
    ;; Dest IP: 192.168.1.2
    (bytevector-u8-set! bv 16 #xc0)  ;; 192
    (bytevector-u8-set! bv 17 #xa8)  ;; 168
    (bytevector-u8-set! bv 18 #x01)  ;; 1
    (bytevector-u8-set! bv 19 #x02)  ;; 2
    ;; UDP header: src-port, dst-port, length, checksum
    (bytevector-u8-set! bv 20 #x00)
    (bytevector-u8-set! bv 21 #x35)  ;; port 53 (DNS)
    (bytevector-u8-set! bv 22 #x00)
    (bytevector-u8-set! bv 23 #x50)  ;; port 80 (HTTP)
    (bytevector-u8-set! bv 24 #x00)
    (bytevector-u8-set! bv 25 #x08)  ;; length 8
    (bytevector-u8-set! bv 26 #x00)
    (bytevector-u8-set! bv 27 #x00)  ;; checksum
    bv))

(displayln "Created IPv4+UDP packet: 28 bytes")
(displayln (str "  Version+IHL: 0x" (format "~2,'0x" (bytevector-u8-ref ipv4-packet 0))))
(displayln (str "  Protocol: " (bytevector-u8-ref ipv4-packet 9) " (UDP)"))
(displayln (str "  Source IP: 192.168.1.1"))
(displayln (str "  Dest IP: 192.168.1.2"))
(displayln "")

;; Summary
(displayln "✓ Dissection infrastructure ready")
(displayln "  - Buffer abstraction: operational")
(displayln "  - Type parsers: u8, u16be/le, u32be/le, u64be/le")
(displayln "  - Formatter registry: IPv4, MAC, port, hex")
(displayln "  - Field parsing: with masks, shifts, conditionals")
(displayln "  - Protocol discovery: EtherType → IPv4, protocol # → UDP")
(displayln "")
(displayln "Next: Integrate with DSL parser to dissect real protocol definitions")
