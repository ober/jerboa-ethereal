;; jerboa-ethereal/lib/dissector/protocol.ss
;; Protocol dissection: safe, fast, handles malformed packets
;;
;; Key principles:
;; - ALL safety checks INLINE (no runtime interpretation)
;; - Result types for error handling
;; - Zero boilerplate
;; - Tight, readable code
;; - Handles corruption gracefully

(import (jerboa prelude))

;; ── Safe Reading Primitives ────────────────────────────────────────────────

(def (read-u8 buf offset)
  "Read u8 at offset, returns (ok val) or (err msg)"
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  "Read u16 big-endian at offset"
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u32be buf offset)
  "Read u32 big-endian at offset"
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness big)))))

(def (read-u16le buf offset)
  "Read u16 little-endian at offset"
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness little)))))

(def (read-u32le buf offset)
  "Read u32 little-endian at offset"
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness little)))))

(def (slice buf offset len)
  "Extract slice [offset, offset+len), returns (ok bytes) or (err msg)"
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

;; ── Bitfield Extraction ────────────────────────────────────────────────────

(def (extract-bits val mask shift)
  "Extract masked bits and shift: (extract-bits #b11110000 #xF0 4) → top nibble"
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

;; ── Validation Helpers ────────────────────────────────────────────────────

(def (validate pred msg)
  "Check predicate, return (err msg) or (ok #t)"
  (if pred (ok #t) (err msg)))

;; ── Protocol Discovery ────────────────────────────────────────────────────

(def (ethertype->protocol type)
  "Map EtherType to protocol name"
  (cond
    ((= type #x0800) 'ipv4)
    ((= type #x0806) 'arp)
    ((= type #x86DD) 'ipv6)
    ((= type #x8100) 'vlan)
    (#t #f)))

(def (ip-protocol->protocol num)
  "Map IP protocol number to protocol name"
  (cond
    ((= num 1) 'icmp)
    ((= num 6) 'tcp)
    ((= num 17) 'udp)
    ((= num 41) 'ipv6)
    ((= num 47) 'gre)
    ((= num 50) 'esp)
    ((= num 51) 'ah)
    ((= num 58) 'icmpv6)
    (#t #f)))

;; ── Formatters ────────────────────────────────────────────────────────────

(def (fmt-ipv4 addr)
  "Convert u32 to a.b.c.d"
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (fmt-mac bytes)
  "Convert 6-byte MAC to xx:xx:xx:xx:xx:xx"
  (string-join
    (for/collect ((i (in-range 0 6)))
      (format "~2,'0x" (bytevector-u8-ref bytes i)))
    ":"))

(def (fmt-hex val)
  "Format as 0xHEXHEX"
  (if (integer? val)
      (format "0x~x" val)
      (str val)))

(def (fmt-port port-num)
  "Port number with service name lookup"
  (let ((services '((22 . "ssh") (80 . "http") (443 . "https")
                    (53 . "dns") (123 . "ntp") (3306 . "mysql")
                    (5432 . "postgres") (6379 . "redis"))))
    (let ((svc (assoc-in services port-num)))
      (if svc (str (cdr svc) " (" port-num ")") (str port-num)))))

;; ── Field Assembly ────────────────────────────────────────────────────────
;; Helper to create field records consistently

(def (field name raw formatted)
  "Create field record: (name . (raw . formatted))"
  (cons name (cons raw formatted)))

(def (field-with-next name raw formatted next-proto)
  "Create field record with protocol chaining info"
  (cons name `((raw . ,raw)
               (formatted . ,formatted)
               (next . ,next-proto))))