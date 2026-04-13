;; jerboa-ethereal/dissectors/ipv4.ss
;; RFC 791: Internet Protocol Version 4
;;
;; Production dissector with inline safety and error handling.

(import (jerboa prelude))

;; ── Safe Reading Primitives (inlined from lib/dissector/protocol.ss) ─────

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

(def (extract-bits val mask shift)
  "Extract masked bits and shift"
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

(def (validate pred msg)
  "Check predicate, return (err msg) or (ok #t)"
  (if pred (ok #t) (err msg)))

(def (slice buf offset len)
  "Extract slice [offset, offset+len), returns (ok bytes) or (err msg)"
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (fmt-ipv4 addr)
  "Convert u32 to a.b.c.d"
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

;; ── IPv4 Dissector ────────────────────────────────────────────────────────

(def (dissect-ipv4 buffer)
  "Parse IPv4 packet from bytevector
   Returns (ok fields) or (err message)

   Handles:
   - Truncated packets
   - Invalid version/IHL
   - Corrupt headers
   - Any bytevector size

   Structure (20-byte minimum):
   [0]     version (4b) + IHL (4b)
   [1]     DSCP (6b) + ECN (2b)
   [2:4)   total length
   [4:6)   identification
   [6:8)   flags + fragment offset
   [8]     TTL
   [9]     protocol number
   [10:12) header checksum
   [12:16) source IP
   [16:20) destination IP
   [20:)   options (if IHL > 5) + payload"

  (try
    ;; Byte 0: version + IHL
    (let* ((b0-res (read-u8 buffer 0))
           (b0 (unwrap b0-res))
           (version (extract-bits b0 #xF0 4))
           (ihl (extract-bits b0 #x0F 0))

           ;; Validate version and IHL
           (-v1 (unwrap (validate (= version 4) "Invalid IPv4 version")))
           (-v2 (unwrap (validate (>= ihl 5) "IHL too small")))

           ;; Byte 1: DSCP + ECN
           (b1-res (read-u8 buffer 1))
           (b1 (unwrap b1-res))
           (dscp (extract-bits b1 #xFC 2))
           (ecn (extract-bits b1 #x03 0))

           ;; Bytes 2-3: Total length
           (tlen-res (read-u16be buffer 2))
           (total-length (unwrap tlen-res))
           (-v3 (unwrap (validate (>= total-length 20) "Packet too short")))

           ;; Bytes 4-5: Identification
           (id-res (read-u16be buffer 4))
           (id (unwrap id-res))

           ;; Bytes 6-7: Flags + Fragment Offset
           (flags-res (read-u16be buffer 6))
           (flags-word (unwrap flags-res))
           (df-flag (extract-bits flags-word #x4000 14))
           (mf-flag (extract-bits flags-word #x2000 13))
           (frag-offset (extract-bits flags-word #x1FFF 0))

           ;; Byte 8: TTL
           (ttl-res (read-u8 buffer 8))
           (ttl (unwrap ttl-res))

           ;; Byte 9: Protocol
           (proto-res (read-u8 buffer 9))
           (proto (unwrap proto-res))

           ;; Bytes 10-11: Checksum
           (checksum-res (read-u16be buffer 10))
           (checksum (unwrap checksum-res))

           ;; Bytes 12-15: Source IP
           (src-ip-res (read-u32be buffer 12))
           (src-ip (unwrap src-ip-res))

           ;; Bytes 16-19: Destination IP
           (dst-ip-res (read-u32be buffer 16))
           (dst-ip (unwrap dst-ip-res))

           ;; Header length in bytes
           (header-len (* ihl 4))

           ;; Options (if IHL > 5)
           (options (if (> ihl 5)
                        (unwrap (slice buffer 20 (- header-len 20)))
                        #f))

           ;; Payload
           (payload (unwrap (slice buffer header-len
                                   (max 0 (- total-length header-len))))))

      ;; Return structured packet
      (ok `((version . ,version)
            (ihl . ,ihl)
            (dscp . ,dscp)
            (ecn . ,ecn)
            (total-length . ,total-length)
            (identification . ((raw . ,id)
                              (formatted . ,(fmt-hex id))))
            (df-flag . (= df-flag 1))
            (mf-flag . (= mf-flag 1))
            (fragment-offset . ,frag-offset)
            (ttl . ,ttl)
            (protocol . ((raw . ,proto)
                        (formatted . ,(format-ip-protocol proto))
                        (next-protocol . ,(ip-protocol->protocol proto))))
            (checksum . ((raw . ,checksum)
                        (formatted . ,(fmt-hex checksum))))
            (src-ip . ((raw . ,src-ip)
                      (formatted . ,(fmt-ipv4 src-ip))))
            (dst-ip . ((raw . ,dst-ip)
                      (formatted . ,(fmt-ipv4 dst-ip))))
            (options . ,options)
            (payload . ,payload))))

    ;; Catch errors with clear messages
    (catch (e)
      (err (str "IPv4 parse error: " e)))))

;; ── IP Protocol Number Formatter ───────────────────────────────────────────

(def (format-ip-protocol num)
  "Format IP protocol number with name"
  (cond
    ((= num 0) "HOPOPT")
    ((= num 1) "ICMP")
    ((= num 2) "IGMP")
    ((= num 6) "TCP")
    ((= num 17) "UDP")
    ((= num 41) "IPv6")
    ((= num 47) "GRE")
    ((= num 50) "ESP")
    ((= num 51) "AH")
    ((= num 58) "ICMPv6")
    ((= num 112) "VRRP")
    (#t (str "proto-" num))))

;; ── Exported API ───────────────────────────────────────────────────────────

;; dissect-ipv4: main entry point
;; format-ip-protocol: formatter for display