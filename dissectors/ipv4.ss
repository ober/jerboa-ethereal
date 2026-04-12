;; jerboa-ethereal/dissectors/ipv4.ss
;; RFC 791: Internet Protocol Version 4
;;
;; Production dissector with inline safety and error handling.

(import (jerboa prelude)
        (lib dissector protocol))

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

  (try-result
    ;; Byte 0: version + IHL
    (let* ((b0-res (read-u8 buffer 0))
           (b0 (unwrap b0-res))
           (version (extract-bits b0 #xF0 4))
           (ihl (extract-bits b0 #x0F 0))

           ;; Validate version and IHL
           (_ (unwrap (validate (= version 4) "Invalid IPv4 version")))
           (_ (unwrap (validate (>= ihl 5) "IHL too small")))

           ;; Byte 1: DSCP + ECN
           (b1-res (read-u8 buffer 1))
           (b1 (unwrap b1-res))
           (dscp (extract-bits b1 #xFC 2))
           (ecn (extract-bits b1 #x03 0))

           ;; Bytes 2-3: Total length
           (tlen-res (read-u16be buffer 2))
           (total-length (unwrap tlen-res))
           (_ (unwrap (validate (>= total-length 20) "Packet too short")))

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