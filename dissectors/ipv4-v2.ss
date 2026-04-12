;; jerboa-ethereal/dissectors/ipv4-v2.ss
;; RFC 791: Internet Protocol Version 4 (Code-Generated Dissector)

(import (jerboa prelude)
        (lib dsl defprotocol))

;; ── IPv4 Dissector ─────────────────────────────────────────────────────────

(def (dissect-ipv4 buffer)
  "Parse IPv4 packet, returns (ok fields) or (err message)
   Handles truncated packets, corrupt fields, etc."

  (try-result
    ;; Byte 0: version (upper 4 bits) + IHL (lower 4 bits)
    (let* ((b0-result (safe-read-u8 buffer 0))
           (b0 (unwrap b0-result))
           (version (bitwise-arithmetic-shift-right b0 4))
           (ihl (bitwise-and b0 #x0F))

           ;; Validate version and IHL
           (_ (when (not (= version 4))
                (throw (str "IPv4: invalid version " version))))
           (_ (when (< ihl 5)
                (throw "IPv4: IHL too small (< 5)")))

           ;; Byte 1: DSCP (6 bits) + ECN (2 bits)
           (b1-result (safe-read-u8 buffer 1))
           (b1 (unwrap b1-result))
           (dscp (bitwise-arithmetic-shift-right b1 2))
           (ecn (bitwise-and b1 #x03))

           ;; Bytes 2-3: Total length (big-endian)
           (total-length-result (safe-read-u16be buffer 2))
           (total-length (unwrap total-length-result))
           (_ (when (< total-length 20)
                (throw "IPv4: packet too short")))

           ;; Bytes 4-5: Identification
           (id-result (safe-read-u16be buffer 4))
           (id (unwrap id-result))

           ;; Bytes 6-7: Flags + Fragment Offset
           (flags-result (safe-read-u16be buffer 6))
           (flags-word (unwrap flags-result))
           (df-flag (bitwise-arithmetic-shift-right flags-word 14))
           (mf-flag (bitwise-arithmetic-shift-right (bitwise-and flags-word #x2000) 13))
           (frag-offset (bitwise-and flags-word #x1FFF))

           ;; Byte 8: TTL
           (ttl-result (safe-read-u8 buffer 8))
           (ttl (unwrap ttl-result))

           ;; Byte 9: Protocol number
           (proto-result (safe-read-u8 buffer 9))
           (proto (unwrap proto-result))

           ;; Bytes 10-11: Header checksum
           (checksum-result (safe-read-u16be buffer 10))
           (checksum (unwrap checksum-result))

           ;; Bytes 12-15: Source IP
           (src-ip-result (safe-read-u32be buffer 12))
           (src-ip (unwrap src-ip-result))

           ;; Bytes 16-19: Destination IP
           (dst-ip-result (safe-read-u32be buffer 16))
           (dst-ip (unwrap dst-ip-result))

           ;; Options (if IHL > 5): 4*(IHL-5) bytes
           (header-len (* ihl 4))
           (options-result (if (> ihl 5)
                               (safe-slice buffer 20 (- header-len 20))
                               (ok #f)))
           (options (unwrap options-result))

           ;; Payload: remaining bytes
           (payload-result (safe-slice buffer header-len
                                       (- total-length header-len)))
           (payload (unwrap payload-result)))

      ;; Return structured packet
      (ok (alist
            (version . version)
            (ihl . ihl)
            (dscp . dscp)
            (ecn . ecn)
            (total-length . total-length)
            (identification . id)
            (df . (= df-flag 1))
            (mf . (= mf-flag 1))
            (fragment-offset . frag-offset)
            (ttl . ttl)
            (protocol . (alist (raw . proto)
                              (formatted . (format-ip-protocol proto))
                              (next-protocol . (ip-protocol->protocol proto))))
            (checksum . checksum)
            (src-ip . (alist (raw . src-ip)
                            (formatted . (fmt-ipv4 src-ip))))
            (dst-ip . (alist (raw . dst-ip)
                            (formatted . (fmt-ipv4 dst-ip))))
            (options . options)
            (payload . payload))))

    (catch (e)
      (err (str "IPv4 parse error: " e)))))

;; ── IP Protocol Number Formatter ───────────────────────────────────────────

(def (format-ip-protocol num)
  "Format IP protocol number with name"
  (case num
    ((0) "HOPOPT")
    ((1) "ICMP")
    ((2) "IGMP")
    ((6) "TCP")
    ((17) "UDP")
    ((41) "IPv6")
    ((47) "GRE")
    ((50) "ESP")
    ((51) "AH")
    ((58) "ICMPv6")
    (else (str "proto-" num))))

;; ── Exported API ────────────────────────────────────────────────────────────

(export dissect-ipv4 format-ip-protocol ip-protocol->protocol)