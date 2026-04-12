;; jerboa-ethereal/dissectors/ethernet-v2.ss
;; IEEE 802.3 Ethernet Frame (Code-Generated Dissector)
;;
;; Clean DSL that compiles to safe, performant code.

(import (jerboa prelude)
        (lib dsl defprotocol))

;; ── Ethernet Dissector (hand-optimized version) ─────────────────────────────
;; Shows what the defprotocol macro would generate

(def (dissect-ethernet buffer)
  "Parse Ethernet frame, returns (ok fields) or (err message)
   Safe: handles truncated packets, corruption, etc."

  (try-result
    ;; Parse all fields with error propagation
    (let* ((dest-mac-result (safe-slice buffer 0 6))
           (dest-mac (unwrap dest-mac-result))

           (src-mac-result (safe-slice buffer 6 6))
           (src-mac (unwrap src-mac-result))

           (type-result (safe-read-u16be buffer 12))
           (type-val (unwrap type-result))

           (payload-result (safe-slice buffer 14 (- (bytevector-length buffer) 14)))
           (payload (unwrap payload-result)))

      ;; Return structured result
      (ok (alist
            (dest-mac . (alist (raw . dest-mac)
                              (formatted . (fmt-mac (bytes->u48be dest-mac)))))
            (src-mac . (alist (raw . src-mac)
                             (formatted . (fmt-mac (bytes->u48be src-mac)))))
            (type . (alist (raw . type-val)
                          (formatted . (format-ethertype type-val))
                          (next-protocol . (ethertype->protocol type-val))))
            (payload . payload))))

    (catch (e)
      (err (str "Ethernet parse error: " e)))))

;; ── Helper: Convert 6-byte MAC to u48 ──────────────────────────────────────

(def (bytes->u48be bytes)
  "Convert 6-byte vector to u48 big-endian"
  (let loop ((i 0) (acc 0))
    (if (>= i 6)
        acc
        (loop (+ i 1)
              (+ (bitwise-arithmetic-shift-left acc 8)
                 (bytevector-u8-ref bytes i))))))

;; ── EtherType Formatter ────────────────────────────────────────────────────

(def (format-ethertype type)
  "Format EtherType value with name"
  (case type
    ((#x0800) "IPv4 (0x0800)")
    ((#x0806) "ARP (0x0806)")
    ((#x86DD) "IPv6 (0x86DD)")
    ((#x8100) "VLAN (0x8100)")
    (else (format "0x~4,'0x" type))))

;; ── Exported API ────────────────────────────────────────────────────────────

(export dissect-ethernet format-ethertype)