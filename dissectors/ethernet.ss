;; jerboa-ethereal/dissectors/ethernet.ss
;; IEEE 802.3 Ethernet Frame
;;
;; Clean, safe dissector with zero boilerplate.
;; Returns (ok packet-data) or (err message) on any issue.

(import (jerboa prelude)
        (lib dissector protocol))

(def (dissect-ethernet buffer)
  "Parse Ethernet frame from bytevector
   Returns (ok fields) or (err message)

   Handles:
   - Truncated frames
   - Corrupt fields
   - Any bytevector size

   Structure:
   [0:6)   dest MAC (6 bytes)
   [6:12)  src MAC (6 bytes)
   [12:14) EtherType (2 bytes, big-endian)
   [14:)   payload (variable)"

  (try-result
    ;; Parse each field with error propagation
    (let* ((dest-mac (unwrap (slice buffer 0 6)))
           (src-mac (unwrap (slice buffer 6 6)))
           (etype-result (read-u16be buffer 12))
           (etype (unwrap etype-result))
           (payload (unwrap (slice buffer 14
                                   (max 0 (- (bytevector-length buffer) 14))))))

      ;; Return structured packet
      (ok `((dest-mac . ((raw . ,dest-mac)
                        (formatted . ,(fmt-mac dest-mac))))
            (src-mac . ((raw . ,src-mac)
                       (formatted . ,(fmt-mac src-mac))))
            (etype . ((raw . ,etype)
                     (formatted . ,(format-ethertype etype))
                     (next-protocol . ,(ethertype->protocol etype))))
            (payload . ,payload))))

    ;; Catch ANY error and return structured message
    (catch (e)
      (err (str "Ethernet parse error: " e)))))

;; ── EtherType Formatter ────────────────────────────────────────────────────

(def (format-ethertype type)
  "Format EtherType value with name and hex"
  (cond
    ((= type #x0800) "IPv4 (0x0800)")
    ((= type #x0806) "ARP (0x0806)")
    ((= type #x86DD) "IPv6 (0x86DD)")
    ((= type #x8100) "VLAN (0x8100)")
    ((= type #x8847) "MPLS (0x8847)")
    ((= type #x888E) "802.1X (0x888E)")
    (#t (format "Unknown (0x~4,'0x)" type))))

;; ── Exported API ───────────────────────────────────────────────────────────

;; dissect-ethernet: main entry point
;; format-ethertype: formatter for display