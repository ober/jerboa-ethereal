;; jerboa-ethereal/dissectors/tcp.ss
;; RFC 793: Transmission Control Protocol
;;
;; Complex protocol with variable-length options.
;; Demonstrates safe handling of optional fields.

(import (jerboa prelude)
        (lib dissector protocol))

(def (dissect-tcp buffer)
  "Parse TCP segment from bytevector
   Returns (ok fields) or (err message)

   Structure (20-byte minimum):
   [0:2)   source port
   [2:4)   destination port
   [4:8)   sequence number
   [8:12)  acknowledgment number
   [12]    data offset (4b) + reserved (4b)
   [13]    flags (SYN, ACK, FIN, RST, PSH, URG)
   [14:16) window size
   [16:18) checksum
   [18:20) urgent pointer (if URG flag set)
   [20:)   options (if data-offset > 5) + payload"

  (try
    ;; Byte 0-1: Source port
    (let* ((src-port-res (read-u16be buffer 0))
           (src-port (unwrap src-port-res))

           ;; Byte 2-3: Destination port
           (dst-port-res (read-u16be buffer 2))
           (dst-port (unwrap dst-port-res))

           ;; Byte 4-7: Sequence number
           (seq-res (read-u32be buffer 4))
           (sequence (unwrap seq-res))

           ;; Byte 8-11: Acknowledgment number
           (ack-res (read-u32be buffer 8))
           (acknowledgment (unwrap ack-res))

           ;; Byte 12: Data offset (upper 4 bits) + Reserved (lower 4 bits)
           (b12-res (read-u8 buffer 12))
           (b12 (unwrap b12-res))
           (data-offset (extract-bits b12 #xF0 4))
           (reserved (extract-bits b12 #x0F 0))

           ;; Validate data offset
           (_ (unwrap (validate (>= data-offset 5) "Data offset too small")))

           ;; Byte 13: Flags
           (b13-res (read-u8 buffer 13))
           (b13 (unwrap b13-res))
           (cwr-flag (extract-bits b13 #x80 7))
           (ece-flag (extract-bits b13 #x40 6))
           (urg-flag (extract-bits b13 #x20 5))
           (ack-flag (extract-bits b13 #x10 4))
           (psh-flag (extract-bits b13 #x08 3))
           (rst-flag (extract-bits b13 #x04 2))
           (syn-flag (extract-bits b13 #x02 1))
           (fin-flag (extract-bits b13 #x01 0))

           ;; Byte 14-15: Window size
           (window-res (read-u16be buffer 14))
           (window-size (unwrap window-res))

           ;; Byte 16-17: Checksum
           (checksum-res (read-u16be buffer 16))
           (checksum (unwrap checksum-res))

           ;; Byte 18-19: Urgent pointer (if URG flag set)
           (urgent-ptr-res (read-u16be buffer 18))
           (urgent-ptr (unwrap urgent-ptr-res))

           ;; Options: (data-offset - 5) * 4 bytes
           (header-len (* data-offset 4))
           (options-len (max 0 (- header-len 20)))
           (options (if (> options-len 0)
                        (unwrap (slice buffer 20 options-len))
                        #f))

           ;; Payload: remaining bytes
           (payload (unwrap (slice buffer header-len
                                   (max 0 (- (bytevector-length buffer) header-len))))))

      ;; Return structured segment
      (ok `((src-port . ((raw . ,src-port)
                        (formatted . ,(fmt-port src-port))))
            (dst-port . ((raw . ,dst-port)
                        (formatted . ,(fmt-port dst-port))))
            (sequence . ((raw . ,sequence)
                        (formatted . ,(fmt-hex sequence))))
            (acknowledgment . ((raw . ,acknowledgment)
                              (formatted . ,(fmt-hex acknowledgment))))
            (data-offset . ,data-offset)
            (reserved . ,reserved)
            (flags . ((raw . ,b13)
                     (formatted . ,(format-tcp-flags cwr-flag ece-flag urg-flag
                                                     ack-flag psh-flag rst-flag
                                                     syn-flag fin-flag))))
            (window-size . ,window-size)
            (checksum . ((raw . ,checksum)
                        (formatted . ,(fmt-hex checksum))))
            (urgent-pointer . ,urgent-ptr)
            (options . ,options)
            (payload . ,payload))))

    ;; Error handling
    (catch (e)
      (err (str "TCP parse error: " e)))))

;; ── TCP Flags Formatter ────────────────────────────────────────────────────

(def (format-tcp-flags cwr ece urg ack psh rst syn fin)
  "Format TCP flags as readable string
   Example: SYN,ACK or RST or SYN"
  (let ((flags (filter identity
                       (list (if (= syn 1) "SYN" #f)
                             (if (= ack 1) "ACK" #f)
                             (if (= fin 1) "FIN" #f)
                             (if (= rst 1) "RST" #f)
                             (if (= psh 1) "PSH" #f)
                             (if (= urg 1) "URG" #f)
                             (if (= ece 1) "ECE" #f)
                             (if (= cwr 1) "CWR" #f)))))
    (if (null? flags)
        "NO FLAGS"
        (string-join flags ","))))

;; ── Exported API ───────────────────────────────────────────────────────────

;; dissect-tcp: main entry point
;; format-tcp-flags: formatter for display