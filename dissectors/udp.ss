;; jerboa-ethereal/dissectors/udp.ss
;; RFC 768: User Datagram Protocol
;;
;; Simple, safe UDP dissector.

(import (jerboa prelude))

(def (dissect-udp buffer)
  "Parse UDP datagram from bytevector
   Returns (ok fields) or (err message)

   Structure (8-byte minimum):
   [0:2)   source port
   [2:4)   destination port
   [4:6)   length (total datagram length)
   [6:8)   checksum
   [8:)    payload"

  (try-result
    (let* ((src-port-res (read-u16be buffer 0))
           (src-port (unwrap src-port-res))

           (dst-port-res (read-u16be buffer 2))
           (dst-port (unwrap dst-port-res))

           (length-res (read-u16be buffer 4))
           (udp-length (unwrap length-res))
           (_ (unwrap (validate (>= udp-length 8) "UDP length too small")))

           (checksum-res (read-u16be buffer 6))
           (checksum (unwrap checksum-res))

           (payload-len (max 0 (- udp-length 8)))
           (payload (unwrap (slice buffer 8 payload-len))))

      ;; Return structured datagram
      (ok `((src-port . ((raw . ,src-port)
                        (formatted . ,(fmt-port src-port))))
            (dst-port . ((raw . ,dst-port)
                        (formatted . ,(fmt-port dst-port))))
            (length . ,udp-length)
            (checksum . ((raw . ,checksum)
                        (formatted . ,(fmt-hex checksum))))
            (payload . ,payload))))

    ;; Clear error handling
    (catch (e)
      (err (str "UDP parse error: " e)))))

;; ── Exported API ───────────────────────────────────────────────────────────

;; dissect-udp: main entry point