;; jerboa-ethereal/dissectors/udp.ss
;; RFC 768: User Datagram Protocol
;;
;; Simple, safe UDP dissector.

(import (jerboa prelude))
;; ── Protocol Helpers (from lib/dissector/protocol.ss) ────────────────────

(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u32be buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness big)))))

(def (read-u16le buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness little)))))

(def (read-u32le buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness little)))))

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

(def (validate pred msg)
  (if pred (ok #t) (err msg)))

(def (fmt-ipv4 addr)
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (fmt-mac bytes)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\0))
         (bytevector->list bytes))
    ":"))

(def (fmt-hex val)
  (str "0x" (number->string val 16)))

(def (fmt-port port)
  (number->string port))

(def (ip-protocol->protocol num)
  (case num
    ((1) 'icmp) ((6) 'tcp) ((17) 'udp)
    ((41) 'ipv6) ((58) 'icmpv6) (else #f)))



(def (dissect-udp buffer)
  "Parse UDP datagram from bytevector
   Returns (ok fields) or (err message)

   Structure (8-byte minimum):
   [0:2)   source port
   [2:4)   destination port
   [4:6)   length (total datagram length)
   [6:8)   checksum
   [8:)    payload"

  (try
    (let* ((src-port-res (read-u16be buffer 0))
           (src-port (unwrap src-port-res))

           (dst-port-res (read-u16be buffer 2))
           (dst-port (unwrap dst-port-res))

           (length-res (read-u16be buffer 4))
           (udp-length (unwrap length-res))
           (unwrap (validate (>= udp-length 8) "UDP length too small")))

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