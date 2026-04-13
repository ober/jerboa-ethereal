;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/snmp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-snmp.c
;; RFC 1157

(import (jerboa prelude))

;; ── Protocol Helpers ─────────────────────────────────────────────────
(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u24be buf offset)
  (if (> (+ offset 3) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (+ (* (bytevector-u8-ref buf offset) 65536)
             (* (bytevector-u8-ref buf (+ offset 1)) 256)
             (bytevector-u8-ref buf (+ offset 2))))))

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

(def (read-u64be buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness big)))))

(def (read-u64le buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness little)))))

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

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

(def (fmt-oct val)
  (str "0" (number->string val 8)))

(def (fmt-port port)
  (number->string port))

(def (fmt-bytes bv)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\0))
         (bytevector->list bv))
    " "))

(def (fmt-ipv6-address bytes)
  (let loop ((i 0) (parts '()))
    (if (>= i 16)
        (string-join (reverse parts) ":")
        (loop (+ i 2)
              (cons (let ((w (+ (* (bytevector-u8-ref bytes i) 256)
                                (bytevector-u8-ref bytes (+ i 1)))))
                      (number->string w 16))
                    parts)))))

;; ── Dissector ──────────────────────────────────────────────────────
(def (dissect-snmp buffer)
  "Simple Network Management Protocol"
  (try
    (let* (
           (msgAuthentication (unwrap (read-u8 buffer 0)))
           (var-bind-str (unwrap (slice buffer 0 1)))
           (engineid-conform (unwrap (read-u8 buffer 0)))
           (agentid-trailer (unwrap (slice buffer 4 8)))
           (engineid-ipv4 (unwrap (read-u32be buffer 13)))
           (engineid-ipv6 (unwrap (slice buffer 17 16)))
           (engineid-mac (unwrap (slice buffer 33 6)))
           (engineid-text (unwrap (slice buffer 39 1)))
           (engineid-data (unwrap (slice buffer 39 4)))
           )

      (ok (list
        (cons 'msgAuthentication (list (cons 'raw msgAuthentication) (cons 'formatted (if (= msgAuthentication 0) "Failed" "OK"))))
        (cons 'var-bind-str (list (cons 'raw var-bind-str) (cons 'formatted (utf8->string var-bind-str))))
        (cons 'engineid-conform (list (cons 'raw engineid-conform) (cons 'formatted (if (= engineid-conform 0) "RFC1910 (Non-SNMPv3)" "RFC3411 (SNMPv3)"))))
        (cons 'agentid-trailer (list (cons 'raw agentid-trailer) (cons 'formatted (fmt-bytes agentid-trailer))))
        (cons 'engineid-ipv4 (list (cons 'raw engineid-ipv4) (cons 'formatted (fmt-ipv4 engineid-ipv4))))
        (cons 'engineid-ipv6 (list (cons 'raw engineid-ipv6) (cons 'formatted (fmt-ipv6-address engineid-ipv6))))
        (cons 'engineid-mac (list (cons 'raw engineid-mac) (cons 'formatted (fmt-mac engineid-mac))))
        (cons 'engineid-text (list (cons 'raw engineid-text) (cons 'formatted (utf8->string engineid-text))))
        (cons 'engineid-data (list (cons 'raw engineid-data) (cons 'formatted (fmt-bytes engineid-data))))
        )))

    (catch (e)
      (err (str "SNMP parse error: " e)))))

;; dissect-snmp: parse SNMP from bytevector
;; Returns (ok fields-alist) or (err message)