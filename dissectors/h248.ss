;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/h248.ss
;; Auto-generated from wireshark/epan/dissectors/packet-h248.c

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
(def (dissect-h248 buffer)
  "H.248 MEGACO"
  (try
    (let* (
           (pkg-param (unwrap (read-u16be buffer 0)))
           (transactionId64 (unwrap (read-u64be buffer 0)))
           (transactionId (unwrap (read-u32be buffer 0)))
           (context-id64 (unwrap (read-u64be buffer 0)))
           (context-id (unwrap (read-u32be buffer 0)))
           (event-code (unwrap (read-u16be buffer 0)))
           (signal-code (unwrap (read-u16be buffer 0)))
           (magic-num (unwrap (read-u32be buffer 0)))
           (pkg-name (unwrap (read-u16be buffer 8)))
           )

      (ok (list
        (cons 'pkg-param (list (cons 'raw pkg-param) (cons 'formatted (fmt-hex pkg-param))))
        (cons 'transactionId64 (list (cons 'raw transactionId64) (cons 'formatted (number->string transactionId64))))
        (cons 'transactionId (list (cons 'raw transactionId) (cons 'formatted (number->string transactionId))))
        (cons 'context-id64 (list (cons 'raw context-id64) (cons 'formatted (fmt-hex context-id64))))
        (cons 'context-id (list (cons 'raw context-id) (cons 'formatted (fmt-hex context-id))))
        (cons 'event-code (list (cons 'raw event-code) (cons 'formatted (fmt-hex event-code))))
        (cons 'signal-code (list (cons 'raw signal-code) (cons 'formatted (fmt-hex signal-code))))
        (cons 'magic-num (list (cons 'raw magic-num) (cons 'formatted (fmt-hex magic-num))))
        (cons 'pkg-name (list (cons 'raw pkg-name) (cons 'formatted (fmt-hex pkg-name))))
        )))

    (catch (e)
      (err (str "H248 parse error: " e)))))

;; dissect-h248: parse H248 from bytevector
;; Returns (ok fields-alist) or (err message)