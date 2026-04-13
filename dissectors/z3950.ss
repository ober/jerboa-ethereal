;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/z3950.ss
;; Auto-generated from wireshark/epan/dissectors/packet-z3950.c

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
(def (dissect-z3950 buffer)
  "Z39.50 Protocol"
  (try
    (let* (
           (leader-length (unwrap (slice buffer 0 5)))
           (leader-data-offset (unwrap (slice buffer 12 5)))
           (directory-entry-tag (unwrap (slice buffer 24 3)))
           (directory-entry-length (unwrap (slice buffer 27 1)))
           (directory-entry-starting-position (unwrap (slice buffer 27 1)))
           (field-control (unwrap (slice buffer 28 1)))
           (field-subfield (unwrap (slice buffer 33 1)))
           )

      (ok (list
        (cons 'leader-length (list (cons 'raw leader-length) (cons 'formatted (utf8->string leader-length))))
        (cons 'leader-data-offset (list (cons 'raw leader-data-offset) (cons 'formatted (utf8->string leader-data-offset))))
        (cons 'directory-entry-tag (list (cons 'raw directory-entry-tag) (cons 'formatted (utf8->string directory-entry-tag))))
        (cons 'directory-entry-length (list (cons 'raw directory-entry-length) (cons 'formatted (utf8->string directory-entry-length))))
        (cons 'directory-entry-starting-position (list (cons 'raw directory-entry-starting-position) (cons 'formatted (utf8->string directory-entry-starting-position))))
        (cons 'field-control (list (cons 'raw field-control) (cons 'formatted (utf8->string field-control))))
        (cons 'field-subfield (list (cons 'raw field-subfield) (cons 'formatted (utf8->string field-subfield))))
        )))

    (catch (e)
      (err (str "Z3950 parse error: " e)))))

;; dissect-z3950: parse Z3950 from bytevector
;; Returns (ok fields-alist) or (err message)