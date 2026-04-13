;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/goose.ss
;; Auto-generated from wireshark/epan/dissectors/packet-goose.c

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
(def (dissect-goose buffer)
  "GOOSE"
  (try
    (let* (
           (appid (unwrap (read-u16be buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           (reserve2 (unwrap (read-u16be buffer 0)))
           (spdu-lenth (unwrap (read-u32be buffer 0)))
           (spdu-num (unwrap (read-u32be buffer 4)))
           (version (unwrap (read-u16be buffer 8)))
           (current-key-t (unwrap (read-u32be buffer 10)))
           (next-key-t (unwrap (read-u16be buffer 14)))
           (key-id (unwrap (read-u32be buffer 16)))
           (init-vec (unwrap (slice buffer 20 1)))
           (payload-length (unwrap (read-u32be buffer 20)))
           (apdu-appid (unwrap (read-u16be buffer 24)))
           (apdu-length (unwrap (read-u16be buffer 26)))
           (padding (unwrap (slice buffer 28 1)))
           (hmac (unwrap (slice buffer 28 1)))
           )

      (ok (list
        (cons 'appid (list (cons 'raw appid) (cons 'formatted (fmt-hex appid))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'reserve2 (list (cons 'raw reserve2) (cons 'formatted (fmt-hex reserve2))))
        (cons 'spdu-lenth (list (cons 'raw spdu-lenth) (cons 'formatted (number->string spdu-lenth))))
        (cons 'spdu-num (list (cons 'raw spdu-num) (cons 'formatted (number->string spdu-num))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'current-key-t (list (cons 'raw current-key-t) (cons 'formatted (fmt-hex current-key-t))))
        (cons 'next-key-t (list (cons 'raw next-key-t) (cons 'formatted (fmt-hex next-key-t))))
        (cons 'key-id (list (cons 'raw key-id) (cons 'formatted (fmt-hex key-id))))
        (cons 'init-vec (list (cons 'raw init-vec) (cons 'formatted (fmt-bytes init-vec))))
        (cons 'payload-length (list (cons 'raw payload-length) (cons 'formatted (number->string payload-length))))
        (cons 'apdu-appid (list (cons 'raw apdu-appid) (cons 'formatted (fmt-hex apdu-appid))))
        (cons 'apdu-length (list (cons 'raw apdu-length) (cons 'formatted (fmt-hex apdu-length))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'hmac (list (cons 'raw hmac) (cons 'formatted (fmt-bytes hmac))))
        )))

    (catch (e)
      (err (str "GOOSE parse error: " e)))))

;; dissect-goose: parse GOOSE from bytevector
;; Returns (ok fields-alist) or (err message)