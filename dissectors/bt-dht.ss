;; ***************************************************************************************************

;; jerboa-ethereal/dissectors/bt-dht.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bt_dht.c

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
(def (dissect-bt-dht buffer)
  "BitTorrent DHT Protocol"
  (try
    (let* (
           (hf-ip (unwrap (read-u32be buffer 7)))
           (data (unwrap (slice buffer 7 1)))
           (dht-id (unwrap (slice buffer 7 20)))
           (hf-ip6 (unwrap (slice buffer 13 16)))
           (hf-port (unwrap (read-u16be buffer 29)))
           (list-terminator (unwrap (slice buffer 32 1)))
           (string (unwrap (slice buffer 33 1)))
           )

      (ok (list
        (cons 'hf-ip (list (cons 'raw hf-ip) (cons 'formatted (fmt-ipv4 hf-ip))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'dht-id (list (cons 'raw dht-id) (cons 'formatted (fmt-bytes dht-id))))
        (cons 'hf-ip6 (list (cons 'raw hf-ip6) (cons 'formatted (fmt-ipv6-address hf-ip6))))
        (cons 'hf-port (list (cons 'raw hf-port) (cons 'formatted (number->string hf-port))))
        (cons 'list-terminator (list (cons 'raw list-terminator) (cons 'formatted (utf8->string list-terminator))))
        (cons 'string (list (cons 'raw string) (cons 'formatted (utf8->string string))))
        )))

    (catch (e)
      (err (str "BT-DHT parse error: " e)))))

;; dissect-bt-dht: parse BT-DHT from bytevector
;; Returns (ok fields-alist) or (err message)