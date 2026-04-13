;; packet-nats.c
;; Routines for NATS Client Protocol dissection
;; https://docs.nats.io/reference/reference-protocols/nats-protocol
;;
;; Copyright 2025, Max Dmitrichenko <dmitrmax@gmail.com>
;; Copyright 2025, Florian Matouschek <florian@matoutech.dev>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nats.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nats.c

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
(def (dissect-nats buffer)
  "NATS"
  (try
    (let* (
           (rsp-frame-ref (unwrap (read-u32be buffer 0)))
           (req-frame-ref (unwrap (read-u32be buffer 0)))
           (body-bytes (unwrap (read-u64be buffer 0)))
           (header-version (unwrap (slice buffer 0 1)))
           (header (unwrap (slice buffer 0 1)))
           (header-name (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'rsp-frame-ref (list (cons 'raw rsp-frame-ref) (cons 'formatted (number->string rsp-frame-ref))))
        (cons 'req-frame-ref (list (cons 'raw req-frame-ref) (cons 'formatted (number->string req-frame-ref))))
        (cons 'body-bytes (list (cons 'raw body-bytes) (cons 'formatted (number->string body-bytes))))
        (cons 'header-version (list (cons 'raw header-version) (cons 'formatted (utf8->string header-version))))
        (cons 'header (list (cons 'raw header) (cons 'formatted (utf8->string header))))
        (cons 'header-name (list (cons 'raw header-name) (cons 'formatted (utf8->string header-name))))
        )))

    (catch (e)
      (err (str "NATS parse error: " e)))))

;; dissect-nats: parse NATS from bytevector
;; Returns (ok fields-alist) or (err message)