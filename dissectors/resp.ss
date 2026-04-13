;; packet-resp.c
;; Routines for Redis Client/Server RESP (REdis Serialization Protocol) v2 as
;; documented by https://redis.io/topics/protocol
;; and RESP v3 as documented by:
;; https://github.com/redis/redis-specifications/blob/master/protocol/RESP3.md
;; https://redis.io/docs/latest/develop/reference/protocol-spec/
;;
;; Copyright 2022 Ryan Doyle <ryan <AT> doylenet dot net>
;; Modifications for RESP3 support by Corentin B <corentinb.pro@pm.me> in 2025
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/resp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-resp.c

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
(def (dissect-resp buffer)
  "REdis Serialization Protocol"
  (try
    (let* (
           (string (unwrap (slice buffer 0 1)))
           (boolean (unwrap (read-u8 buffer 0)))
           (double (unwrap (read-u64be buffer 0)))
           (error (unwrap (slice buffer 0 1)))
           (big-number (unwrap (slice buffer 0 1)))
           (bulk-string-length (unwrap (read-u32be buffer 0)))
           (verbatim-string-length (unwrap (read-u32be buffer 0)))
           (verbatim-string-encoding (unwrap (slice buffer 0 1)))
           (verbatim-string-value (unwrap (slice buffer 0 1)))
           (integer (unwrap (read-u64be buffer 0)))
           )

      (ok (list
        (cons 'string (list (cons 'raw string) (cons 'formatted (utf8->string string))))
        (cons 'boolean (list (cons 'raw boolean) (cons 'formatted (number->string boolean))))
        (cons 'double (list (cons 'raw double) (cons 'formatted (number->string double))))
        (cons 'error (list (cons 'raw error) (cons 'formatted (utf8->string error))))
        (cons 'big-number (list (cons 'raw big-number) (cons 'formatted (utf8->string big-number))))
        (cons 'bulk-string-length (list (cons 'raw bulk-string-length) (cons 'formatted (number->string bulk-string-length))))
        (cons 'verbatim-string-length (list (cons 'raw verbatim-string-length) (cons 'formatted (number->string verbatim-string-length))))
        (cons 'verbatim-string-encoding (list (cons 'raw verbatim-string-encoding) (cons 'formatted (utf8->string verbatim-string-encoding))))
        (cons 'verbatim-string-value (list (cons 'raw verbatim-string-value) (cons 'formatted (fmt-bytes verbatim-string-value))))
        (cons 'integer (list (cons 'raw integer) (cons 'formatted (number->string integer))))
        )))

    (catch (e)
      (err (str "RESP parse error: " e)))))

;; dissect-resp: parse RESP from bytevector
;; Returns (ok fields-alist) or (err message)