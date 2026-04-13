;; packet-openwire.c
;; Routines for ActiveMQ OpenWire protocol
;;
;; metatech <metatechbe@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/openwire.ss
;; Auto-generated from wireshark/epan/dissectors/packet-openwire.c

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
(def (dissect-openwire buffer)
  "OpenWire"
  (try
    (let* (
           (cached-id (unwrap (read-u16be buffer 0)))
           (length (unwrap (read-u32be buffer 0)))
           (cached-enabled (unwrap (read-u8 buffer 0)))
           (type-notnull (unwrap (read-u8 buffer 5)))
           (type-integer (unwrap (read-u32be buffer 42)))
           (map-length (unwrap (read-u32be buffer 48)))
           (type-short (unwrap (read-u32be buffer 52)))
           (wireformatinfo-magic (unwrap (slice buffer 55 8)))
           (wireformatinfo-version (unwrap (read-u32be buffer 55)))
           (wireformatinfo-data (unwrap (read-u8 buffer 55)))
           (wireformatinfo-length (unwrap (read-u32be buffer 55)))
           (command-id (unwrap (read-u32be buffer 72)))
           (command-response-required (unwrap (read-u8 buffer 72)))
           (cached-inlined (unwrap (read-u8 buffer 76)))
           )

      (ok (list
        (cons 'cached-id (list (cons 'raw cached-id) (cons 'formatted (number->string cached-id))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'cached-enabled (list (cons 'raw cached-enabled) (cons 'formatted (number->string cached-enabled))))
        (cons 'type-notnull (list (cons 'raw type-notnull) (cons 'formatted (number->string type-notnull))))
        (cons 'type-integer (list (cons 'raw type-integer) (cons 'formatted (number->string type-integer))))
        (cons 'map-length (list (cons 'raw map-length) (cons 'formatted (number->string map-length))))
        (cons 'type-short (list (cons 'raw type-short) (cons 'formatted (number->string type-short))))
        (cons 'wireformatinfo-magic (list (cons 'raw wireformatinfo-magic) (cons 'formatted (utf8->string wireformatinfo-magic))))
        (cons 'wireformatinfo-version (list (cons 'raw wireformatinfo-version) (cons 'formatted (number->string wireformatinfo-version))))
        (cons 'wireformatinfo-data (list (cons 'raw wireformatinfo-data) (cons 'formatted (number->string wireformatinfo-data))))
        (cons 'wireformatinfo-length (list (cons 'raw wireformatinfo-length) (cons 'formatted (number->string wireformatinfo-length))))
        (cons 'command-id (list (cons 'raw command-id) (cons 'formatted (number->string command-id))))
        (cons 'command-response-required (list (cons 'raw command-response-required) (cons 'formatted (number->string command-response-required))))
        (cons 'cached-inlined (list (cons 'raw cached-inlined) (cons 'formatted (number->string cached-inlined))))
        )))

    (catch (e)
      (err (str "OPENWIRE parse error: " e)))))

;; dissect-openwire: parse OPENWIRE from bytevector
;; Returns (ok fields-alist) or (err message)