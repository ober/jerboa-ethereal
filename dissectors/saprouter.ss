;; packet-saprouter.c
;; Routines for SAP Router dissection
;; Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
;; Code contributed by SecureAuth Corp.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/saprouter.ss
;; Auto-generated from wireshark/epan/dissectors/packet-saprouter.c

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
(def (dissect-saprouter buffer)
  "SAP Router Protocol"
  (try
    (let* (
           (route-requested-in (unwrap (read-u32be buffer 0)))
           (route-accepted-in (unwrap (read-u32be buffer 0)))
           (admin-password (unwrap (slice buffer 12 1)))
           (admin-address-mask (unwrap (slice buffer 12 32)))
           (admin-client-count-short (unwrap (read-u16be buffer 14)))
           (admin-client-count-int (unwrap (read-u32be buffer 16)))
           (admin-client-id (unwrap (read-u32be buffer 20)))
           (route-version (unwrap (read-u8 buffer 24)))
           (entries (unwrap (read-u8 buffer 24)))
           (rest-nodes (unwrap (read-u8 buffer 27)))
           (route-length (unwrap (read-u32be buffer 27)))
           (route-offset (unwrap (read-u32be buffer 31)))
           (type (unwrap (slice buffer 35 1)))
           (ni-version (unwrap (read-u8 buffer 35)))
           (error-length (unwrap (read-u32be buffer 41)))
           (unknown (unwrap (read-u32be buffer 45)))
           (control-length (unwrap (read-u32be buffer 45)))
           (control-string (unwrap (slice buffer 49 1)))
           (control-unknown (unwrap (slice buffer 49 4)))
           )

      (ok (list
        (cons 'route-requested-in (list (cons 'raw route-requested-in) (cons 'formatted (number->string route-requested-in))))
        (cons 'route-accepted-in (list (cons 'raw route-accepted-in) (cons 'formatted (number->string route-accepted-in))))
        (cons 'admin-password (list (cons 'raw admin-password) (cons 'formatted (utf8->string admin-password))))
        (cons 'admin-address-mask (list (cons 'raw admin-address-mask) (cons 'formatted (utf8->string admin-address-mask))))
        (cons 'admin-client-count-short (list (cons 'raw admin-client-count-short) (cons 'formatted (number->string admin-client-count-short))))
        (cons 'admin-client-count-int (list (cons 'raw admin-client-count-int) (cons 'formatted (number->string admin-client-count-int))))
        (cons 'admin-client-id (list (cons 'raw admin-client-id) (cons 'formatted (number->string admin-client-id))))
        (cons 'route-version (list (cons 'raw route-version) (cons 'formatted (number->string route-version))))
        (cons 'entries (list (cons 'raw entries) (cons 'formatted (number->string entries))))
        (cons 'rest-nodes (list (cons 'raw rest-nodes) (cons 'formatted (number->string rest-nodes))))
        (cons 'route-length (list (cons 'raw route-length) (cons 'formatted (number->string route-length))))
        (cons 'route-offset (list (cons 'raw route-offset) (cons 'formatted (number->string route-offset))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (utf8->string type))))
        (cons 'ni-version (list (cons 'raw ni-version) (cons 'formatted (number->string ni-version))))
        (cons 'error-length (list (cons 'raw error-length) (cons 'formatted (number->string error-length))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (number->string unknown))))
        (cons 'control-length (list (cons 'raw control-length) (cons 'formatted (number->string control-length))))
        (cons 'control-string (list (cons 'raw control-string) (cons 'formatted (utf8->string control-string))))
        (cons 'control-unknown (list (cons 'raw control-unknown) (cons 'formatted (utf8->string control-unknown))))
        )))

    (catch (e)
      (err (str "SAPROUTER parse error: " e)))))

;; dissect-saprouter: parse SAPROUTER from bytevector
;; Returns (ok fields-alist) or (err message)