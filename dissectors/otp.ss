;; packet-otp.c
;; Routines for OTP (ANSI E1.59) packet disassembly
;;
;; Copyright (c) 2025 by Matt Morris <mattm.dev.1[AT]gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/otp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-otp.c

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
(def (dissect-otp buffer)
  "Object Transform Protocol"
  (try
    (let* (
           (identifier (unwrap (slice buffer 0 12)))
           (length (unwrap (read-u16be buffer 14)))
           (footer-options (unwrap (read-u8 buffer 16)))
           (footer-length (unwrap (read-u8 buffer 17)))
           (sender-cid (unwrap (slice buffer 18 16)))
           (folio (unwrap (read-u32be buffer 34)))
           (page (unwrap (read-u16be buffer 38)))
           (last-page (unwrap (read-u16be buffer 40)))
           (options (unwrap (read-u8 buffer 42)))
           (reserved (unwrap (read-u32be buffer 43)))
           (component-name (unwrap (slice buffer 47 32)))
           (module-scale-x (unwrap (read-u32be buffer 91)))
           (module-scale-y (unwrap (read-u32be buffer 95)))
           (module-scale-z (unwrap (read-u32be buffer 99)))
           (module-reference-system (unwrap (read-u8 buffer 103)))
           (module-reference-group (unwrap (read-u16be buffer 104)))
           (module-reference-point (unwrap (read-u32be buffer 106)))
           (point-priority (unwrap (read-u8 buffer 110)))
           (point-options (unwrap (read-u8 buffer 125)))
           (point-reserved (unwrap (read-u32be buffer 126)))
           (transform-options (unwrap (read-u8 buffer 139)))
           (transform-pointset (extract-bits transform-options 0x80 7))
           (transform-reserved (unwrap (read-u32be buffer 140)))
           (advert-module-reserved (unwrap (read-u32be buffer 144)))
           (module-module-number (unwrap (read-u16be buffer 150)))
           (advert-name-reserved (unwrap (read-u32be buffer 153)))
           (point-group-number (unwrap (read-u16be buffer 158)))
           (point-number (unwrap (read-u32be buffer 160)))
           (point-name (unwrap (slice buffer 164 32)))
           (advert-system-reserved (unwrap (read-u32be buffer 197)))
           (transform-system-number (unwrap (read-u8 buffer 201)))
           (advert-reserved (unwrap (read-u32be buffer 202)))
           )

      (ok (list
        (cons 'identifier (list (cons 'raw identifier) (cons 'formatted (utf8->string identifier))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'footer-options (list (cons 'raw footer-options) (cons 'formatted (fmt-hex footer-options))))
        (cons 'footer-length (list (cons 'raw footer-length) (cons 'formatted (number->string footer-length))))
        (cons 'sender-cid (list (cons 'raw sender-cid) (cons 'formatted (fmt-bytes sender-cid))))
        (cons 'folio (list (cons 'raw folio) (cons 'formatted (number->string folio))))
        (cons 'page (list (cons 'raw page) (cons 'formatted (number->string page))))
        (cons 'last-page (list (cons 'raw last-page) (cons 'formatted (number->string last-page))))
        (cons 'options (list (cons 'raw options) (cons 'formatted (fmt-hex options))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'component-name (list (cons 'raw component-name) (cons 'formatted (utf8->string component-name))))
        (cons 'module-scale-x (list (cons 'raw module-scale-x) (cons 'formatted (number->string module-scale-x))))
        (cons 'module-scale-y (list (cons 'raw module-scale-y) (cons 'formatted (number->string module-scale-y))))
        (cons 'module-scale-z (list (cons 'raw module-scale-z) (cons 'formatted (number->string module-scale-z))))
        (cons 'module-reference-system (list (cons 'raw module-reference-system) (cons 'formatted (number->string module-reference-system))))
        (cons 'module-reference-group (list (cons 'raw module-reference-group) (cons 'formatted (number->string module-reference-group))))
        (cons 'module-reference-point (list (cons 'raw module-reference-point) (cons 'formatted (number->string module-reference-point))))
        (cons 'point-priority (list (cons 'raw point-priority) (cons 'formatted (number->string point-priority))))
        (cons 'point-options (list (cons 'raw point-options) (cons 'formatted (fmt-hex point-options))))
        (cons 'point-reserved (list (cons 'raw point-reserved) (cons 'formatted (fmt-hex point-reserved))))
        (cons 'transform-options (list (cons 'raw transform-options) (cons 'formatted (fmt-hex transform-options))))
        (cons 'transform-pointset (list (cons 'raw transform-pointset) (cons 'formatted (if (= transform-pointset 0) "Not set" "Set"))))
        (cons 'transform-reserved (list (cons 'raw transform-reserved) (cons 'formatted (fmt-hex transform-reserved))))
        (cons 'advert-module-reserved (list (cons 'raw advert-module-reserved) (cons 'formatted (fmt-hex advert-module-reserved))))
        (cons 'module-module-number (list (cons 'raw module-module-number) (cons 'formatted (fmt-hex module-module-number))))
        (cons 'advert-name-reserved (list (cons 'raw advert-name-reserved) (cons 'formatted (fmt-hex advert-name-reserved))))
        (cons 'point-group-number (list (cons 'raw point-group-number) (cons 'formatted (number->string point-group-number))))
        (cons 'point-number (list (cons 'raw point-number) (cons 'formatted (number->string point-number))))
        (cons 'point-name (list (cons 'raw point-name) (cons 'formatted (utf8->string point-name))))
        (cons 'advert-system-reserved (list (cons 'raw advert-system-reserved) (cons 'formatted (fmt-hex advert-system-reserved))))
        (cons 'transform-system-number (list (cons 'raw transform-system-number) (cons 'formatted (number->string transform-system-number))))
        (cons 'advert-reserved (list (cons 'raw advert-reserved) (cons 'formatted (fmt-hex advert-reserved))))
        )))

    (catch (e)
      (err (str "OTP parse error: " e)))))

;; dissect-otp: parse OTP from bytevector
;; Returns (ok fields-alist) or (err message)