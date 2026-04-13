;; packet-tnef.c
;; Routines for Transport-Neutral Encapsulation Format (TNEF) packet disassembly
;;
;; Copyright (c) 2007 by Graeme Lunt
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tnef.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tnef.c

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
(def (dissect-tnef buffer)
  "Transport-Neutral Encapsulation Format"
  (try
    (let* (
           (attribute-date-year (unwrap (read-u16be buffer 0)))
           (mapi-props-count (unwrap (read-u32be buffer 0)))
           (signature (unwrap (read-u32be buffer 0)))
           (attribute-date-month (unwrap (read-u16be buffer 2)))
           (attribute-date-day (unwrap (read-u16be buffer 4)))
           (key (unwrap (read-u16be buffer 4)))
           (attribute-date-hour (unwrap (read-u16be buffer 6)))
           (property-tag-id (unwrap (read-u16be buffer 6)))
           (attribute-tag-id (unwrap (read-u16be buffer 7)))
           (attribute-date-minute (unwrap (read-u16be buffer 8)))
           (property-tag-set (unwrap (slice buffer 8 16)))
           (attribute-display-name (unwrap (slice buffer 10 1)))
           (value-length (unwrap (read-u32be buffer 10)))
           (attribute-date-second (unwrap (read-u16be buffer 10)))
           (attribute-length (unwrap (read-u32be buffer 11)))
           (attribute-email-address (unwrap (slice buffer 12 1)))
           (oem-codepage (unwrap (read-u64be buffer 15)))
           (version (unwrap (read-u32be buffer 15)))
           (message-class (unwrap (slice buffer 15 1)))
           (original-message-class (unwrap (slice buffer 15 1)))
           (attribute-string (unwrap (slice buffer 15 1)))
           (property-tag-kind (unwrap (read-u32be buffer 24)))
           (property-tag-name-id (unwrap (read-u32be buffer 28)))
           (property-tag-name-length (unwrap (read-u32be buffer 32)))
           (property-tag-name-string (unwrap (slice buffer 36 1)))
           (values-count (unwrap (read-u32be buffer 37)))
           )

      (ok (list
        (cons 'attribute-date-year (list (cons 'raw attribute-date-year) (cons 'formatted (number->string attribute-date-year))))
        (cons 'mapi-props-count (list (cons 'raw mapi-props-count) (cons 'formatted (number->string mapi-props-count))))
        (cons 'signature (list (cons 'raw signature) (cons 'formatted (fmt-hex signature))))
        (cons 'attribute-date-month (list (cons 'raw attribute-date-month) (cons 'formatted (number->string attribute-date-month))))
        (cons 'attribute-date-day (list (cons 'raw attribute-date-day) (cons 'formatted (number->string attribute-date-day))))
        (cons 'key (list (cons 'raw key) (cons 'formatted (fmt-hex key))))
        (cons 'attribute-date-hour (list (cons 'raw attribute-date-hour) (cons 'formatted (number->string attribute-date-hour))))
        (cons 'property-tag-id (list (cons 'raw property-tag-id) (cons 'formatted (fmt-hex property-tag-id))))
        (cons 'attribute-tag-id (list (cons 'raw attribute-tag-id) (cons 'formatted (fmt-hex attribute-tag-id))))
        (cons 'attribute-date-minute (list (cons 'raw attribute-date-minute) (cons 'formatted (number->string attribute-date-minute))))
        (cons 'property-tag-set (list (cons 'raw property-tag-set) (cons 'formatted (fmt-bytes property-tag-set))))
        (cons 'attribute-display-name (list (cons 'raw attribute-display-name) (cons 'formatted (utf8->string attribute-display-name))))
        (cons 'value-length (list (cons 'raw value-length) (cons 'formatted (number->string value-length))))
        (cons 'attribute-date-second (list (cons 'raw attribute-date-second) (cons 'formatted (number->string attribute-date-second))))
        (cons 'attribute-length (list (cons 'raw attribute-length) (cons 'formatted (number->string attribute-length))))
        (cons 'attribute-email-address (list (cons 'raw attribute-email-address) (cons 'formatted (utf8->string attribute-email-address))))
        (cons 'oem-codepage (list (cons 'raw oem-codepage) (cons 'formatted (number->string oem-codepage))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'message-class (list (cons 'raw message-class) (cons 'formatted (utf8->string message-class))))
        (cons 'original-message-class (list (cons 'raw original-message-class) (cons 'formatted (utf8->string original-message-class))))
        (cons 'attribute-string (list (cons 'raw attribute-string) (cons 'formatted (utf8->string attribute-string))))
        (cons 'property-tag-kind (list (cons 'raw property-tag-kind) (cons 'formatted (number->string property-tag-kind))))
        (cons 'property-tag-name-id (list (cons 'raw property-tag-name-id) (cons 'formatted (fmt-hex property-tag-name-id))))
        (cons 'property-tag-name-length (list (cons 'raw property-tag-name-length) (cons 'formatted (number->string property-tag-name-length))))
        (cons 'property-tag-name-string (list (cons 'raw property-tag-name-string) (cons 'formatted (utf8->string property-tag-name-string))))
        (cons 'values-count (list (cons 'raw values-count) (cons 'formatted (number->string values-count))))
        )))

    (catch (e)
      (err (str "TNEF parse error: " e)))))

;; dissect-tnef: parse TNEF from bytevector
;; Returns (ok fields-alist) or (err message)