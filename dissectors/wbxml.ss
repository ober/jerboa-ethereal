;; packet-wbxml.c
;;
;; Routines for WAP Binary XML dissection
;; Copyright 2003, 2004, Olivier Biot.
;;
;; Routines for WV-CSP 1.3 dissection
;; Copyright 2007, Andrei Rubaniuk.
;;
;; Refer to the AUTHORS file or the AUTHORS section in the man page
;; for contacting the author(s) of this file.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; WAP Binary XML decoding functionality provided by Olivier Biot.
;; WV-CSP 1.2 updated to Release version and WV-CSP 1.3 protocol
;; decoding functionality provided by Andrei Rubaniuk.
;;
;; The WAP specifications used to be found at the WAP Forum:
;; <http://www.wapforum.org/what/Technical.htm>
;; But now the correct link is at the Open Mobile Alliance:
;; <http://www.openmobilealliance.org/tech/affiliates/wap/wapindex.html>
;; Media types defined by OMA affiliates will have their standards at:
;; <http://www.openmobilealliance.org/tech/affiliates/index.html>
;; <http://www.openmobilealliance.org/release_program/index.html>
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wbxml.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wbxml.c

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
(def (dissect-wbxml buffer)
  "WAP Binary XML"
  (try
    (let* (
           (string-table-item-offset (unwrap (read-u32be buffer 0)))
           (string-table-item-string (unwrap (slice buffer 0 1)))
           (public-id-literal (unwrap (slice buffer 1 1)))
           (known-attrvalue (unwrap (slice buffer 10 1)))
           (known-attrstart (unwrap (slice buffer 10 1)))
           (switch-page (unwrap (read-u32be buffer 10)))
           (end-known-tag (unwrap (slice buffer 12 1)))
           (entity (unwrap (read-u32be buffer 12)))
           (str-i (unwrap (slice buffer 13 1)))
           (ext-i (unwrap (slice buffer 14 1)))
           (ext-t (unwrap (slice buffer 15 1)))
           (str-t (unwrap (slice buffer 16 1)))
           (extension-token (unwrap (slice buffer 17 1)))
           (opaque-data (unwrap (slice buffer 17 1)))
           (literal-ac (unwrap (slice buffer 19 1)))
           (literal-c (unwrap (slice buffer 20 1)))
           (end-known-tag-uint (unwrap (read-u32be buffer 21)))
           (literal-a (unwrap (slice buffer 21 1)))
           (end-literal-tag (unwrap (slice buffer 22 1)))
           (known-tag (unwrap (slice buffer 22 1)))
           (literal (unwrap (slice buffer 22 1)))
           )

      (ok (list
        (cons 'string-table-item-offset (list (cons 'raw string-table-item-offset) (cons 'formatted (number->string string-table-item-offset))))
        (cons 'string-table-item-string (list (cons 'raw string-table-item-string) (cons 'formatted (utf8->string string-table-item-string))))
        (cons 'public-id-literal (list (cons 'raw public-id-literal) (cons 'formatted (utf8->string public-id-literal))))
        (cons 'known-attrvalue (list (cons 'raw known-attrvalue) (cons 'formatted (utf8->string known-attrvalue))))
        (cons 'known-attrstart (list (cons 'raw known-attrstart) (cons 'formatted (utf8->string known-attrstart))))
        (cons 'switch-page (list (cons 'raw switch-page) (cons 'formatted (number->string switch-page))))
        (cons 'end-known-tag (list (cons 'raw end-known-tag) (cons 'formatted (utf8->string end-known-tag))))
        (cons 'entity (list (cons 'raw entity) (cons 'formatted (number->string entity))))
        (cons 'str-i (list (cons 'raw str-i) (cons 'formatted (utf8->string str-i))))
        (cons 'ext-i (list (cons 'raw ext-i) (cons 'formatted (utf8->string ext-i))))
        (cons 'ext-t (list (cons 'raw ext-t) (cons 'formatted (utf8->string ext-t))))
        (cons 'str-t (list (cons 'raw str-t) (cons 'formatted (utf8->string str-t))))
        (cons 'extension-token (list (cons 'raw extension-token) (cons 'formatted (utf8->string extension-token))))
        (cons 'opaque-data (list (cons 'raw opaque-data) (cons 'formatted (fmt-bytes opaque-data))))
        (cons 'literal-ac (list (cons 'raw literal-ac) (cons 'formatted (utf8->string literal-ac))))
        (cons 'literal-c (list (cons 'raw literal-c) (cons 'formatted (utf8->string literal-c))))
        (cons 'end-known-tag-uint (list (cons 'raw end-known-tag-uint) (cons 'formatted (number->string end-known-tag-uint))))
        (cons 'literal-a (list (cons 'raw literal-a) (cons 'formatted (utf8->string literal-a))))
        (cons 'end-literal-tag (list (cons 'raw end-literal-tag) (cons 'formatted (utf8->string end-literal-tag))))
        (cons 'known-tag (list (cons 'raw known-tag) (cons 'formatted (utf8->string known-tag))))
        (cons 'literal (list (cons 'raw literal) (cons 'formatted (utf8->string literal))))
        )))

    (catch (e)
      (err (str "WBXML parse error: " e)))))

;; dissect-wbxml: parse WBXML from bytevector
;; Returns (ok fields-alist) or (err message)