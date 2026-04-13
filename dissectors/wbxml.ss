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
           (public-id-literal (unwrap (slice buffer 1 1)))
           )

      (ok (list
        (cons 'string-table-item-offset (list (cons 'raw string-table-item-offset) (cons 'formatted (number->string string-table-item-offset))))
        (cons 'public-id-literal (list (cons 'raw public-id-literal) (cons 'formatted (utf8->string public-id-literal))))
        )))

    (catch (e)
      (err (str "WBXML parse error: " e)))))

;; dissect-wbxml: parse WBXML from bytevector
;; Returns (ok fields-alist) or (err message)