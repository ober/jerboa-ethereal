;; packet-isup.c
;; Routines for ISUP dissection
;; Copyright 2001, Martina Obermeier <martina.obermeier@icn.siemens.de>
;;
;; Modified 2003-09-10 by Anders Broman
;; <anders.broman@ericsson.com>
;; Inserted routines for BICC dissection according to Q.765.5 Q.1902 Q.1970 Q.1990,
;; calling SDP dissector for RFC2327 decoding.
;; Modified 2004-01-10 by Anders Broman to add ability to dissect
;; Content type application/ISUP RFC 3204 used in SIP-T
;;
;; Copyright 2004-2005, Anders Broman <anders.broman@ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from README.developer
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; References:
;; ISUP:
;; http://www.itu.int/rec/recommendation.asp?type=products&lang=e&parent=T-REC-Q
;; Q.763-199912, Q.763-200212Amd2
;; ITU-T Q.763/Amd.1 (03/2001)
;;
;; National variants
;; French ISUP Specification: SPIROU 1998 - 002-005 edition 1 ( Info found here http://www.icg-corp.com/docs/ISUP.pdf ).
;; See also http://www.fftelecoms.org/sites/default/files/contenus_lies/fft_interco_ip_-_sip-i_interface_specification_v1_0.pdf
;; Israeli ISUP Specification: excertp (for BCM message) found in https://gitlab.com/wireshark/wireshark/-/issues/4231 .
;; Russian national ISUP-R 2000: RD 45.217-2001 book 4
;; Japan ISUP http://www.ttc.or.jp/jp/document_list/sum/sum_JT-Q763v21.1.pdf
;;

;; jerboa-ethereal/dissectors/isup.ss
;; Auto-generated from wireshark/epan/dissectors/packet-isup.c
;; RFC 2327

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
(def (dissect-isup buffer)
  "ISDN User Part"
  (try
    (let* (
           (configuration-data (unwrap (read-u8 buffer 1)))
           (code-set (unwrap (read-u8 buffer 1)))
           (code-set-12-2 (extract-bits code-set 0x80 7))
           (code-set-10-2 (extract-bits code-set 0x40 6))
           (code-set-7-95 (extract-bits code-set 0x20 5))
           (code-set-7-40 (extract-bits code-set 0x10 4))
           (code-set-6-70 (extract-bits code-set 0x8 3))
           (code-set-5-90 (extract-bits code-set 0x4 2))
           (code-set-5-15 (extract-bits code-set 0x2 1))
           (code-set-4-75 (extract-bits code-set 0x1 0))
           (codec-modes (unwrap (read-u8 buffer 1)))
           (unknown-organisation-identifier (unwrap (read-u8 buffer 1)))
           )

      (ok (list
        (cons 'configuration-data (list (cons 'raw configuration-data) (cons 'formatted (fmt-hex configuration-data))))
        (cons 'code-set (list (cons 'raw code-set) (cons 'formatted (fmt-hex code-set))))
        (cons 'code-set-12-2 (list (cons 'raw code-set-12-2) (cons 'formatted (if (= code-set-12-2 0) "Not set" "Set"))))
        (cons 'code-set-10-2 (list (cons 'raw code-set-10-2) (cons 'formatted (if (= code-set-10-2 0) "Not set" "Set"))))
        (cons 'code-set-7-95 (list (cons 'raw code-set-7-95) (cons 'formatted (if (= code-set-7-95 0) "Not set" "Set"))))
        (cons 'code-set-7-40 (list (cons 'raw code-set-7-40) (cons 'formatted (if (= code-set-7-40 0) "Not set" "Set"))))
        (cons 'code-set-6-70 (list (cons 'raw code-set-6-70) (cons 'formatted (if (= code-set-6-70 0) "Not set" "Set"))))
        (cons 'code-set-5-90 (list (cons 'raw code-set-5-90) (cons 'formatted (if (= code-set-5-90 0) "Not set" "Set"))))
        (cons 'code-set-5-15 (list (cons 'raw code-set-5-15) (cons 'formatted (if (= code-set-5-15 0) "Not set" "Set"))))
        (cons 'code-set-4-75 (list (cons 'raw code-set-4-75) (cons 'formatted (if (= code-set-4-75 0) "Not set" "Set"))))
        (cons 'codec-modes (list (cons 'raw codec-modes) (cons 'formatted (number->string codec-modes))))
        (cons 'unknown-organisation-identifier (list (cons 'raw unknown-organisation-identifier) (cons 'formatted (number->string unknown-organisation-identifier))))
        )))

    (catch (e)
      (err (str "ISUP parse error: " e)))))

;; dissect-isup: parse ISUP from bytevector
;; Returns (ok fields-alist) or (err message)