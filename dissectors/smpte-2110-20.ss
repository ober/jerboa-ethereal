;; packet-smpte-2110-20.c
;; SMPTE ST2110-20
;;
;; Copyright 2023, Sergey V. Lobanov <sergey@lobanov.in>
;;
;; References:
;; SMPTE ST 2110-20:2022, Uncompressed Active Video
;; RFC4175, RTP Payload Format for Uncompressed Video
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/smpte-2110-20.ss
;; Auto-generated from wireshark/epan/dissectors/packet-smpte_2110_20.c
;; RFC 4175

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
(def (dissect-smpte-2110-20 buffer)
  "SMPTE ST2110-20 (Uncompressed Active Video)"
  (try
    (let* (
           (ext-seqno (unwrap (read-u16be buffer 0)))
           (seqno (unwrap (read-u16be buffer 0)))
           (srd-length (unwrap (read-u16be buffer 2)))
           (field-ident (unwrap (read-u16be buffer 4)))
           (row-num (unwrap (read-u16be buffer 4)))
           (continuation (unwrap (read-u16be buffer 6)))
           (srd-offset (unwrap (read-u16be buffer 6)))
           )

      (ok (list
        (cons 'ext-seqno (list (cons 'raw ext-seqno) (cons 'formatted (number->string ext-seqno))))
        (cons 'seqno (list (cons 'raw seqno) (cons 'formatted (number->string seqno))))
        (cons 'srd-length (list (cons 'raw srd-length) (cons 'formatted (number->string srd-length))))
        (cons 'field-ident (list (cons 'raw field-ident) (cons 'formatted (number->string field-ident))))
        (cons 'row-num (list (cons 'raw row-num) (cons 'formatted (number->string row-num))))
        (cons 'continuation (list (cons 'raw continuation) (cons 'formatted (number->string continuation))))
        (cons 'srd-offset (list (cons 'raw srd-offset) (cons 'formatted (number->string srd-offset))))
        )))

    (catch (e)
      (err (str "SMPTE-2110-20 parse error: " e)))))

;; dissect-smpte-2110-20: parse SMPTE-2110-20 from bytevector
;; Returns (ok fields-alist) or (err message)