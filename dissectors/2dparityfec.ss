;; packet-2dparityfec.c
;; Mark Lewis <mlewis@altera.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/2dparityfec.ss
;; Auto-generated from wireshark/epan/dissectors/packet-2dparityfec.c

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
(def (dissect-2dparityfec buffer)
  "Pro-MPEG Code of Practice #3 release 2 FEC Protocol"
  (try
    (let* (
           (snbase-low (unwrap (read-u16be buffer 0)))
           (length-recovery (unwrap (read-u16be buffer 2)))
           (rfc2733-ext (unwrap (read-u8 buffer 4)))
           (pt-recovery (unwrap (read-u8 buffer 4)))
           (ts-recovery (unwrap (read-u32be buffer 8)))
           (ts-pro-mpeg-ext (unwrap (read-u8 buffer 12)))
           (row-flag (unwrap (read-u8 buffer 12)))
           (index (unwrap (read-u8 buffer 12)))
           (offset (unwrap (read-u8 buffer 13)))
           (na (unwrap (read-u8 buffer 14)))
           (snbase-ext (unwrap (read-u8 buffer 15)))
           (payload (unwrap (slice buffer 16 1)))
           )

      (ok (list
        (cons 'snbase-low (list (cons 'raw snbase-low) (cons 'formatted (number->string snbase-low))))
        (cons 'length-recovery (list (cons 'raw length-recovery) (cons 'formatted (fmt-hex length-recovery))))
        (cons 'rfc2733-ext (list (cons 'raw rfc2733-ext) (cons 'formatted (number->string rfc2733-ext))))
        (cons 'pt-recovery (list (cons 'raw pt-recovery) (cons 'formatted (fmt-hex pt-recovery))))
        (cons 'ts-recovery (list (cons 'raw ts-recovery) (cons 'formatted (fmt-hex ts-recovery))))
        (cons 'ts-pro-mpeg-ext (list (cons 'raw ts-pro-mpeg-ext) (cons 'formatted (number->string ts-pro-mpeg-ext))))
        (cons 'row-flag (list (cons 'raw row-flag) (cons 'formatted (number->string row-flag))))
        (cons 'index (list (cons 'raw index) (cons 'formatted (number->string index))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (number->string offset))))
        (cons 'na (list (cons 'raw na) (cons 'formatted (number->string na))))
        (cons 'snbase-ext (list (cons 'raw snbase-ext) (cons 'formatted (number->string snbase-ext))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        )))

    (catch (e)
      (err (str "2DPARITYFEC parse error: " e)))))

;; dissect-2dparityfec: parse 2DPARITYFEC from bytevector
;; Returns (ok fields-alist) or (err message)