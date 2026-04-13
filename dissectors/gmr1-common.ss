;; packet-gmr1_common.c
;;
;; Routines for GMR-1 dissection in wireshark (common stuff).
;; Copyright (c) 2011 Sylvain Munaut <tnt@246tNt.com>
;;
;; References:
;; [1] ETSI TS 101 376-4-8 V1.3.1 - GMR-1 04.008
;; [2] ETSI TS 101 376-4-8 V2.2.1 - GMPRS-1 04.008
;; [3] ETSI TS 101 376-4-8 V3.1.1 - GMR-1 3G 44.008
;; [4] ETSI TS 100 940 V7.21.0 - GSM 04.08
;; [5] ETSI TS 101 376-4-12 V3.2.1 - GMR-1 3G 44.060
;; [6] ETSI TS 101 376-5-6 V1.3.1 - GMR-1 05.008
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gmr1-common.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gmr1_common.c

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
(def (dissect-gmr1-common buffer)
  "GEO-Mobile Radio (1) Common"
  (try
    (let* (
           (cm2-spare2 (unwrap (read-u8 buffer 0)))
           (cm2-spare3 (unwrap (read-u8 buffer 0)))
           (cm2-spare4 (unwrap (read-u8 buffer 0)))
           (spare-nibble (unwrap (read-u8 buffer 0)))
           (cm2-spare1 (unwrap (read-u8 buffer 1)))
           )

      (ok (list
        (cons 'cm2-spare2 (list (cons 'raw cm2-spare2) (cons 'formatted (number->string cm2-spare2))))
        (cons 'cm2-spare3 (list (cons 'raw cm2-spare3) (cons 'formatted (number->string cm2-spare3))))
        (cons 'cm2-spare4 (list (cons 'raw cm2-spare4) (cons 'formatted (number->string cm2-spare4))))
        (cons 'spare-nibble (list (cons 'raw spare-nibble) (cons 'formatted (fmt-hex spare-nibble))))
        (cons 'cm2-spare1 (list (cons 'raw cm2-spare1) (cons 'formatted (number->string cm2-spare1))))
        )))

    (catch (e)
      (err (str "GMR1-COMMON parse error: " e)))))

;; dissect-gmr1-common: parse GMR1-COMMON from bytevector
;; Returns (ok fields-alist) or (err message)