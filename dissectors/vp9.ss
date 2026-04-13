;; packet-vp9.c
;; Routines for VP9 dissection
;; Copyright 2023, Noan Perrot <noan.perrot@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vp9.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vp9.c

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
(def (dissect-vp9 buffer)
  "VP9"
  (try
    (let* (
           (pld-p-bit (unwrap (read-u8 buffer 0)))
           (pld-l-bit (unwrap (read-u8 buffer 0)))
           (pld-f-bit (unwrap (read-u8 buffer 0)))
           (pld-b-bit (unwrap (read-u8 buffer 0)))
           (pld-e-bit (unwrap (read-u8 buffer 0)))
           (pld-v-bit (unwrap (read-u8 buffer 0)))
           (pld-z-bit (unwrap (read-u8 buffer 0)))
           (pld-m-bit (unwrap (read-u8 buffer 0)))
           (pld-pid-extended-bits (unwrap (read-u16be buffer 0)))
           (pld-pid-bits (unwrap (read-u8 buffer 2)))
           (pld-pg-extended-bits (unwrap (read-u16be buffer 2)))
           (pld-pg-bits (unwrap (read-u8 buffer 4)))
           (pld-tid-bits (unwrap (read-u8 buffer 4)))
           (pld-u-bit (unwrap (read-u8 buffer 4)))
           (pld-sid-bits (unwrap (read-u8 buffer 4)))
           (pld-d-bit (unwrap (read-u8 buffer 4)))
           (pld-tl0picidx-bits (unwrap (read-u8 buffer 4)))
           (pld-p-diff-bits (unwrap (read-u8 buffer 4)))
           (pld-n-bit (unwrap (read-u8 buffer 4)))
           (pld-n-s-bits (unwrap (read-u8 buffer 4)))
           (pld-n-s-numbers (unwrap (read-u8 buffer 4)))
           (pld-y-bit (unwrap (read-u8 buffer 4)))
           (pld-g-bit (unwrap (read-u8 buffer 4)))
           (pld-width-bits (unwrap (read-u16be buffer 4)))
           (pld-height-bits (unwrap (read-u16be buffer 6)))
           (pld-n-g-bits (unwrap (read-u8 buffer 8)))
           (pld-i-bit (unwrap (read-u8 buffer 9)))
           )

      (ok (list
        (cons 'pld-p-bit (list (cons 'raw pld-p-bit) (cons 'formatted (number->string pld-p-bit))))
        (cons 'pld-l-bit (list (cons 'raw pld-l-bit) (cons 'formatted (number->string pld-l-bit))))
        (cons 'pld-f-bit (list (cons 'raw pld-f-bit) (cons 'formatted (number->string pld-f-bit))))
        (cons 'pld-b-bit (list (cons 'raw pld-b-bit) (cons 'formatted (number->string pld-b-bit))))
        (cons 'pld-e-bit (list (cons 'raw pld-e-bit) (cons 'formatted (number->string pld-e-bit))))
        (cons 'pld-v-bit (list (cons 'raw pld-v-bit) (cons 'formatted (number->string pld-v-bit))))
        (cons 'pld-z-bit (list (cons 'raw pld-z-bit) (cons 'formatted (number->string pld-z-bit))))
        (cons 'pld-m-bit (list (cons 'raw pld-m-bit) (cons 'formatted (number->string pld-m-bit))))
        (cons 'pld-pid-extended-bits (list (cons 'raw pld-pid-extended-bits) (cons 'formatted (number->string pld-pid-extended-bits))))
        (cons 'pld-pid-bits (list (cons 'raw pld-pid-bits) (cons 'formatted (number->string pld-pid-bits))))
        (cons 'pld-pg-extended-bits (list (cons 'raw pld-pg-extended-bits) (cons 'formatted (number->string pld-pg-extended-bits))))
        (cons 'pld-pg-bits (list (cons 'raw pld-pg-bits) (cons 'formatted (number->string pld-pg-bits))))
        (cons 'pld-tid-bits (list (cons 'raw pld-tid-bits) (cons 'formatted (number->string pld-tid-bits))))
        (cons 'pld-u-bit (list (cons 'raw pld-u-bit) (cons 'formatted (number->string pld-u-bit))))
        (cons 'pld-sid-bits (list (cons 'raw pld-sid-bits) (cons 'formatted (number->string pld-sid-bits))))
        (cons 'pld-d-bit (list (cons 'raw pld-d-bit) (cons 'formatted (number->string pld-d-bit))))
        (cons 'pld-tl0picidx-bits (list (cons 'raw pld-tl0picidx-bits) (cons 'formatted (number->string pld-tl0picidx-bits))))
        (cons 'pld-p-diff-bits (list (cons 'raw pld-p-diff-bits) (cons 'formatted (number->string pld-p-diff-bits))))
        (cons 'pld-n-bit (list (cons 'raw pld-n-bit) (cons 'formatted (number->string pld-n-bit))))
        (cons 'pld-n-s-bits (list (cons 'raw pld-n-s-bits) (cons 'formatted (number->string pld-n-s-bits))))
        (cons 'pld-n-s-numbers (list (cons 'raw pld-n-s-numbers) (cons 'formatted (number->string pld-n-s-numbers))))
        (cons 'pld-y-bit (list (cons 'raw pld-y-bit) (cons 'formatted (number->string pld-y-bit))))
        (cons 'pld-g-bit (list (cons 'raw pld-g-bit) (cons 'formatted (number->string pld-g-bit))))
        (cons 'pld-width-bits (list (cons 'raw pld-width-bits) (cons 'formatted (number->string pld-width-bits))))
        (cons 'pld-height-bits (list (cons 'raw pld-height-bits) (cons 'formatted (number->string pld-height-bits))))
        (cons 'pld-n-g-bits (list (cons 'raw pld-n-g-bits) (cons 'formatted (number->string pld-n-g-bits))))
        (cons 'pld-i-bit (list (cons 'raw pld-i-bit) (cons 'formatted (number->string pld-i-bit))))
        )))

    (catch (e)
      (err (str "VP9 parse error: " e)))))

;; dissect-vp9: parse VP9 from bytevector
;; Returns (ok fields-alist) or (err message)