;; packet-egnos-ems.c
;; EGNOS Message Server file format dissection.
;;
;; By Timo Warns <timo.warns@gmail.com>
;; Copyright 2023 Timo Warns
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@unicom.net>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/egnos-ems.ss
;; Auto-generated from wireshark/epan/dissectors/packet-egnos_ems.c

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
(def (dissect-egnos-ems buffer)
  "EGNOS Message Server file"
  (try
    (let* (
           (prn (unwrap (slice buffer 0 3)))
           (year (unwrap (slice buffer 4 2)))
           (month (unwrap (slice buffer 7 2)))
           (day (unwrap (slice buffer 10 2)))
           (hour (unwrap (slice buffer 13 2)))
           (minute (unwrap (slice buffer 16 2)))
           (second (unwrap (slice buffer 19 2)))
           (mt (unwrap (slice buffer 22 1)))
           (nof (unwrap (slice buffer 25 1)))
           (svc-flag (unwrap (slice buffer 29 2)))
           (nof-bits (unwrap (slice buffer 32 4)))
           )

      (ok (list
        (cons 'prn (list (cons 'raw prn) (cons 'formatted (utf8->string prn))))
        (cons 'year (list (cons 'raw year) (cons 'formatted (utf8->string year))))
        (cons 'month (list (cons 'raw month) (cons 'formatted (utf8->string month))))
        (cons 'day (list (cons 'raw day) (cons 'formatted (utf8->string day))))
        (cons 'hour (list (cons 'raw hour) (cons 'formatted (utf8->string hour))))
        (cons 'minute (list (cons 'raw minute) (cons 'formatted (utf8->string minute))))
        (cons 'second (list (cons 'raw second) (cons 'formatted (utf8->string second))))
        (cons 'mt (list (cons 'raw mt) (cons 'formatted (utf8->string mt))))
        (cons 'nof (list (cons 'raw nof) (cons 'formatted (fmt-bytes nof))))
        (cons 'svc-flag (list (cons 'raw svc-flag) (cons 'formatted (utf8->string svc-flag))))
        (cons 'nof-bits (list (cons 'raw nof-bits) (cons 'formatted (utf8->string nof-bits))))
        )))

    (catch (e)
      (err (str "EGNOS-EMS parse error: " e)))))

;; dissect-egnos-ems: parse EGNOS-EMS from bytevector
;; Returns (ok fields-alist) or (err message)