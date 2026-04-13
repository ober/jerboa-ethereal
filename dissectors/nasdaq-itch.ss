;; packet-nasdaq-itch.c
;; Routines for NASDAQ TotalView-ITCH version 2.00/3.00 (with Chi-X extension) Protocol dissection
;; Copyright 2007,2008 Didier Gautheron <dgautheron@magic.fr>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Documentation:
;; http://www.nasdaqtrader.com/Trader.aspx?id=DPSpecs
;; ex:
;; http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/tv-itch2a.pdf
;; http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/tvitch-v3.pdf
;;
;; Chi-X
;; http://www.chi-x.com/docs/Chi-X%20CHIXMD.pdf
;;
;;

;; jerboa-ethereal/dissectors/nasdaq-itch.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nasdaq_itch.c

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
(def (dissect-nasdaq-itch buffer)
  "Nasdaq TotalView-ITCH"
  (try
    (let* (
           (itch-version (unwrap (read-u8 buffer 0)))
           (itch-round-lot-size (unwrap (slice buffer 4 6)))
           (itch-trading-state (unwrap (slice buffer 11 1)))
           (itch-reserved (unwrap (slice buffer 12 1)))
           (itch-reason (unwrap (slice buffer 13 4)))
           (itch-attribution (unwrap (slice buffer 18 4)))
           (itch-printable (unwrap (slice buffer 22 1)))
           (itch-match (unwrap (slice buffer 51 9)))
           (itch-cross (unwrap (slice buffer 60 1)))
           (itch-message (unwrap (slice buffer 61 1)))
           )

      (ok (list
        (cons 'itch-version (list (cons 'raw itch-version) (cons 'formatted (number->string itch-version))))
        (cons 'itch-round-lot-size (list (cons 'raw itch-round-lot-size) (cons 'formatted (utf8->string itch-round-lot-size))))
        (cons 'itch-trading-state (list (cons 'raw itch-trading-state) (cons 'formatted (utf8->string itch-trading-state))))
        (cons 'itch-reserved (list (cons 'raw itch-reserved) (cons 'formatted (utf8->string itch-reserved))))
        (cons 'itch-reason (list (cons 'raw itch-reason) (cons 'formatted (utf8->string itch-reason))))
        (cons 'itch-attribution (list (cons 'raw itch-attribution) (cons 'formatted (utf8->string itch-attribution))))
        (cons 'itch-printable (list (cons 'raw itch-printable) (cons 'formatted (utf8->string itch-printable))))
        (cons 'itch-match (list (cons 'raw itch-match) (cons 'formatted (utf8->string itch-match))))
        (cons 'itch-cross (list (cons 'raw itch-cross) (cons 'formatted (utf8->string itch-cross))))
        (cons 'itch-message (list (cons 'raw itch-message) (cons 'formatted (utf8->string itch-message))))
        )))

    (catch (e)
      (err (str "NASDAQ-ITCH parse error: " e)))))

;; dissect-nasdaq-itch: parse NASDAQ-ITCH from bytevector
;; Returns (ok fields-alist) or (err message)