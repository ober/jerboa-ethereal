;; packet-ouch.c
;; Routines for OUCH 4.x protocol dissection
;; Copyright (C) 2013, 2015, 2016 David Arnold <d@0x1.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ouch.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ouch.c

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
(def (dissect-ouch buffer)
  "OUCH"
  (try
    (let* (
           (existing-order-token (unwrap (slice buffer 114 14)))
           (replacement-order-token (unwrap (slice buffer 214 14)))
           (stock (unwrap (slice buffer 233 8)))
           (firm (unwrap (slice buffer 249 4)))
           (min-quantity (unwrap (read-u32be buffer 264)))
           (previous-order-token (unwrap (slice buffer 270 14)))
           (decrement-shares (unwrap (read-u32be buffer 334)))
           (quantity-prevented-from-trading (unwrap (read-u32be buffer 339)))
           (executed-shares (unwrap (read-u32be buffer 480)))
           (match-number (unwrap (read-u64be buffer 524)))
           (order-reference-number (unwrap (read-u64be buffer 631)))
           (order-token (unwrap (slice buffer 647 14)))
           (shares (unwrap (read-u32be buffer 662)))
           (message (unwrap (slice buffer 666 1)))
           )

      (ok (list
        (cons 'existing-order-token (list (cons 'raw existing-order-token) (cons 'formatted (utf8->string existing-order-token))))
        (cons 'replacement-order-token (list (cons 'raw replacement-order-token) (cons 'formatted (utf8->string replacement-order-token))))
        (cons 'stock (list (cons 'raw stock) (cons 'formatted (utf8->string stock))))
        (cons 'firm (list (cons 'raw firm) (cons 'formatted (utf8->string firm))))
        (cons 'min-quantity (list (cons 'raw min-quantity) (cons 'formatted (number->string min-quantity))))
        (cons 'previous-order-token (list (cons 'raw previous-order-token) (cons 'formatted (utf8->string previous-order-token))))
        (cons 'decrement-shares (list (cons 'raw decrement-shares) (cons 'formatted (number->string decrement-shares))))
        (cons 'quantity-prevented-from-trading (list (cons 'raw quantity-prevented-from-trading) (cons 'formatted (number->string quantity-prevented-from-trading))))
        (cons 'executed-shares (list (cons 'raw executed-shares) (cons 'formatted (number->string executed-shares))))
        (cons 'match-number (list (cons 'raw match-number) (cons 'formatted (number->string match-number))))
        (cons 'order-reference-number (list (cons 'raw order-reference-number) (cons 'formatted (number->string order-reference-number))))
        (cons 'order-token (list (cons 'raw order-token) (cons 'formatted (utf8->string order-token))))
        (cons 'shares (list (cons 'raw shares) (cons 'formatted (number->string shares))))
        (cons 'message (list (cons 'raw message) (cons 'formatted (fmt-bytes message))))
        )))

    (catch (e)
      (err (str "OUCH parse error: " e)))))

;; dissect-ouch: parse OUCH from bytevector
;; Returns (ok fields-alist) or (err message)