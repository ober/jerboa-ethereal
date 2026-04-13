;; packet-bist-itch.c
;; Routines for BIST-ITCH dissection
;; Copyright 2025, Sadettin Er <sadettin.er@b-ulltech.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bist-itch.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bist_itch.c

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
(def (dissect-bist-itch buffer)
  "BIST ITCH"
  (try
    (let* (
           (ranking-seq (unwrap (read-u32be buffer 6)))
           (order-attributes (unwrap (read-u16be buffer 10)))
           (lot-type (unwrap (read-u8 buffer 12)))
           (ranking-time (unwrap (read-u64be buffer 13)))
           (eq-bid-qty (unwrap (read-u64be buffer 25)))
           (eq-ask-qty (unwrap (read-u64be buffer 33)))
           (bid-qty (unwrap (read-u64be buffer 41)))
           (ask-qty (unwrap (read-u64be buffer 49)))
           (combo-orderbook-id (unwrap (read-u32be buffer 57)))
           (leg-order-book (unwrap (read-u32be buffer 61)))
           (leg-ratio (unwrap (read-u32be buffer 66)))
           (second (unwrap (read-u32be buffer 101)))
           (match-id (unwrap (read-u64be buffer 143)))
           (combo-group (unwrap (read-u32be buffer 151)))
           (reserved1 (unwrap (slice buffer 155 7)))
           (reserved2 (unwrap (slice buffer 162 7)))
           (occurred-cross (unwrap (slice buffer 169 1)))
           (printable (unwrap (slice buffer 170 1)))
           (symbol (unwrap (slice buffer 181 32)))
           (long-name (unwrap (slice buffer 213 32)))
           (isin (unwrap (slice buffer 245 12)))
           (financial-product (unwrap (read-u8 buffer 257)))
           (trading-currency (unwrap (slice buffer 258 3)))
           (price-decimals (unwrap (read-u16be buffer 261)))
           (nominal-decimals (unwrap (read-u16be buffer 263)))
           (odd-lot-size (unwrap (read-u32be buffer 265)))
           (round-lot-size (unwrap (read-u32be buffer 269)))
           (block-lot-size (unwrap (read-u32be buffer 273)))
           (nominal-value (unwrap (read-u64be buffer 277)))
           (number-of-leg (unwrap (read-u8 buffer 285)))
           (underlying-orderbook-id (unwrap (read-u32be buffer 286)))
           (expiration-date (unwrap (read-u32be buffer 290)))
           (strike-price-decimals (unwrap (read-u16be buffer 294)))
           (put-or-call (unwrap (read-u8 buffer 296)))
           (ranking-type (unwrap (read-u8 buffer 297)))
           (short-sell-status (unwrap (read-u8 buffer 306)))
           (state-name (unwrap (slice buffer 311 20)))
           (orderbook-id (unwrap (read-u32be buffer 331)))
           (tick-size (unwrap (read-u64be buffer 335)))
           (message (unwrap (slice buffer 343 1)))
           (unexpected (unwrap (slice buffer 343 1)))
           )

      (ok (list
        (cons 'ranking-seq (list (cons 'raw ranking-seq) (cons 'formatted (number->string ranking-seq))))
        (cons 'order-attributes (list (cons 'raw order-attributes) (cons 'formatted (fmt-hex order-attributes))))
        (cons 'lot-type (list (cons 'raw lot-type) (cons 'formatted (number->string lot-type))))
        (cons 'ranking-time (list (cons 'raw ranking-time) (cons 'formatted (number->string ranking-time))))
        (cons 'eq-bid-qty (list (cons 'raw eq-bid-qty) (cons 'formatted (number->string eq-bid-qty))))
        (cons 'eq-ask-qty (list (cons 'raw eq-ask-qty) (cons 'formatted (number->string eq-ask-qty))))
        (cons 'bid-qty (list (cons 'raw bid-qty) (cons 'formatted (number->string bid-qty))))
        (cons 'ask-qty (list (cons 'raw ask-qty) (cons 'formatted (number->string ask-qty))))
        (cons 'combo-orderbook-id (list (cons 'raw combo-orderbook-id) (cons 'formatted (number->string combo-orderbook-id))))
        (cons 'leg-order-book (list (cons 'raw leg-order-book) (cons 'formatted (number->string leg-order-book))))
        (cons 'leg-ratio (list (cons 'raw leg-ratio) (cons 'formatted (number->string leg-ratio))))
        (cons 'second (list (cons 'raw second) (cons 'formatted (number->string second))))
        (cons 'match-id (list (cons 'raw match-id) (cons 'formatted (number->string match-id))))
        (cons 'combo-group (list (cons 'raw combo-group) (cons 'formatted (number->string combo-group))))
        (cons 'reserved1 (list (cons 'raw reserved1) (cons 'formatted (fmt-bytes reserved1))))
        (cons 'reserved2 (list (cons 'raw reserved2) (cons 'formatted (fmt-bytes reserved2))))
        (cons 'occurred-cross (list (cons 'raw occurred-cross) (cons 'formatted (utf8->string occurred-cross))))
        (cons 'printable (list (cons 'raw printable) (cons 'formatted (utf8->string printable))))
        (cons 'symbol (list (cons 'raw symbol) (cons 'formatted (utf8->string symbol))))
        (cons 'long-name (list (cons 'raw long-name) (cons 'formatted (utf8->string long-name))))
        (cons 'isin (list (cons 'raw isin) (cons 'formatted (utf8->string isin))))
        (cons 'financial-product (list (cons 'raw financial-product) (cons 'formatted (number->string financial-product))))
        (cons 'trading-currency (list (cons 'raw trading-currency) (cons 'formatted (utf8->string trading-currency))))
        (cons 'price-decimals (list (cons 'raw price-decimals) (cons 'formatted (number->string price-decimals))))
        (cons 'nominal-decimals (list (cons 'raw nominal-decimals) (cons 'formatted (number->string nominal-decimals))))
        (cons 'odd-lot-size (list (cons 'raw odd-lot-size) (cons 'formatted (number->string odd-lot-size))))
        (cons 'round-lot-size (list (cons 'raw round-lot-size) (cons 'formatted (number->string round-lot-size))))
        (cons 'block-lot-size (list (cons 'raw block-lot-size) (cons 'formatted (number->string block-lot-size))))
        (cons 'nominal-value (list (cons 'raw nominal-value) (cons 'formatted (number->string nominal-value))))
        (cons 'number-of-leg (list (cons 'raw number-of-leg) (cons 'formatted (number->string number-of-leg))))
        (cons 'underlying-orderbook-id (list (cons 'raw underlying-orderbook-id) (cons 'formatted (number->string underlying-orderbook-id))))
        (cons 'expiration-date (list (cons 'raw expiration-date) (cons 'formatted (number->string expiration-date))))
        (cons 'strike-price-decimals (list (cons 'raw strike-price-decimals) (cons 'formatted (number->string strike-price-decimals))))
        (cons 'put-or-call (list (cons 'raw put-or-call) (cons 'formatted (number->string put-or-call))))
        (cons 'ranking-type (list (cons 'raw ranking-type) (cons 'formatted (number->string ranking-type))))
        (cons 'short-sell-status (list (cons 'raw short-sell-status) (cons 'formatted (number->string short-sell-status))))
        (cons 'state-name (list (cons 'raw state-name) (cons 'formatted (utf8->string state-name))))
        (cons 'orderbook-id (list (cons 'raw orderbook-id) (cons 'formatted (number->string orderbook-id))))
        (cons 'tick-size (list (cons 'raw tick-size) (cons 'formatted (number->string tick-size))))
        (cons 'message (list (cons 'raw message) (cons 'formatted (fmt-bytes message))))
        (cons 'unexpected (list (cons 'raw unexpected) (cons 'formatted (fmt-bytes unexpected))))
        )))

    (catch (e)
      (err (str "BIST-ITCH parse error: " e)))))

;; dissect-bist-itch: parse BIST-ITCH from bytevector
;; Returns (ok fields-alist) or (err message)