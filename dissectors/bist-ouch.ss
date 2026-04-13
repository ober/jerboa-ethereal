;; packet-bist-ouch.c
;; Routines for BIST-OUCH dissection
;; Copyright 2025, Sadettin Er <sadettin.er@b-ulltech.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bist-ouch.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bist_ouch.c

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
(def (dissect-bist-ouch buffer)
  "BIST OUCH"
  (try
    (let* (
           (no-quote-entries (unwrap (read-u16be buffer 184)))
           (q-entry-bid-sz (unwrap (read-u64be buffer 190)))
           (q-entry-offer-sz (unwrap (read-u64be buffer 198)))
           (client-account (unwrap (slice buffer 251 16)))
           (order-state (unwrap (read-u8 buffer 267)))
           (customer-info (unwrap (slice buffer 268 15)))
           (exchange-info (unwrap (slice buffer 283 32)))
           (pretrade-qty (unwrap (read-u64be buffer 315)))
           (display-qty (unwrap (read-u64be buffer 323)))
           (offhours (unwrap (read-u8 buffer 332)))
           (smp-level (unwrap (read-u8 buffer 333)))
           (smp-method (unwrap (read-u8 buffer 334)))
           (smp-id (unwrap (slice buffer 335 3)))
           (order-id (unwrap (read-u64be buffer 391)))
           (orderbook-id (unwrap (read-u32be buffer 422)))
           (match-id (unwrap (slice buffer 434 12)))
           (reserved (unwrap (slice buffer 447 16)))
           (quantity (unwrap (read-u64be buffer 489)))
           (traded-qty (unwrap (read-u64be buffer 497)))
           (timestamp-ns (unwrap (read-u64be buffer 510)))
           (order-token (unwrap (slice buffer 518 14)))
           (q-entry-orderbook-id (unwrap (read-u32be buffer 532)))
           (reject-code (unwrap (read-u32be buffer 536)))
           (raw (unwrap (slice buffer 540 1)))
           )

      (ok (list
        (cons 'no-quote-entries (list (cons 'raw no-quote-entries) (cons 'formatted (number->string no-quote-entries))))
        (cons 'q-entry-bid-sz (list (cons 'raw q-entry-bid-sz) (cons 'formatted (number->string q-entry-bid-sz))))
        (cons 'q-entry-offer-sz (list (cons 'raw q-entry-offer-sz) (cons 'formatted (number->string q-entry-offer-sz))))
        (cons 'client-account (list (cons 'raw client-account) (cons 'formatted (utf8->string client-account))))
        (cons 'order-state (list (cons 'raw order-state) (cons 'formatted (number->string order-state))))
        (cons 'customer-info (list (cons 'raw customer-info) (cons 'formatted (utf8->string customer-info))))
        (cons 'exchange-info (list (cons 'raw exchange-info) (cons 'formatted (utf8->string exchange-info))))
        (cons 'pretrade-qty (list (cons 'raw pretrade-qty) (cons 'formatted (number->string pretrade-qty))))
        (cons 'display-qty (list (cons 'raw display-qty) (cons 'formatted (number->string display-qty))))
        (cons 'offhours (list (cons 'raw offhours) (cons 'formatted (number->string offhours))))
        (cons 'smp-level (list (cons 'raw smp-level) (cons 'formatted (number->string smp-level))))
        (cons 'smp-method (list (cons 'raw smp-method) (cons 'formatted (number->string smp-method))))
        (cons 'smp-id (list (cons 'raw smp-id) (cons 'formatted (utf8->string smp-id))))
        (cons 'order-id (list (cons 'raw order-id) (cons 'formatted (number->string order-id))))
        (cons 'orderbook-id (list (cons 'raw orderbook-id) (cons 'formatted (number->string orderbook-id))))
        (cons 'match-id (list (cons 'raw match-id) (cons 'formatted (fmt-bytes match-id))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'quantity (list (cons 'raw quantity) (cons 'formatted (number->string quantity))))
        (cons 'traded-qty (list (cons 'raw traded-qty) (cons 'formatted (number->string traded-qty))))
        (cons 'timestamp-ns (list (cons 'raw timestamp-ns) (cons 'formatted (number->string timestamp-ns))))
        (cons 'order-token (list (cons 'raw order-token) (cons 'formatted (utf8->string order-token))))
        (cons 'q-entry-orderbook-id (list (cons 'raw q-entry-orderbook-id) (cons 'formatted (number->string q-entry-orderbook-id))))
        (cons 'reject-code (list (cons 'raw reject-code) (cons 'formatted (number->string reject-code))))
        (cons 'raw (list (cons 'raw raw) (cons 'formatted (fmt-bytes raw))))
        )))

    (catch (e)
      (err (str "BIST-OUCH parse error: " e)))))

;; dissect-bist-ouch: parse BIST-OUCH from bytevector
;; Returns (ok fields-alist) or (err message)