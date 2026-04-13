;; packet-zvt.c
;; Routines for ZVT dissection
;; Copyright 2014-2015, Martin Kaiser <martin@kaiser.cx>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/zvt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zvt.c

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
(def (dissect-zvt buffer)
  "ZVT Kassenschnittstelle"
  (try
    (let* (
           (permitted-cmd (unwrap (read-u16be buffer 0)))
           (receipt-parameter (unwrap (read-u8 buffer 0)))
           (receipt-parameter-positive-customer (extract-bits receipt-parameter 0x80 7))
           (receipt-parameter-negative-customer (extract-bits receipt-parameter 0x40 6))
           (receipt-parameter-positive-merchant (extract-bits receipt-parameter 0x20 5))
           (receipt-parameter-negative-merchant (extract-bits receipt-parameter 0x10 4))
           (receipt-parameter-customer-before-merchant (extract-bits receipt-parameter 0x8 3))
           (receipt-parameter-print-short-receipt (extract-bits receipt-parameter 0x4 2))
           (receipt-parameter-no-product-data (extract-bits receipt-parameter 0x2 1))
           (receipt-parameter-ecr-as-printer (extract-bits receipt-parameter 0x1 0))
           (characters-per-line (unwrap (slice buffer 0 1)))
           (receipt-info (unwrap (read-u8 buffer 0)))
           (receipt-info-positive (extract-bits receipt-info 0x1 0))
           (receipt-info-signature (extract-bits receipt-info 0x2 1))
           (receipt-info-negative (extract-bits receipt-info 0x4 2))
           (receipt-info-printing (extract-bits receipt-info 0x80 7))
           (terminal-id (unwrap (slice buffer 0 4)))
           (amount (unwrap (slice buffer 0 6)))
           (time (unwrap (slice buffer 0 3)))
           (date (unwrap (slice buffer 0 2)))
           (expiry-date (unwrap (slice buffer 0 2)))
           (trace-number (unwrap (slice buffer 0 3)))
           (card-number (unwrap (slice buffer 0 1)))
           (card-name (unwrap (slice buffer 0 1)))
           (additional-data (unwrap (slice buffer 0 1)))
           (int-status (unwrap (read-u8 buffer 0)))
           (reg-cfg (unwrap (read-u8 buffer 3)))
           (res-code (unwrap (read-u8 buffer 3)))
           (pwd (unwrap (slice buffer 4 3)))
           (ccrc (unwrap (read-u8 buffer 7)))
           (aprc (unwrap (read-u8 buffer 7)))
           (len (unwrap (read-u16be buffer 9)))
           (data (unwrap (slice buffer 9 1)))
           (crc (unwrap (read-u16be buffer 9)))
           (text-lines-line (unwrap (slice buffer 11 1)))
           )

      (ok (list
        (cons 'permitted-cmd (list (cons 'raw permitted-cmd) (cons 'formatted (fmt-hex permitted-cmd))))
        (cons 'receipt-parameter (list (cons 'raw receipt-parameter) (cons 'formatted (fmt-hex receipt-parameter))))
        (cons 'receipt-parameter-positive-customer (list (cons 'raw receipt-parameter-positive-customer) (cons 'formatted (if (= receipt-parameter-positive-customer 0) "Not set" "Set"))))
        (cons 'receipt-parameter-negative-customer (list (cons 'raw receipt-parameter-negative-customer) (cons 'formatted (if (= receipt-parameter-negative-customer 0) "Not set" "Set"))))
        (cons 'receipt-parameter-positive-merchant (list (cons 'raw receipt-parameter-positive-merchant) (cons 'formatted (if (= receipt-parameter-positive-merchant 0) "Not set" "Set"))))
        (cons 'receipt-parameter-negative-merchant (list (cons 'raw receipt-parameter-negative-merchant) (cons 'formatted (if (= receipt-parameter-negative-merchant 0) "Not set" "Set"))))
        (cons 'receipt-parameter-customer-before-merchant (list (cons 'raw receipt-parameter-customer-before-merchant) (cons 'formatted (if (= receipt-parameter-customer-before-merchant 0) "Not set" "Set"))))
        (cons 'receipt-parameter-print-short-receipt (list (cons 'raw receipt-parameter-print-short-receipt) (cons 'formatted (if (= receipt-parameter-print-short-receipt 0) "Not set" "Set"))))
        (cons 'receipt-parameter-no-product-data (list (cons 'raw receipt-parameter-no-product-data) (cons 'formatted (if (= receipt-parameter-no-product-data 0) "Not set" "Set"))))
        (cons 'receipt-parameter-ecr-as-printer (list (cons 'raw receipt-parameter-ecr-as-printer) (cons 'formatted (if (= receipt-parameter-ecr-as-printer 0) "Not set" "Set"))))
        (cons 'characters-per-line (list (cons 'raw characters-per-line) (cons 'formatted (utf8->string characters-per-line))))
        (cons 'receipt-info (list (cons 'raw receipt-info) (cons 'formatted (fmt-hex receipt-info))))
        (cons 'receipt-info-positive (list (cons 'raw receipt-info-positive) (cons 'formatted (if (= receipt-info-positive 0) "Not set" "Set"))))
        (cons 'receipt-info-signature (list (cons 'raw receipt-info-signature) (cons 'formatted (if (= receipt-info-signature 0) "Not set" "Set"))))
        (cons 'receipt-info-negative (list (cons 'raw receipt-info-negative) (cons 'formatted (if (= receipt-info-negative 0) "Not set" "Set"))))
        (cons 'receipt-info-printing (list (cons 'raw receipt-info-printing) (cons 'formatted (if (= receipt-info-printing 0) "Not set" "Set"))))
        (cons 'terminal-id (list (cons 'raw terminal-id) (cons 'formatted (utf8->string terminal-id))))
        (cons 'amount (list (cons 'raw amount) (cons 'formatted (number->string amount))))
        (cons 'time (list (cons 'raw time) (cons 'formatted (utf8->string time))))
        (cons 'date (list (cons 'raw date) (cons 'formatted (utf8->string date))))
        (cons 'expiry-date (list (cons 'raw expiry-date) (cons 'formatted (utf8->string expiry-date))))
        (cons 'trace-number (list (cons 'raw trace-number) (cons 'formatted (utf8->string trace-number))))
        (cons 'card-number (list (cons 'raw card-number) (cons 'formatted (utf8->string card-number))))
        (cons 'card-name (list (cons 'raw card-name) (cons 'formatted (utf8->string card-name))))
        (cons 'additional-data (list (cons 'raw additional-data) (cons 'formatted (utf8->string additional-data))))
        (cons 'int-status (list (cons 'raw int-status) (cons 'formatted (fmt-hex int-status))))
        (cons 'reg-cfg (list (cons 'raw reg-cfg) (cons 'formatted (fmt-hex reg-cfg))))
        (cons 'res-code (list (cons 'raw res-code) (cons 'formatted (fmt-hex res-code))))
        (cons 'pwd (list (cons 'raw pwd) (cons 'formatted (fmt-bytes pwd))))
        (cons 'ccrc (list (cons 'raw ccrc) (cons 'formatted (fmt-hex ccrc))))
        (cons 'aprc (list (cons 'raw aprc) (cons 'formatted (fmt-hex aprc))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'crc (list (cons 'raw crc) (cons 'formatted (fmt-hex crc))))
        (cons 'text-lines-line (list (cons 'raw text-lines-line) (cons 'formatted (utf8->string text-lines-line))))
        )))

    (catch (e)
      (err (str "ZVT parse error: " e)))))

;; dissect-zvt: parse ZVT from bytevector
;; Returns (ok fields-alist) or (err message)