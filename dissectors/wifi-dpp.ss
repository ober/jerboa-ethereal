;; packet-wifi-dpp.c
;;
;; Wi-Fi Device Provisioning Protocol (DPP)
;;
;; Copyright 2017-2020 Richard Sharpe <realrichardsharpe@gmail.com>
;; Copyright 2017-2020 The WiFi Alliance
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wifi-dpp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wifi_dpp.c

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
(def (dissect-wifi-dpp buffer)
  "Wi-Fi Device Provisioning Protocol"
  (try
    (let* (
           (dpp-unknown-anqp-item (unwrap (slice buffer 0 1)))
           (dpp-crypto-suite (unwrap (read-u8 buffer 0)))
           (dpp-tcp-pdu-length (unwrap (read-u32be buffer 0)))
           (dpp-ie-attr-len (unwrap (read-u16be buffer 2)))
           (dpp-init-hash (unwrap (slice buffer 4 1)))
           (dpp-resp-hash (unwrap (slice buffer 4 1)))
           (dpp-key-x (unwrap (slice buffer 4 1)))
           (dpp-trans-id (unwrap (read-u8 buffer 4)))
           (dpp-finite-cyclic-group (unwrap (read-u16be buffer 4)))
           (dpp-capabilities (unwrap (read-u8 buffer 4)))
           (dpp-code-identifier (unwrap (slice buffer 4 1)))
           (dpp-enc-key-attribute (unwrap (slice buffer 4 1)))
           (dpp-primary-wrapped-data (unwrap (slice buffer 4 1)))
           (dpp-connector-attr (unwrap (slice buffer 4 1)))
           (dpp-initiator-nonce (unwrap (slice buffer 4 1)))
           (dpp-operating-class (unwrap (read-u8 buffer 4)))
           (dpp-channel (unwrap (read-u8 buffer 4)))
           (dpp-a-nonce (unwrap (slice buffer 4 1)))
           (dpp-e-prime-id (unwrap (slice buffer 4 1)))
           (dpp-ie-generic (unwrap (slice buffer 4 1)))
           (dpp-tcp-pdu-action-field (unwrap (read-u8 buffer 4)))
           (dpp-tcp-query-req-len (unwrap (read-u16be buffer 20)))
           (dpp-tcp-dialog-token (unwrap (read-u8 buffer 22)))
           (dpp-tcp-status-code (unwrap (read-u16be buffer 23)))
           (dpp-gas-query-resp-frag-id (unwrap (read-u8 buffer 25)))
           (dpp-tcp-comeback-delay (unwrap (read-u16be buffer 26)))
           (dpp-tcp-adv-proto-elt (unwrap (slice buffer 28 3)))
           (dpp-tcp-vendor-specific (unwrap (read-u8 buffer 31)))
           (dpp-tcp-vendor-spec-len (unwrap (read-u8 buffer 32)))
           (dpp-tcp-oui (unwrap (read-u24be buffer 33)))
           (dpp-tcp-config (unwrap (read-u8 buffer 37)))
           (dpp-tcp-query-resp-len (unwrap (read-u16be buffer 38)))
           )

      (ok (list
        (cons 'dpp-unknown-anqp-item (list (cons 'raw dpp-unknown-anqp-item) (cons 'formatted (fmt-bytes dpp-unknown-anqp-item))))
        (cons 'dpp-crypto-suite (list (cons 'raw dpp-crypto-suite) (cons 'formatted (number->string dpp-crypto-suite))))
        (cons 'dpp-tcp-pdu-length (list (cons 'raw dpp-tcp-pdu-length) (cons 'formatted (number->string dpp-tcp-pdu-length))))
        (cons 'dpp-ie-attr-len (list (cons 'raw dpp-ie-attr-len) (cons 'formatted (number->string dpp-ie-attr-len))))
        (cons 'dpp-init-hash (list (cons 'raw dpp-init-hash) (cons 'formatted (fmt-bytes dpp-init-hash))))
        (cons 'dpp-resp-hash (list (cons 'raw dpp-resp-hash) (cons 'formatted (fmt-bytes dpp-resp-hash))))
        (cons 'dpp-key-x (list (cons 'raw dpp-key-x) (cons 'formatted (fmt-bytes dpp-key-x))))
        (cons 'dpp-trans-id (list (cons 'raw dpp-trans-id) (cons 'formatted (number->string dpp-trans-id))))
        (cons 'dpp-finite-cyclic-group (list (cons 'raw dpp-finite-cyclic-group) (cons 'formatted (fmt-hex dpp-finite-cyclic-group))))
        (cons 'dpp-capabilities (list (cons 'raw dpp-capabilities) (cons 'formatted (fmt-hex dpp-capabilities))))
        (cons 'dpp-code-identifier (list (cons 'raw dpp-code-identifier) (cons 'formatted (utf8->string dpp-code-identifier))))
        (cons 'dpp-enc-key-attribute (list (cons 'raw dpp-enc-key-attribute) (cons 'formatted (fmt-bytes dpp-enc-key-attribute))))
        (cons 'dpp-primary-wrapped-data (list (cons 'raw dpp-primary-wrapped-data) (cons 'formatted (fmt-bytes dpp-primary-wrapped-data))))
        (cons 'dpp-connector-attr (list (cons 'raw dpp-connector-attr) (cons 'formatted (fmt-bytes dpp-connector-attr))))
        (cons 'dpp-initiator-nonce (list (cons 'raw dpp-initiator-nonce) (cons 'formatted (fmt-bytes dpp-initiator-nonce))))
        (cons 'dpp-operating-class (list (cons 'raw dpp-operating-class) (cons 'formatted (number->string dpp-operating-class))))
        (cons 'dpp-channel (list (cons 'raw dpp-channel) (cons 'formatted (number->string dpp-channel))))
        (cons 'dpp-a-nonce (list (cons 'raw dpp-a-nonce) (cons 'formatted (fmt-bytes dpp-a-nonce))))
        (cons 'dpp-e-prime-id (list (cons 'raw dpp-e-prime-id) (cons 'formatted (fmt-bytes dpp-e-prime-id))))
        (cons 'dpp-ie-generic (list (cons 'raw dpp-ie-generic) (cons 'formatted (fmt-bytes dpp-ie-generic))))
        (cons 'dpp-tcp-pdu-action-field (list (cons 'raw dpp-tcp-pdu-action-field) (cons 'formatted (fmt-hex dpp-tcp-pdu-action-field))))
        (cons 'dpp-tcp-query-req-len (list (cons 'raw dpp-tcp-query-req-len) (cons 'formatted (number->string dpp-tcp-query-req-len))))
        (cons 'dpp-tcp-dialog-token (list (cons 'raw dpp-tcp-dialog-token) (cons 'formatted (fmt-hex dpp-tcp-dialog-token))))
        (cons 'dpp-tcp-status-code (list (cons 'raw dpp-tcp-status-code) (cons 'formatted (number->string dpp-tcp-status-code))))
        (cons 'dpp-gas-query-resp-frag-id (list (cons 'raw dpp-gas-query-resp-frag-id) (cons 'formatted (number->string dpp-gas-query-resp-frag-id))))
        (cons 'dpp-tcp-comeback-delay (list (cons 'raw dpp-tcp-comeback-delay) (cons 'formatted (number->string dpp-tcp-comeback-delay))))
        (cons 'dpp-tcp-adv-proto-elt (list (cons 'raw dpp-tcp-adv-proto-elt) (cons 'formatted (fmt-bytes dpp-tcp-adv-proto-elt))))
        (cons 'dpp-tcp-vendor-specific (list (cons 'raw dpp-tcp-vendor-specific) (cons 'formatted (fmt-hex dpp-tcp-vendor-specific))))
        (cons 'dpp-tcp-vendor-spec-len (list (cons 'raw dpp-tcp-vendor-spec-len) (cons 'formatted (number->string dpp-tcp-vendor-spec-len))))
        (cons 'dpp-tcp-oui (list (cons 'raw dpp-tcp-oui) (cons 'formatted (number->string dpp-tcp-oui))))
        (cons 'dpp-tcp-config (list (cons 'raw dpp-tcp-config) (cons 'formatted (number->string dpp-tcp-config))))
        (cons 'dpp-tcp-query-resp-len (list (cons 'raw dpp-tcp-query-resp-len) (cons 'formatted (number->string dpp-tcp-query-resp-len))))
        )))

    (catch (e)
      (err (str "WIFI-DPP parse error: " e)))))

;; dissect-wifi-dpp: parse WIFI-DPP from bytevector
;; Returns (ok fields-alist) or (err message)