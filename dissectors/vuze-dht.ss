;; packet-vuze-dht.c
;; Routines for Vuze-DHT dissection
;; Copyright 2011, Xiao Xiangquan <xiaoxiangquan@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vuze-dht.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vuze_dht.c

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
(def (dissect-vuze-dht buffer)
  "Vuze DHT Protocol"
  (try
    (let* (
           (dht-address-len (unwrap (read-u8 buffer 0)))
           (dht-address-v4 (unwrap (read-u32be buffer 0)))
           (dht-address-v6 (unwrap (slice buffer 0 16)))
           (dht-address-port (unwrap (read-u16be buffer 0)))
           (dht-proto-ver (unwrap (read-u8 buffer 0)))
           (dht-key-len (unwrap (read-u8 buffer 0)))
           (dht-key-data (unwrap (slice buffer 0 1)))
           (dht-value-ver (unwrap (read-u32be buffer 0)))
           (dht-values-num (unwrap (read-u32be buffer 0)))
           (dht-values-total (unwrap (read-u32be buffer 0)))
           (dht-reads-per-min (unwrap (read-u32be buffer 0)))
           (dht-diversification-type (unwrap (read-u8 buffer 0)))
           (dht-value-created (unwrap (read-u64be buffer 0)))
           (dht-value-bytes-count (unwrap (read-u16be buffer 0)))
           (dht-value-bytes (unwrap (slice buffer 0 1)))
           (dht-value-flags (unwrap (read-u8 buffer 0)))
           (dht-value-life-hours (unwrap (read-u8 buffer 0)))
           (dht-value-replication-factor (unwrap (read-u8 buffer 0)))
           (dht-values-count (unwrap (read-u16be buffer 0)))
           (dht-network-coordinate-size (unwrap (read-u8 buffer 0)))
           (dht-network-coordinate-x (unwrap (read-u32be buffer 0)))
           (dht-network-coordinate-y (unwrap (read-u32be buffer 0)))
           (dht-network-coordinate-height (unwrap (read-u32be buffer 0)))
           (dht-network-coordinate-error (unwrap (read-u32be buffer 0)))
           (dht-network-coordinate-data (unwrap (slice buffer 0 1)))
           (dht-network-coordinates-count (unwrap (read-u8 buffer 0)))
           (dht-connection-id (unwrap (read-u64be buffer 0)))
           (dht-transaction-id (unwrap (read-u32be buffer 0)))
           (dht-vendor-id (unwrap (read-u8 buffer 0)))
           (dht-network-id (unwrap (read-u32be buffer 0)))
           (dht-local-proto-ver (unwrap (read-u8 buffer 0)))
           (dht-instance-id (unwrap (read-u32be buffer 0)))
           (dht-time (unwrap (read-u64be buffer 0)))
           (dht-spoof-id (unwrap (read-u32be buffer 0)))
           (dht-keys-count (unwrap (read-u8 buffer 0)))
           (dht-value-groups-count (unwrap (read-u8 buffer 0)))
           (dht-diversifications-len (unwrap (read-u8 buffer 0)))
           (dht-diversifications (unwrap (slice buffer 0 1)))
           (dht-id-len (unwrap (read-u8 buffer 0)))
           (dht-id (unwrap (slice buffer 0 1)))
           (dht-node-status (unwrap (read-u32be buffer 0)))
           (dht-size (unwrap (read-u32be buffer 0)))
           (dht-contacts-count (unwrap (read-u16be buffer 0)))
           (dht-max-values (unwrap (read-u8 buffer 0)))
           (dht-key-block-request-len (unwrap (read-u8 buffer 0)))
           (dht-key-block-request (unwrap (slice buffer 0 1)))
           (dht-signature-len (unwrap (read-u16be buffer 0)))
           (dht-signature (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'dht-address-len (list (cons 'raw dht-address-len) (cons 'formatted (number->string dht-address-len))))
        (cons 'dht-address-v4 (list (cons 'raw dht-address-v4) (cons 'formatted (fmt-ipv4 dht-address-v4))))
        (cons 'dht-address-v6 (list (cons 'raw dht-address-v6) (cons 'formatted (fmt-ipv6-address dht-address-v6))))
        (cons 'dht-address-port (list (cons 'raw dht-address-port) (cons 'formatted (number->string dht-address-port))))
        (cons 'dht-proto-ver (list (cons 'raw dht-proto-ver) (cons 'formatted (number->string dht-proto-ver))))
        (cons 'dht-key-len (list (cons 'raw dht-key-len) (cons 'formatted (number->string dht-key-len))))
        (cons 'dht-key-data (list (cons 'raw dht-key-data) (cons 'formatted (fmt-bytes dht-key-data))))
        (cons 'dht-value-ver (list (cons 'raw dht-value-ver) (cons 'formatted (number->string dht-value-ver))))
        (cons 'dht-values-num (list (cons 'raw dht-values-num) (cons 'formatted (number->string dht-values-num))))
        (cons 'dht-values-total (list (cons 'raw dht-values-total) (cons 'formatted (number->string dht-values-total))))
        (cons 'dht-reads-per-min (list (cons 'raw dht-reads-per-min) (cons 'formatted (number->string dht-reads-per-min))))
        (cons 'dht-diversification-type (list (cons 'raw dht-diversification-type) (cons 'formatted (number->string dht-diversification-type))))
        (cons 'dht-value-created (list (cons 'raw dht-value-created) (cons 'formatted (number->string dht-value-created))))
        (cons 'dht-value-bytes-count (list (cons 'raw dht-value-bytes-count) (cons 'formatted (number->string dht-value-bytes-count))))
        (cons 'dht-value-bytes (list (cons 'raw dht-value-bytes) (cons 'formatted (fmt-bytes dht-value-bytes))))
        (cons 'dht-value-flags (list (cons 'raw dht-value-flags) (cons 'formatted (number->string dht-value-flags))))
        (cons 'dht-value-life-hours (list (cons 'raw dht-value-life-hours) (cons 'formatted (number->string dht-value-life-hours))))
        (cons 'dht-value-replication-factor (list (cons 'raw dht-value-replication-factor) (cons 'formatted (number->string dht-value-replication-factor))))
        (cons 'dht-values-count (list (cons 'raw dht-values-count) (cons 'formatted (number->string dht-values-count))))
        (cons 'dht-network-coordinate-size (list (cons 'raw dht-network-coordinate-size) (cons 'formatted (number->string dht-network-coordinate-size))))
        (cons 'dht-network-coordinate-x (list (cons 'raw dht-network-coordinate-x) (cons 'formatted (number->string dht-network-coordinate-x))))
        (cons 'dht-network-coordinate-y (list (cons 'raw dht-network-coordinate-y) (cons 'formatted (number->string dht-network-coordinate-y))))
        (cons 'dht-network-coordinate-height (list (cons 'raw dht-network-coordinate-height) (cons 'formatted (number->string dht-network-coordinate-height))))
        (cons 'dht-network-coordinate-error (list (cons 'raw dht-network-coordinate-error) (cons 'formatted (number->string dht-network-coordinate-error))))
        (cons 'dht-network-coordinate-data (list (cons 'raw dht-network-coordinate-data) (cons 'formatted (fmt-bytes dht-network-coordinate-data))))
        (cons 'dht-network-coordinates-count (list (cons 'raw dht-network-coordinates-count) (cons 'formatted (number->string dht-network-coordinates-count))))
        (cons 'dht-connection-id (list (cons 'raw dht-connection-id) (cons 'formatted (number->string dht-connection-id))))
        (cons 'dht-transaction-id (list (cons 'raw dht-transaction-id) (cons 'formatted (number->string dht-transaction-id))))
        (cons 'dht-vendor-id (list (cons 'raw dht-vendor-id) (cons 'formatted (number->string dht-vendor-id))))
        (cons 'dht-network-id (list (cons 'raw dht-network-id) (cons 'formatted (number->string dht-network-id))))
        (cons 'dht-local-proto-ver (list (cons 'raw dht-local-proto-ver) (cons 'formatted (number->string dht-local-proto-ver))))
        (cons 'dht-instance-id (list (cons 'raw dht-instance-id) (cons 'formatted (number->string dht-instance-id))))
        (cons 'dht-time (list (cons 'raw dht-time) (cons 'formatted (number->string dht-time))))
        (cons 'dht-spoof-id (list (cons 'raw dht-spoof-id) (cons 'formatted (number->string dht-spoof-id))))
        (cons 'dht-keys-count (list (cons 'raw dht-keys-count) (cons 'formatted (number->string dht-keys-count))))
        (cons 'dht-value-groups-count (list (cons 'raw dht-value-groups-count) (cons 'formatted (number->string dht-value-groups-count))))
        (cons 'dht-diversifications-len (list (cons 'raw dht-diversifications-len) (cons 'formatted (number->string dht-diversifications-len))))
        (cons 'dht-diversifications (list (cons 'raw dht-diversifications) (cons 'formatted (fmt-bytes dht-diversifications))))
        (cons 'dht-id-len (list (cons 'raw dht-id-len) (cons 'formatted (number->string dht-id-len))))
        (cons 'dht-id (list (cons 'raw dht-id) (cons 'formatted (fmt-bytes dht-id))))
        (cons 'dht-node-status (list (cons 'raw dht-node-status) (cons 'formatted (fmt-hex dht-node-status))))
        (cons 'dht-size (list (cons 'raw dht-size) (cons 'formatted (number->string dht-size))))
        (cons 'dht-contacts-count (list (cons 'raw dht-contacts-count) (cons 'formatted (number->string dht-contacts-count))))
        (cons 'dht-max-values (list (cons 'raw dht-max-values) (cons 'formatted (number->string dht-max-values))))
        (cons 'dht-key-block-request-len (list (cons 'raw dht-key-block-request-len) (cons 'formatted (number->string dht-key-block-request-len))))
        (cons 'dht-key-block-request (list (cons 'raw dht-key-block-request) (cons 'formatted (fmt-bytes dht-key-block-request))))
        (cons 'dht-signature-len (list (cons 'raw dht-signature-len) (cons 'formatted (number->string dht-signature-len))))
        (cons 'dht-signature (list (cons 'raw dht-signature) (cons 'formatted (fmt-bytes dht-signature))))
        )))

    (catch (e)
      (err (str "VUZE-DHT parse error: " e)))))

;; dissect-vuze-dht: parse VUZE-DHT from bytevector
;; Returns (ok fields-alist) or (err message)