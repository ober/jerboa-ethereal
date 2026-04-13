;; packet-nordic_ble.c
;; Routines for nRF Sniffer for Bluetooth LE dissection
;;
;; Copyright (c) 2016-2018 Nordic Semiconductor.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nordic-ble.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nordic_ble.c

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
(def (dissect-nordic-ble buffer)
  "nRF Sniffer for Bluetooth LE"
  (try
    (let* (
           (ble-board-id (unwrap (read-u8 buffer 0)))
           (ble-legacy-marker (unwrap (read-u16be buffer 0)))
           (ble-header-length (unwrap (read-u8 buffer 1)))
           (ble-payload-length (unwrap (read-u16be buffer 3)))
           (ble-flags (unwrap (read-u8 buffer 5)))
           (ble-crcok (unwrap (read-u8 buffer 5)))
           (ble-direction (unwrap (read-u8 buffer 5)))
           (ble-encrypted (unwrap (read-u8 buffer 5)))
           (ble-micok (unwrap (read-u8 buffer 5)))
           (ble-mic-not-relevant (unwrap (read-u8 buffer 5)))
           (ble-flag-reserved1 (unwrap (read-u8 buffer 5)))
           (ble-flag-reserved2 (unwrap (read-u8 buffer 5)))
           (ble-address-resolved (unwrap (read-u8 buffer 5)))
           (ble-flag-reserved7 (unwrap (read-u8 buffer 5)))
           (ble-packet-counter (unwrap (read-u16be buffer 13)))
           (ble-protover (unwrap (read-u8 buffer 18)))
           (ble-packet-id (unwrap (read-u8 buffer 19)))
           (ble-packet-length (unwrap (read-u8 buffer 20)))
           (ble-channel (unwrap (read-u8 buffer 21)))
           (ble-event-counter (unwrap (read-u16be buffer 23)))
           )

      (ok (list
        (cons 'ble-board-id (list (cons 'raw ble-board-id) (cons 'formatted (number->string ble-board-id))))
        (cons 'ble-legacy-marker (list (cons 'raw ble-legacy-marker) (cons 'formatted (fmt-hex ble-legacy-marker))))
        (cons 'ble-header-length (list (cons 'raw ble-header-length) (cons 'formatted (number->string ble-header-length))))
        (cons 'ble-payload-length (list (cons 'raw ble-payload-length) (cons 'formatted (number->string ble-payload-length))))
        (cons 'ble-flags (list (cons 'raw ble-flags) (cons 'formatted (fmt-hex ble-flags))))
        (cons 'ble-crcok (list (cons 'raw ble-crcok) (cons 'formatted (if (= ble-crcok 0) "False" "True"))))
        (cons 'ble-direction (list (cons 'raw ble-direction) (cons 'formatted (if (= ble-direction 0) "Peripheral -> Central" "Central -> Peripheral"))))
        (cons 'ble-encrypted (list (cons 'raw ble-encrypted) (cons 'formatted (if (= ble-encrypted 0) "False" "True"))))
        (cons 'ble-micok (list (cons 'raw ble-micok) (cons 'formatted (if (= ble-micok 0) "False" "True"))))
        (cons 'ble-mic-not-relevant (list (cons 'raw ble-mic-not-relevant) (cons 'formatted (number->string ble-mic-not-relevant))))
        (cons 'ble-flag-reserved1 (list (cons 'raw ble-flag-reserved1) (cons 'formatted (number->string ble-flag-reserved1))))
        (cons 'ble-flag-reserved2 (list (cons 'raw ble-flag-reserved2) (cons 'formatted (number->string ble-flag-reserved2))))
        (cons 'ble-address-resolved (list (cons 'raw ble-address-resolved) (cons 'formatted (if (= ble-address-resolved 0) "False" "True"))))
        (cons 'ble-flag-reserved7 (list (cons 'raw ble-flag-reserved7) (cons 'formatted (number->string ble-flag-reserved7))))
        (cons 'ble-packet-counter (list (cons 'raw ble-packet-counter) (cons 'formatted (number->string ble-packet-counter))))
        (cons 'ble-protover (list (cons 'raw ble-protover) (cons 'formatted (number->string ble-protover))))
        (cons 'ble-packet-id (list (cons 'raw ble-packet-id) (cons 'formatted (number->string ble-packet-id))))
        (cons 'ble-packet-length (list (cons 'raw ble-packet-length) (cons 'formatted (number->string ble-packet-length))))
        (cons 'ble-channel (list (cons 'raw ble-channel) (cons 'formatted (number->string ble-channel))))
        (cons 'ble-event-counter (list (cons 'raw ble-event-counter) (cons 'formatted (number->string ble-event-counter))))
        )))

    (catch (e)
      (err (str "NORDIC-BLE parse error: " e)))))

;; dissect-nordic-ble: parse NORDIC-BLE from bytevector
;; Returns (ok fields-alist) or (err message)