;; packet-btmcap.c
;; Routines for Bluetooth MCAP dissection
;; https://www.bluetooth.org/Technical/Specifications/adopted.htm
;;
;; Copyright 2013, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btmcap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btmcap.c

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
(def (dissect-btmcap buffer)
  "Bluetooth MCAP Protocol"
  (try
    (let* (
           (mdep-id (unwrap (read-u8 buffer 3)))
           (configuration (unwrap (read-u8 buffer 4)))
           (timestamp-update-information (unwrap (read-u8 buffer 7)))
           (bluetooth-clock-access-resolution (unwrap (read-u8 buffer 35)))
           (bluetooth-clock-sync-time (unwrap (read-u32be buffer 42)))
           (timestamp-sync-time (unwrap (read-u64be buffer 46)))
           (mdl-id (unwrap (read-u16be buffer 56)))
           (response-parameters (unwrap (slice buffer 58 1)))
           )

      (ok (list
        (cons 'mdep-id (list (cons 'raw mdep-id) (cons 'formatted (fmt-hex mdep-id))))
        (cons 'configuration (list (cons 'raw configuration) (cons 'formatted (fmt-hex configuration))))
        (cons 'timestamp-update-information (list (cons 'raw timestamp-update-information) (cons 'formatted (number->string timestamp-update-information))))
        (cons 'bluetooth-clock-access-resolution (list (cons 'raw bluetooth-clock-access-resolution) (cons 'formatted (number->string bluetooth-clock-access-resolution))))
        (cons 'bluetooth-clock-sync-time (list (cons 'raw bluetooth-clock-sync-time) (cons 'formatted (number->string bluetooth-clock-sync-time))))
        (cons 'timestamp-sync-time (list (cons 'raw timestamp-sync-time) (cons 'formatted (number->string timestamp-sync-time))))
        (cons 'mdl-id (list (cons 'raw mdl-id) (cons 'formatted (fmt-hex mdl-id))))
        (cons 'response-parameters (list (cons 'raw response-parameters) (cons 'formatted (fmt-bytes response-parameters))))
        )))

    (catch (e)
      (err (str "BTMCAP parse error: " e)))))

;; dissect-btmcap: parse BTMCAP from bytevector
;; Returns (ok fields-alist) or (err message)