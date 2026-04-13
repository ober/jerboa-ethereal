;; packet-isobus.c
;; Routines for ISObus dissection (Based on CANOpen Dissector)
;; Copyright 2016, Jeroen Sack <jeroen@jeroensack.nl>
;; ISO 11783
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/isobus.ss
;; Auto-generated from wireshark/epan/dissectors/packet-isobus.c

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
(def (dissect-isobus buffer)
  "ISObus"
  (try
    (let* (
           (payload (unwrap (slice buffer 0 1)))
           (ack-response (unwrap (slice buffer 0 8)))
           (datetime-response (unwrap (slice buffer 0 8)))
           (ac-name-id-number (unwrap (read-u64be buffer 0)))
           (ac-name-manufacturer (unwrap (read-u64be buffer 0)))
           (ac-name-ecu-instance (unwrap (read-u64be buffer 0)))
           (ac-name-function-instance (unwrap (read-u64be buffer 0)))
           (ac-name-function (unwrap (read-u64be buffer 0)))
           (ac-name-reserved (unwrap (read-u64be buffer 0)))
           (ac-name-vehicle-system (unwrap (read-u64be buffer 0)))
           (ac-name-vehicle-system-instance (unwrap (read-u64be buffer 0)))
           (ac-name-industry-group (unwrap (read-u64be buffer 0)))
           (ac-name-arbitrary-address-capable (unwrap (read-u64be buffer 0)))
           (ac-name (unwrap (slice buffer 0 8)))
           (group-extension (unwrap (read-u32be buffer 0)))
           (data-page (unwrap (read-u32be buffer 0)))
           (ext-data-page (unwrap (read-u32be buffer 0)))
           (priority (unwrap (read-u32be buffer 0)))
           (can-id (unwrap (read-u32be buffer 0)))
           (ack-exended-identifier (unwrap (read-u24be buffer 1)))
           (ack-group-function-value (unwrap (read-u8 buffer 1)))
           (datetime-minute (unwrap (read-u8 buffer 1)))
           (datetime-hour (unwrap (read-u8 buffer 2)))
           (datetime-month (unwrap (read-u8 buffer 3)))
           (ack-address (unwrap (read-u8 buffer 4)))
           )

      (ok (list
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'ack-response (list (cons 'raw ack-response) (cons 'formatted (fmt-bytes ack-response))))
        (cons 'datetime-response (list (cons 'raw datetime-response) (cons 'formatted (fmt-bytes datetime-response))))
        (cons 'ac-name-id-number (list (cons 'raw ac-name-id-number) (cons 'formatted (number->string ac-name-id-number))))
        (cons 'ac-name-manufacturer (list (cons 'raw ac-name-manufacturer) (cons 'formatted (number->string ac-name-manufacturer))))
        (cons 'ac-name-ecu-instance (list (cons 'raw ac-name-ecu-instance) (cons 'formatted (number->string ac-name-ecu-instance))))
        (cons 'ac-name-function-instance (list (cons 'raw ac-name-function-instance) (cons 'formatted (number->string ac-name-function-instance))))
        (cons 'ac-name-function (list (cons 'raw ac-name-function) (cons 'formatted (number->string ac-name-function))))
        (cons 'ac-name-reserved (list (cons 'raw ac-name-reserved) (cons 'formatted (fmt-hex ac-name-reserved))))
        (cons 'ac-name-vehicle-system (list (cons 'raw ac-name-vehicle-system) (cons 'formatted (number->string ac-name-vehicle-system))))
        (cons 'ac-name-vehicle-system-instance (list (cons 'raw ac-name-vehicle-system-instance) (cons 'formatted (number->string ac-name-vehicle-system-instance))))
        (cons 'ac-name-industry-group (list (cons 'raw ac-name-industry-group) (cons 'formatted (number->string ac-name-industry-group))))
        (cons 'ac-name-arbitrary-address-capable (list (cons 'raw ac-name-arbitrary-address-capable) (cons 'formatted (number->string ac-name-arbitrary-address-capable))))
        (cons 'ac-name (list (cons 'raw ac-name) (cons 'formatted (fmt-bytes ac-name))))
        (cons 'group-extension (list (cons 'raw group-extension) (cons 'formatted (number->string group-extension))))
        (cons 'data-page (list (cons 'raw data-page) (cons 'formatted (fmt-hex data-page))))
        (cons 'ext-data-page (list (cons 'raw ext-data-page) (cons 'formatted (fmt-hex ext-data-page))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (fmt-hex priority))))
        (cons 'can-id (list (cons 'raw can-id) (cons 'formatted (fmt-hex can-id))))
        (cons 'ack-exended-identifier (list (cons 'raw ack-exended-identifier) (cons 'formatted (number->string ack-exended-identifier))))
        (cons 'ack-group-function-value (list (cons 'raw ack-group-function-value) (cons 'formatted (number->string ack-group-function-value))))
        (cons 'datetime-minute (list (cons 'raw datetime-minute) (cons 'formatted (number->string datetime-minute))))
        (cons 'datetime-hour (list (cons 'raw datetime-hour) (cons 'formatted (number->string datetime-hour))))
        (cons 'datetime-month (list (cons 'raw datetime-month) (cons 'formatted (number->string datetime-month))))
        (cons 'ack-address (list (cons 'raw ack-address) (cons 'formatted (number->string ack-address))))
        )))

    (catch (e)
      (err (str "ISOBUS parse error: " e)))))

;; dissect-isobus: parse ISOBUS from bytevector
;; Returns (ok fields-alist) or (err message)