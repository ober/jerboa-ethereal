;; packet-bthcrp.c
;; Routines for Bluetooth HCRP dissection
;;
;; Copyright 2013, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bthcrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bthcrp.c

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
(def (dissect-bthcrp buffer)
  "Bluetooth HCRP Profile"
  (try
    (let* (
           (control-transaction-id (unwrap (read-u16be buffer 2)))
           (control-parameter-length (unwrap (read-u16be buffer 4)))
           (control-client-credit-granted (unwrap (read-u32be buffer 8)))
           (control-server-credit-granted (unwrap (read-u32be buffer 12)))
           (control-client-credit-return (unwrap (read-u32be buffer 16)))
           (control-server-credit-return (unwrap (read-u32be buffer 20)))
           (control-client-credit-query (unwrap (read-u32be buffer 24)))
           (control-server-credit-query (unwrap (read-u32be buffer 28)))
           (control-status-reserved-76 (unwrap (read-u8 buffer 32)))
           (control-status-paper-empty (unwrap (read-u8 buffer 32)))
           (control-status-select (unwrap (read-u8 buffer 32)))
           (control-status-not-error (unwrap (read-u8 buffer 32)))
           (control-status-reserved-20 (unwrap (read-u8 buffer 32)))
           (control-start-byte (unwrap (read-u16be buffer 33)))
           (control-number-of-bytes (unwrap (read-u16be buffer 35)))
           (control-1284-id (unwrap (slice buffer 37 1)))
           (control-callback-timeout (unwrap (read-u32be buffer 50)))
           (control-timeout (unwrap (read-u32be buffer 54)))
           (callback-context-id (unwrap (read-u32be buffer 60)))
           )

      (ok (list
        (cons 'control-transaction-id (list (cons 'raw control-transaction-id) (cons 'formatted (fmt-hex control-transaction-id))))
        (cons 'control-parameter-length (list (cons 'raw control-parameter-length) (cons 'formatted (fmt-hex control-parameter-length))))
        (cons 'control-client-credit-granted (list (cons 'raw control-client-credit-granted) (cons 'formatted (number->string control-client-credit-granted))))
        (cons 'control-server-credit-granted (list (cons 'raw control-server-credit-granted) (cons 'formatted (number->string control-server-credit-granted))))
        (cons 'control-client-credit-return (list (cons 'raw control-client-credit-return) (cons 'formatted (number->string control-client-credit-return))))
        (cons 'control-server-credit-return (list (cons 'raw control-server-credit-return) (cons 'formatted (number->string control-server-credit-return))))
        (cons 'control-client-credit-query (list (cons 'raw control-client-credit-query) (cons 'formatted (number->string control-client-credit-query))))
        (cons 'control-server-credit-query (list (cons 'raw control-server-credit-query) (cons 'formatted (number->string control-server-credit-query))))
        (cons 'control-status-reserved-76 (list (cons 'raw control-status-reserved-76) (cons 'formatted (number->string control-status-reserved-76))))
        (cons 'control-status-paper-empty (list (cons 'raw control-status-paper-empty) (cons 'formatted (number->string control-status-paper-empty))))
        (cons 'control-status-select (list (cons 'raw control-status-select) (cons 'formatted (number->string control-status-select))))
        (cons 'control-status-not-error (list (cons 'raw control-status-not-error) (cons 'formatted (number->string control-status-not-error))))
        (cons 'control-status-reserved-20 (list (cons 'raw control-status-reserved-20) (cons 'formatted (fmt-hex control-status-reserved-20))))
        (cons 'control-start-byte (list (cons 'raw control-start-byte) (cons 'formatted (number->string control-start-byte))))
        (cons 'control-number-of-bytes (list (cons 'raw control-number-of-bytes) (cons 'formatted (number->string control-number-of-bytes))))
        (cons 'control-1284-id (list (cons 'raw control-1284-id) (cons 'formatted (utf8->string control-1284-id))))
        (cons 'control-callback-timeout (list (cons 'raw control-callback-timeout) (cons 'formatted (number->string control-callback-timeout))))
        (cons 'control-timeout (list (cons 'raw control-timeout) (cons 'formatted (number->string control-timeout))))
        (cons 'callback-context-id (list (cons 'raw callback-context-id) (cons 'formatted (fmt-hex callback-context-id))))
        )))

    (catch (e)
      (err (str "BTHCRP parse error: " e)))))

;; dissect-bthcrp: parse BTHCRP from bytevector
;; Returns (ok fields-alist) or (err message)