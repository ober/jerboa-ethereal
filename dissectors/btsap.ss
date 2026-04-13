;; packet-btsap.c
;; Routines for Bluetooth SAP dissection
;;
;; Copyright 2012, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btsap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btsap.c

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
(def (dissect-btsap buffer)
  "Bluetooth SAP Profile"
  (try
    (let* (
           (parameter-reserved (unwrap (read-u8 buffer 1)))
           (header-number-of-parameters (unwrap (read-u8 buffer 1)))
           (parameter-length (unwrap (read-u16be buffer 2)))
           (header-reserved (unwrap (read-u16be buffer 2)))
           (parameter-max-msg-size (unwrap (read-u16be buffer 4)))
           (parameter-card-reader-status-card-powered (unwrap (read-u8 buffer 4)))
           (parameter-card-reader-status-card-present (unwrap (read-u8 buffer 4)))
           (parameter-card-reader-status-card-reader-present-lower (unwrap (read-u8 buffer 4)))
           (parameter-card-reader-status-card-reader-present (unwrap (read-u8 buffer 4)))
           (parameter-card-reader-status-card-reader-removable (unwrap (read-u8 buffer 4)))
           (parameter-card-reader-status-card-reader-identity (unwrap (read-u8 buffer 4)))
           (parameter-transport-protocol (unwrap (read-u8 buffer 4)))
           )

      (ok (list
        (cons 'parameter-reserved (list (cons 'raw parameter-reserved) (cons 'formatted (fmt-hex parameter-reserved))))
        (cons 'header-number-of-parameters (list (cons 'raw header-number-of-parameters) (cons 'formatted (fmt-hex header-number-of-parameters))))
        (cons 'parameter-length (list (cons 'raw parameter-length) (cons 'formatted (number->string parameter-length))))
        (cons 'header-reserved (list (cons 'raw header-reserved) (cons 'formatted (fmt-hex header-reserved))))
        (cons 'parameter-max-msg-size (list (cons 'raw parameter-max-msg-size) (cons 'formatted (number->string parameter-max-msg-size))))
        (cons 'parameter-card-reader-status-card-powered (list (cons 'raw parameter-card-reader-status-card-powered) (cons 'formatted (number->string parameter-card-reader-status-card-powered))))
        (cons 'parameter-card-reader-status-card-present (list (cons 'raw parameter-card-reader-status-card-present) (cons 'formatted (number->string parameter-card-reader-status-card-present))))
        (cons 'parameter-card-reader-status-card-reader-present-lower (list (cons 'raw parameter-card-reader-status-card-reader-present-lower) (cons 'formatted (number->string parameter-card-reader-status-card-reader-present-lower))))
        (cons 'parameter-card-reader-status-card-reader-present (list (cons 'raw parameter-card-reader-status-card-reader-present) (cons 'formatted (number->string parameter-card-reader-status-card-reader-present))))
        (cons 'parameter-card-reader-status-card-reader-removable (list (cons 'raw parameter-card-reader-status-card-reader-removable) (cons 'formatted (number->string parameter-card-reader-status-card-reader-removable))))
        (cons 'parameter-card-reader-status-card-reader-identity (list (cons 'raw parameter-card-reader-status-card-reader-identity) (cons 'formatted (fmt-hex parameter-card-reader-status-card-reader-identity))))
        (cons 'parameter-transport-protocol (list (cons 'raw parameter-transport-protocol) (cons 'formatted (fmt-hex parameter-transport-protocol))))
        )))

    (catch (e)
      (err (str "BTSAP parse error: " e)))))

;; dissect-btsap: parse BTSAP from bytevector
;; Returns (ok fields-alist) or (err message)