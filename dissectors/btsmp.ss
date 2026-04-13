;; packet-btsmp.c
;; Routines for Bluetooth Security Manager Protocol dissection
;;
;; Copyright 2012, Allan M. Madsen <allan.m@madsen.dk>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btsmp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btsmp.c

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
(def (dissect-btsmp buffer)
  "Bluetooth Security Manager Protocol"
  (try
    (let* (
           (max-enc-key-size (unwrap (read-u8 buffer 0)))
           (cfm-value (unwrap (slice buffer 0 16)))
           (long-term-key (unwrap (slice buffer 32 16)))
           (ediv (unwrap (read-u16be buffer 48)))
           (random (unwrap (slice buffer 50 8)))
           (id-resolving-key (unwrap (slice buffer 58 16)))
           (signature-key (unwrap (slice buffer 75 16)))
           (public-key-x (unwrap (slice buffer 91 32)))
           (public-key-y (unwrap (slice buffer 123 32)))
           (dhkey-check (unwrap (slice buffer 155 16)))
           )

      (ok (list
        (cons 'max-enc-key-size (list (cons 'raw max-enc-key-size) (cons 'formatted (number->string max-enc-key-size))))
        (cons 'cfm-value (list (cons 'raw cfm-value) (cons 'formatted (fmt-bytes cfm-value))))
        (cons 'long-term-key (list (cons 'raw long-term-key) (cons 'formatted (fmt-bytes long-term-key))))
        (cons 'ediv (list (cons 'raw ediv) (cons 'formatted (fmt-hex ediv))))
        (cons 'random (list (cons 'raw random) (cons 'formatted (fmt-bytes random))))
        (cons 'id-resolving-key (list (cons 'raw id-resolving-key) (cons 'formatted (fmt-bytes id-resolving-key))))
        (cons 'signature-key (list (cons 'raw signature-key) (cons 'formatted (fmt-bytes signature-key))))
        (cons 'public-key-x (list (cons 'raw public-key-x) (cons 'formatted (fmt-bytes public-key-x))))
        (cons 'public-key-y (list (cons 'raw public-key-y) (cons 'formatted (fmt-bytes public-key-y))))
        (cons 'dhkey-check (list (cons 'raw dhkey-check) (cons 'formatted (fmt-bytes dhkey-check))))
        )))

    (catch (e)
      (err (str "BTSMP parse error: " e)))))

;; dissect-btsmp: parse BTSMP from bytevector
;; Returns (ok fields-alist) or (err message)