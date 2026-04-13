;; packet-reload-framing.c
;; Routines for REsource LOcation And Discovery (RELOAD) Framing
;; Author: Stephane Bryant <sbryant@glycon.org>
;; Copyright 2010 Stonyfish Inc.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Please refer to the following specs for protocol detail:
;; - draft-ietf-p2psip-base-15
;; - RFC 6940 (does this incorporate all changes between
;; draft-ietf-p2psip-base-15 and RFC 6940, if any?)
;;

;; jerboa-ethereal/dissectors/reload-framing.ss
;; Auto-generated from wireshark/epan/dissectors/packet-reload_framing.c
;; RFC 6940

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
(def (dissect-reload-framing buffer)
  "REsource LOcation And Discovery Framing"
  (try
    (let* (
           (framing-duplicate (unwrap (read-u32be buffer 0)))
           (framing-sequence (unwrap (read-u32be buffer 1)))
           (framing-message-length (unwrap (read-u32be buffer 5)))
           (framing-message-data (unwrap (slice buffer 8 1)))
           (framing-ack-sequence (unwrap (read-u32be buffer 8)))
           (framing-received (unwrap (read-u32be buffer 12)))
           )

      (ok (list
        (cons 'framing-duplicate (list (cons 'raw framing-duplicate) (cons 'formatted (number->string framing-duplicate))))
        (cons 'framing-sequence (list (cons 'raw framing-sequence) (cons 'formatted (number->string framing-sequence))))
        (cons 'framing-message-length (list (cons 'raw framing-message-length) (cons 'formatted (number->string framing-message-length))))
        (cons 'framing-message-data (list (cons 'raw framing-message-data) (cons 'formatted (fmt-bytes framing-message-data))))
        (cons 'framing-ack-sequence (list (cons 'raw framing-ack-sequence) (cons 'formatted (number->string framing-ack-sequence))))
        (cons 'framing-received (list (cons 'raw framing-received) (cons 'formatted (fmt-hex framing-received))))
        )))

    (catch (e)
      (err (str "RELOAD-FRAMING parse error: " e)))))

;; dissect-reload-framing: parse RELOAD-FRAMING from bytevector
;; Returns (ok fields-alist) or (err message)