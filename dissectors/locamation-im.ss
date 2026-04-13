;; packet-locamation-im.c
;; Routines for Locamation Interface Modules packet disassembly.
;;
;; Copyright (c) 2022 Locamation BV.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/locamation-im.ss
;; Auto-generated from wireshark/epan/dissectors/packet-locamation_im.c

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
(def (dissect-locamation-im buffer)
  "locamation-im dissector"
  (try
    (let* (
           (contents (unwrap (slice buffer 0 1)))
           (sequence-number (unwrap (read-u16be buffer 0)))
           (first-sequence-number (unwrap (read-u16be buffer 0)))
           (last-sequence-number (unwrap (read-u16be buffer 0)))
           (name (unwrap (slice buffer 0 1)))
           (chunk (unwrap (slice buffer 0 1)))
           (hop-count (unwrap (read-u8 buffer 0)))
           (control (unwrap (read-u8 buffer 0)))
           (padding (unwrap (read-u8 buffer 0)))
           (adc-status (unwrap (read-u8 buffer 0)))
           (timestamps-version (unwrap (read-u8 buffer 0)))
           (timestamps-reserved (unwrap (read-u24be buffer 0)))
           )

      (ok (list
        (cons 'contents (list (cons 'raw contents) (cons 'formatted (utf8->string contents))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (number->string sequence-number))))
        (cons 'first-sequence-number (list (cons 'raw first-sequence-number) (cons 'formatted (number->string first-sequence-number))))
        (cons 'last-sequence-number (list (cons 'raw last-sequence-number) (cons 'formatted (number->string last-sequence-number))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'chunk (list (cons 'raw chunk) (cons 'formatted (utf8->string chunk))))
        (cons 'hop-count (list (cons 'raw hop-count) (cons 'formatted (number->string hop-count))))
        (cons 'control (list (cons 'raw control) (cons 'formatted (fmt-hex control))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-hex padding))))
        (cons 'adc-status (list (cons 'raw adc-status) (cons 'formatted (fmt-hex adc-status))))
        (cons 'timestamps-version (list (cons 'raw timestamps-version) (cons 'formatted (number->string timestamps-version))))
        (cons 'timestamps-reserved (list (cons 'raw timestamps-reserved) (cons 'formatted (number->string timestamps-reserved))))
        )))

    (catch (e)
      (err (str "LOCAMATION-IM parse error: " e)))))

;; dissect-locamation-im: parse LOCAMATION-IM from bytevector
;; Returns (ok fields-alist) or (err message)