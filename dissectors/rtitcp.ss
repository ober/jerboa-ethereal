;; packet-rtitcp.c
;; Dissector for the RTI TCP Transport Protocol.
;; Layer on top of TCP used to send Control messages
;; to establish and maintain the connections as well as
;; send RTPS data.
;;
;; (c) 2005-2015 Copyright, Real-Time Innovations, Inc.
;; Real-Time Innovations, Inc.
;; 232 East Java Drive
;; Sunnyvale, CA 94089
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rtitcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rtitcp.c

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
(def (dissect-rtitcp buffer)
  "RTI TCP Transport Protocol"
  (try
    (let* (
           (control-attribute-error-code-description (unwrap (slice buffer 0 1)))
           (locator-port (unwrap (read-u16be buffer 0)))
           (locator-ipv4 (unwrap (read-u32be buffer 0)))
           (locator-ipv6 (unwrap (slice buffer 0 16)))
           (header-control-byte (unwrap (read-u16be buffer 0)))
           (header-message-length (unwrap (read-u24be buffer 0)))
           (header-magic-number (unwrap (read-u32be buffer 0)))
           (crc-magic-cookie (unwrap (read-u32be buffer 0)))
           (control-crc-value (unwrap (read-u32be buffer 0)))
           (attributes-list-length (unwrap (read-u16be buffer 18)))
           (control-magic-cookie (unwrap (read-u32be buffer 20)))
           (control-transaction-id (unwrap (slice buffer 24 12)))
           )

      (ok (list
        (cons 'control-attribute-error-code-description (list (cons 'raw control-attribute-error-code-description) (cons 'formatted (utf8->string control-attribute-error-code-description))))
        (cons 'locator-port (list (cons 'raw locator-port) (cons 'formatted (number->string locator-port))))
        (cons 'locator-ipv4 (list (cons 'raw locator-ipv4) (cons 'formatted (fmt-ipv4 locator-ipv4))))
        (cons 'locator-ipv6 (list (cons 'raw locator-ipv6) (cons 'formatted (fmt-ipv6-address locator-ipv6))))
        (cons 'header-control-byte (list (cons 'raw header-control-byte) (cons 'formatted (fmt-hex header-control-byte))))
        (cons 'header-message-length (list (cons 'raw header-message-length) (cons 'formatted (number->string header-message-length))))
        (cons 'header-magic-number (list (cons 'raw header-magic-number) (cons 'formatted (fmt-hex header-magic-number))))
        (cons 'crc-magic-cookie (list (cons 'raw crc-magic-cookie) (cons 'formatted (fmt-hex crc-magic-cookie))))
        (cons 'control-crc-value (list (cons 'raw control-crc-value) (cons 'formatted (fmt-hex control-crc-value))))
        (cons 'attributes-list-length (list (cons 'raw attributes-list-length) (cons 'formatted (number->string attributes-list-length))))
        (cons 'control-magic-cookie (list (cons 'raw control-magic-cookie) (cons 'formatted (fmt-hex control-magic-cookie))))
        (cons 'control-transaction-id (list (cons 'raw control-transaction-id) (cons 'formatted (fmt-bytes control-transaction-id))))
        )))

    (catch (e)
      (err (str "RTITCP parse error: " e)))))

;; dissect-rtitcp: parse RTITCP from bytevector
;; Returns (ok fields-alist) or (err message)