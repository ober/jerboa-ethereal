;; packet-rsip.c
;; Routines for Realm Specific IP (RSIP) Protocol dissection
;; Brian Ginsbach <ginsbach@cray.com>
;;
;; Copyright (c) 2006, 2010 Cray Inc. All Rights Reserved.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rsip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rsip.c
;; RFC 3103

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
(def (dissect-rsip buffer)
  "Realm Specific IP Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (parameter-length (unwrap (read-u16be buffer 0)))
           (parameter-value (unwrap (slice buffer 0 1)))
           (parameter-address-ipv4 (unwrap (read-u32be buffer 0)))
           (parameter-address-ipv4-netmask (unwrap (read-u32be buffer 0)))
           (parameter-address-ipv6 (unwrap (slice buffer 0 16)))
           (parameter-address-fqdn (unwrap (slice buffer 0 1)))
           (parameter-ports-number (unwrap (read-u8 buffer 0)))
           (parameter-ports-port-number (unwrap (read-u16be buffer 0)))
           (parameter-lease-time (unwrap (read-u32be buffer 0)))
           (parameter-client-id (unwrap (read-u32be buffer 0)))
           (parameter-bind-id (unwrap (read-u32be buffer 0)))
           (parameter-indicator (unwrap (read-u16be buffer 0)))
           (parameter-message-counter (unwrap (read-u32be buffer 0)))
           (parameter-vendor-specific-vendor-id (unwrap (read-u16be buffer 0)))
           (parameter-vendor-specific-subtype (unwrap (read-u16be buffer 0)))
           (parameter-spi-number (unwrap (read-u16be buffer 0)))
           (parameter-spi (unwrap (read-u32be buffer 0)))
           (message-length (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'parameter-length (list (cons 'raw parameter-length) (cons 'formatted (number->string parameter-length))))
        (cons 'parameter-value (list (cons 'raw parameter-value) (cons 'formatted (fmt-bytes parameter-value))))
        (cons 'parameter-address-ipv4 (list (cons 'raw parameter-address-ipv4) (cons 'formatted (fmt-ipv4 parameter-address-ipv4))))
        (cons 'parameter-address-ipv4-netmask (list (cons 'raw parameter-address-ipv4-netmask) (cons 'formatted (fmt-ipv4 parameter-address-ipv4-netmask))))
        (cons 'parameter-address-ipv6 (list (cons 'raw parameter-address-ipv6) (cons 'formatted (fmt-ipv6-address parameter-address-ipv6))))
        (cons 'parameter-address-fqdn (list (cons 'raw parameter-address-fqdn) (cons 'formatted (utf8->string parameter-address-fqdn))))
        (cons 'parameter-ports-number (list (cons 'raw parameter-ports-number) (cons 'formatted (number->string parameter-ports-number))))
        (cons 'parameter-ports-port-number (list (cons 'raw parameter-ports-port-number) (cons 'formatted (number->string parameter-ports-port-number))))
        (cons 'parameter-lease-time (list (cons 'raw parameter-lease-time) (cons 'formatted (number->string parameter-lease-time))))
        (cons 'parameter-client-id (list (cons 'raw parameter-client-id) (cons 'formatted (number->string parameter-client-id))))
        (cons 'parameter-bind-id (list (cons 'raw parameter-bind-id) (cons 'formatted (number->string parameter-bind-id))))
        (cons 'parameter-indicator (list (cons 'raw parameter-indicator) (cons 'formatted (fmt-hex parameter-indicator))))
        (cons 'parameter-message-counter (list (cons 'raw parameter-message-counter) (cons 'formatted (number->string parameter-message-counter))))
        (cons 'parameter-vendor-specific-vendor-id (list (cons 'raw parameter-vendor-specific-vendor-id) (cons 'formatted (number->string parameter-vendor-specific-vendor-id))))
        (cons 'parameter-vendor-specific-subtype (list (cons 'raw parameter-vendor-specific-subtype) (cons 'formatted (number->string parameter-vendor-specific-subtype))))
        (cons 'parameter-spi-number (list (cons 'raw parameter-spi-number) (cons 'formatted (number->string parameter-spi-number))))
        (cons 'parameter-spi (list (cons 'raw parameter-spi) (cons 'formatted (fmt-hex parameter-spi))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        )))

    (catch (e)
      (err (str "RSIP parse error: " e)))))

;; dissect-rsip: parse RSIP from bytevector
;; Returns (ok fields-alist) or (err message)