;; packet-xmcp.c
;; Routines for eXtensible Messaging Client Protocol (XMCP) dissection
;; Copyright 2011, Glenn Matthews <glenn.matthews@cisco.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-stun.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;
;; XMCP is a proprietary Cisco protocol based very loosely on the
;; Session Traversal Utilities for NAT (STUN) protocol.
;; This dissector is capable of understanding XMCP versions 1.0 and 2.0.
;;

;; jerboa-ethereal/dissectors/xmcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-xmcp.c

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
(def (dissect-xmcp buffer)
  "eXtensible Messaging Client Protocol"
  (try
    (let* (
           (type (unwrap (read-u16be buffer 0)))
           (type-reserved (extract-bits type 0x0 0))
           (attr-username (unwrap (slice buffer 0 1)))
           (attr-message-integrity (unwrap (slice buffer 0 1)))
           (attr-error-reserved (unwrap (read-u24be buffer 0)))
           (attr-error-class (unwrap (read-u24be buffer 0)))
           (attr-realm (unwrap (slice buffer 0 1)))
           (attr-nonce (unwrap (slice buffer 0 1)))
           (attr-client-name (unwrap (slice buffer 0 1)))
           (attr-client-handle (unwrap (read-u32be buffer 0)))
           (attr-version-major (unwrap (read-u16be buffer 0)))
           (attr-page-size (unwrap (read-u32be buffer 0)))
           (attr-client-label (unwrap (slice buffer 0 1)))
           (attr-keepalive (unwrap (read-u32be buffer 0)))
           (attr-serv-service (unwrap (read-u16be buffer 0)))
           (attr-reserved (unwrap (slice buffer 0 1)))
           (attr-service-version (unwrap (read-u32be buffer 0)))
           (attr-service-data (unwrap (slice buffer 0 1)))
           (attr-subscription-id (unwrap (read-u32be buffer 0)))
           (attr-domain (unwrap (read-u32be buffer 0)))
           (attr-value (unwrap (slice buffer 0 1)))
           (length (unwrap (read-u16be buffer 2)))
           (attr-length (unwrap (read-u16be buffer 2)))
           (cookie (unwrap (read-u32be buffer 4)))
           (id (unwrap (slice buffer 8 12)))
           )

      (ok (list
        (cons 'type (list (cons 'raw type) (cons 'formatted (fmt-hex type))))
        (cons 'type-reserved (list (cons 'raw type-reserved) (cons 'formatted (if (= type-reserved 0) "Not set" "Set"))))
        (cons 'attr-username (list (cons 'raw attr-username) (cons 'formatted (utf8->string attr-username))))
        (cons 'attr-message-integrity (list (cons 'raw attr-message-integrity) (cons 'formatted (fmt-bytes attr-message-integrity))))
        (cons 'attr-error-reserved (list (cons 'raw attr-error-reserved) (cons 'formatted (fmt-hex attr-error-reserved))))
        (cons 'attr-error-class (list (cons 'raw attr-error-class) (cons 'formatted (number->string attr-error-class))))
        (cons 'attr-realm (list (cons 'raw attr-realm) (cons 'formatted (utf8->string attr-realm))))
        (cons 'attr-nonce (list (cons 'raw attr-nonce) (cons 'formatted (utf8->string attr-nonce))))
        (cons 'attr-client-name (list (cons 'raw attr-client-name) (cons 'formatted (utf8->string attr-client-name))))
        (cons 'attr-client-handle (list (cons 'raw attr-client-handle) (cons 'formatted (number->string attr-client-handle))))
        (cons 'attr-version-major (list (cons 'raw attr-version-major) (cons 'formatted (number->string attr-version-major))))
        (cons 'attr-page-size (list (cons 'raw attr-page-size) (cons 'formatted (number->string attr-page-size))))
        (cons 'attr-client-label (list (cons 'raw attr-client-label) (cons 'formatted (utf8->string attr-client-label))))
        (cons 'attr-keepalive (list (cons 'raw attr-keepalive) (cons 'formatted (number->string attr-keepalive))))
        (cons 'attr-serv-service (list (cons 'raw attr-serv-service) (cons 'formatted (number->string attr-serv-service))))
        (cons 'attr-reserved (list (cons 'raw attr-reserved) (cons 'formatted (fmt-bytes attr-reserved))))
        (cons 'attr-service-version (list (cons 'raw attr-service-version) (cons 'formatted (number->string attr-service-version))))
        (cons 'attr-service-data (list (cons 'raw attr-service-data) (cons 'formatted (fmt-bytes attr-service-data))))
        (cons 'attr-subscription-id (list (cons 'raw attr-subscription-id) (cons 'formatted (number->string attr-subscription-id))))
        (cons 'attr-domain (list (cons 'raw attr-domain) (cons 'formatted (number->string attr-domain))))
        (cons 'attr-value (list (cons 'raw attr-value) (cons 'formatted (fmt-bytes attr-value))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'attr-length (list (cons 'raw attr-length) (cons 'formatted (number->string attr-length))))
        (cons 'cookie (list (cons 'raw cookie) (cons 'formatted (fmt-hex cookie))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-bytes id))))
        )))

    (catch (e)
      (err (str "XMCP parse error: " e)))))

;; dissect-xmcp: parse XMCP from bytevector
;; Returns (ok fields-alist) or (err message)