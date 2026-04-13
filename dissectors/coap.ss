;; packet-coap.c
;; Routines for CoAP packet disassembly
;; draft-ietf-core-coap-14.txt
;; draft-ietf-core-block-10.txt
;; draft-ietf-core-observe-16.txt
;; draft-ietf-core-link-format-06.txt
;; Shoichi Sakane <sakane@tanu.org>
;;
;; Changes for draft-ietf-core-coap-17.txt
;; Hauke Mehrtens <hauke@hauke-m.de>
;;
;; Support for CoAP over TCP, TLS and WebSockets
;; https://tools.ietf.org/html/rfc8323
;; Peter Wu <peter@lekensteyn.nl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/coap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-coap.c

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
(def (dissect-coap buffer)
  "Constrained Application Protocol"
  (try
    (let* (
           (oscore-piv (unwrap (slice buffer 0 1)))
           (oscore-kid-context (unwrap (slice buffer 0 1)))
           (oscore-kid (unwrap (slice buffer 0 1)))
           (response-resend-in (unwrap (read-u32be buffer 0)))
           (request-resend-in (unwrap (read-u32be buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (mid (unwrap (read-u16be buffer 1)))
           (token-len (unwrap (read-u8 buffer 3)))
           (token (unwrap (slice buffer 3 1)))
           (payload (unwrap (slice buffer 3 1)))
           (length (unwrap (read-u32be buffer 3)))
           )

      (ok (list
        (cons 'oscore-piv (list (cons 'raw oscore-piv) (cons 'formatted (fmt-bytes oscore-piv))))
        (cons 'oscore-kid-context (list (cons 'raw oscore-kid-context) (cons 'formatted (fmt-bytes oscore-kid-context))))
        (cons 'oscore-kid (list (cons 'raw oscore-kid) (cons 'formatted (fmt-bytes oscore-kid))))
        (cons 'response-resend-in (list (cons 'raw response-resend-in) (cons 'formatted (number->string response-resend-in))))
        (cons 'request-resend-in (list (cons 'raw request-resend-in) (cons 'formatted (number->string request-resend-in))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'mid (list (cons 'raw mid) (cons 'formatted (number->string mid))))
        (cons 'token-len (list (cons 'raw token-len) (cons 'formatted (number->string token-len))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (fmt-bytes token))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        )))

    (catch (e)
      (err (str "COAP parse error: " e)))))

;; dissect-coap: parse COAP from bytevector
;; Returns (ok fields-alist) or (err message)