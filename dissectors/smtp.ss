;; packet-smtp.c
;; Routines for SMTP packet disassembly
;;
;; Copyright (c) 2000 by Richard Sharpe <rsharpe@ns.aus.com>
;;
;; Added RFC 4954 SMTP Authentication
;; Michael Mann * Copyright 2012
;; Added RFC 2920 Pipelining and RFC 3030 BDAT Pipelining
;; John Thacker <johnthacker@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/smtp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-smtp.c
;; RFC 4954

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
(def (dissect-smtp buffer)
  "Simple Mail Transfer Protocol"
  (try
    (let* (
           (rsp (unwrap (read-u8 buffer 0)))
           (req (unwrap (read-u8 buffer 0)))
           (message (unwrap (slice buffer 0 1)))
           (username (unwrap (slice buffer 0 1)))
           (password (unwrap (slice buffer 0 1)))
           (command-line (unwrap (slice buffer 0 1)))
           (req-command (unwrap (slice buffer 0 1)))
           (req-parameter (unwrap (slice buffer 0 1)))
           (response (unwrap (slice buffer 0 1)))
           (rsp-parameter (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'rsp (list (cons 'raw rsp) (cons 'formatted (number->string rsp))))
        (cons 'req (list (cons 'raw req) (cons 'formatted (number->string req))))
        (cons 'message (list (cons 'raw message) (cons 'formatted (utf8->string message))))
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (utf8->string password))))
        (cons 'command-line (list (cons 'raw command-line) (cons 'formatted (utf8->string command-line))))
        (cons 'req-command (list (cons 'raw req-command) (cons 'formatted (utf8->string req-command))))
        (cons 'req-parameter (list (cons 'raw req-parameter) (cons 'formatted (utf8->string req-parameter))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (utf8->string response))))
        (cons 'rsp-parameter (list (cons 'raw rsp-parameter) (cons 'formatted (utf8->string rsp-parameter))))
        )))

    (catch (e)
      (err (str "SMTP parse error: " e)))))

;; dissect-smtp: parse SMTP from bytevector
;; Returns (ok fields-alist) or (err message)