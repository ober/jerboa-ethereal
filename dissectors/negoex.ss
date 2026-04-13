;; packet-negoex.c
;; Dissect the NEGOEX security protocol
;; as described here: https://tools.ietf.org/html/draft-zhu-negoex-04
;; Copyright 2012 Richard Sharpe <realrichardsharpe@gmail.com>
;; Routines for SPNEGO Extended Negotiation Security Mechanism
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/negoex.ss
;; Auto-generated from wireshark/epan/dissectors/packet-negoex.c

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
(def (dissect-negoex buffer)
  "SPNEGO Extended Negotiation Security Mechanism"
  (try
    (let* (
           (sig (unwrap (slice buffer 0 8)))
           (sequence-num (unwrap (read-u32be buffer 12)))
           (errorcode (unwrap (read-u32be buffer 16)))
           (header-len (unwrap (read-u32be buffer 16)))
           (message-len (unwrap (read-u32be buffer 20)))
           (conversation-id (unwrap (slice buffer 24 16)))
           (data (unwrap (slice buffer 40 1)))
           (checksum-type (unwrap (read-u32be buffer 44)))
           (checksum-vector-offset (unwrap (read-u32be buffer 48)))
           (checksum-vector-count (unwrap (read-u16be buffer 52)))
           (checksum-vector-pad (unwrap (slice buffer 54 2)))
           (authscheme (unwrap (slice buffer 56 16)))
           (exchange-vector-offset (unwrap (read-u32be buffer 72)))
           (exchange-vector-count (unwrap (read-u16be buffer 76)))
           (exchange-vector-pad (unwrap (slice buffer 78 2)))
           (random (unwrap (slice buffer 80 32)))
           (proto-version (unwrap (read-u64be buffer 112)))
           (authscheme-vector-offset (unwrap (read-u32be buffer 120)))
           (authscheme-vector-count (unwrap (read-u16be buffer 124)))
           (authscheme-vector-pad (unwrap (slice buffer 126 2)))
           (extension-vector-offset (unwrap (read-u32be buffer 128)))
           (extension-vector-count (unwrap (read-u16be buffer 132)))
           (extension-vector-pad (unwrap (slice buffer 134 2)))
           )

      (ok (list
        (cons 'sig (list (cons 'raw sig) (cons 'formatted (utf8->string sig))))
        (cons 'sequence-num (list (cons 'raw sequence-num) (cons 'formatted (number->string sequence-num))))
        (cons 'errorcode (list (cons 'raw errorcode) (cons 'formatted (fmt-hex errorcode))))
        (cons 'header-len (list (cons 'raw header-len) (cons 'formatted (number->string header-len))))
        (cons 'message-len (list (cons 'raw message-len) (cons 'formatted (number->string message-len))))
        (cons 'conversation-id (list (cons 'raw conversation-id) (cons 'formatted (fmt-bytes conversation-id))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'checksum-type (list (cons 'raw checksum-type) (cons 'formatted (number->string checksum-type))))
        (cons 'checksum-vector-offset (list (cons 'raw checksum-vector-offset) (cons 'formatted (number->string checksum-vector-offset))))
        (cons 'checksum-vector-count (list (cons 'raw checksum-vector-count) (cons 'formatted (number->string checksum-vector-count))))
        (cons 'checksum-vector-pad (list (cons 'raw checksum-vector-pad) (cons 'formatted (fmt-bytes checksum-vector-pad))))
        (cons 'authscheme (list (cons 'raw authscheme) (cons 'formatted (fmt-bytes authscheme))))
        (cons 'exchange-vector-offset (list (cons 'raw exchange-vector-offset) (cons 'formatted (number->string exchange-vector-offset))))
        (cons 'exchange-vector-count (list (cons 'raw exchange-vector-count) (cons 'formatted (number->string exchange-vector-count))))
        (cons 'exchange-vector-pad (list (cons 'raw exchange-vector-pad) (cons 'formatted (fmt-bytes exchange-vector-pad))))
        (cons 'random (list (cons 'raw random) (cons 'formatted (fmt-bytes random))))
        (cons 'proto-version (list (cons 'raw proto-version) (cons 'formatted (number->string proto-version))))
        (cons 'authscheme-vector-offset (list (cons 'raw authscheme-vector-offset) (cons 'formatted (number->string authscheme-vector-offset))))
        (cons 'authscheme-vector-count (list (cons 'raw authscheme-vector-count) (cons 'formatted (number->string authscheme-vector-count))))
        (cons 'authscheme-vector-pad (list (cons 'raw authscheme-vector-pad) (cons 'formatted (fmt-bytes authscheme-vector-pad))))
        (cons 'extension-vector-offset (list (cons 'raw extension-vector-offset) (cons 'formatted (number->string extension-vector-offset))))
        (cons 'extension-vector-count (list (cons 'raw extension-vector-count) (cons 'formatted (number->string extension-vector-count))))
        (cons 'extension-vector-pad (list (cons 'raw extension-vector-pad) (cons 'formatted (fmt-bytes extension-vector-pad))))
        )))

    (catch (e)
      (err (str "NEGOEX parse error: " e)))))

;; dissect-negoex: parse NEGOEX from bytevector
;; Returns (ok fields-alist) or (err message)