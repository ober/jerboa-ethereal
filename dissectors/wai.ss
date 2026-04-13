;; packet-wai.c
;; Routines for WAI packet dissection
;; Based on: WAPI ISO submission - ISO/IEC JTC 1 N 9880 [ref: 1]
;; chapter "8.1.4 WAI protocol"
;;
;; Written by Lukasz Kotasa <lukasz.kotasa@tieto.com>
;; Lukasz Suchy  <lukasz.suchy@tieto.com>
;; Copyright 2010, Tieto.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wai.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wai.c

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
(def (dissect-wai buffer)
  "WAI Protocol"
  (try
    (let* (
           (version (unwrap (read-u16be buffer 0)))
           (data (unwrap (slice buffer 0 1)))
           (flag (unwrap (read-u8 buffer 0)))
           (bkid (unwrap (slice buffer 0 16)))
           (uskid (unwrap (slice buffer 0 1)))
           (wie (unwrap (slice buffer 0 1)))
           (message-auth-code (unwrap (slice buffer 0 20)))
           (mskid (unwrap (slice buffer 0 1)))
           (key-ann-id (unwrap (slice buffer 0 16)))
           (counter (unwrap (slice buffer 0 16)))
           (auth-id (unwrap (slice buffer 0 32)))
           (addid (unwrap (slice buffer 0 12)))
           (ae-mac (unwrap (slice buffer 0 6)))
           (asue-mac (unwrap (slice buffer 0 6)))
           (identity (unwrap (slice buffer 0 1)))
           (identity-id (unwrap (read-u16be buffer 0)))
           (identity-len (unwrap (read-u16be buffer 0)))
           (identity-data (unwrap (slice buffer 0 1)))
           (cert (unwrap (slice buffer 0 1)))
           (cert-id (unwrap (read-u16be buffer 0)))
           (cert-len (unwrap (read-u16be buffer 0)))
           (cert-data (unwrap (slice buffer 0 1)))
           (ecdh (unwrap (slice buffer 0 1)))
           (ecdh-id (unwrap (read-u8 buffer 0)))
           (ecdh-len (unwrap (read-u16be buffer 0)))
           (ecdh-content (unwrap (slice buffer 0 1)))
           (challenge (unwrap (slice buffer 0 32)))
           (key-data (unwrap (slice buffer 0 1)))
           (key-data-len (unwrap (read-u8 buffer 0)))
           (key-data-content (unwrap (slice buffer 0 1)))
           (cert-ver (unwrap (slice buffer 0 1)))
           (sta-key-id (unwrap (read-u8 buffer 1)))
           (nonce (unwrap (slice buffer 3 32)))
           (reserved (unwrap (read-u16be buffer 4)))
           (seq (unwrap (read-u16be buffer 8)))
           (fragm-seq (unwrap (read-u8 buffer 10)))
           (data-pack-num (unwrap (slice buffer 15 16)))
           (identity-list (unwrap (slice buffer 69 1)))
           (reserved-byte (unwrap (read-u8 buffer 72)))
           (no-of-ids (unwrap (read-u16be buffer 73)))
           (sign-alg (unwrap (slice buffer 75 1)))
           (hash-alg-id (unwrap (read-u8 buffer 77)))
           (sign-alg-id (unwrap (read-u8 buffer 78)))
           (param (unwrap (slice buffer 79 1)))
           (param-id (unwrap (slice buffer 79 1)))
           (param-content (unwrap (slice buffer 82 1)))
           (sign-val (unwrap (slice buffer 82 1)))
           (sign-content (unwrap (slice buffer 84 1)))
           (sign (unwrap (slice buffer 84 1)))
           (length (unwrap (read-u16be buffer 85)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'flag (list (cons 'raw flag) (cons 'formatted (fmt-hex flag))))
        (cons 'bkid (list (cons 'raw bkid) (cons 'formatted (fmt-bytes bkid))))
        (cons 'uskid (list (cons 'raw uskid) (cons 'formatted (fmt-bytes uskid))))
        (cons 'wie (list (cons 'raw wie) (cons 'formatted (fmt-bytes wie))))
        (cons 'message-auth-code (list (cons 'raw message-auth-code) (cons 'formatted (fmt-bytes message-auth-code))))
        (cons 'mskid (list (cons 'raw mskid) (cons 'formatted (fmt-bytes mskid))))
        (cons 'key-ann-id (list (cons 'raw key-ann-id) (cons 'formatted (fmt-bytes key-ann-id))))
        (cons 'counter (list (cons 'raw counter) (cons 'formatted (fmt-bytes counter))))
        (cons 'auth-id (list (cons 'raw auth-id) (cons 'formatted (fmt-bytes auth-id))))
        (cons 'addid (list (cons 'raw addid) (cons 'formatted (utf8->string addid))))
        (cons 'ae-mac (list (cons 'raw ae-mac) (cons 'formatted (fmt-mac ae-mac))))
        (cons 'asue-mac (list (cons 'raw asue-mac) (cons 'formatted (fmt-mac asue-mac))))
        (cons 'identity (list (cons 'raw identity) (cons 'formatted (fmt-bytes identity))))
        (cons 'identity-id (list (cons 'raw identity-id) (cons 'formatted (fmt-hex identity-id))))
        (cons 'identity-len (list (cons 'raw identity-len) (cons 'formatted (number->string identity-len))))
        (cons 'identity-data (list (cons 'raw identity-data) (cons 'formatted (fmt-bytes identity-data))))
        (cons 'cert (list (cons 'raw cert) (cons 'formatted (fmt-bytes cert))))
        (cons 'cert-id (list (cons 'raw cert-id) (cons 'formatted (fmt-hex cert-id))))
        (cons 'cert-len (list (cons 'raw cert-len) (cons 'formatted (number->string cert-len))))
        (cons 'cert-data (list (cons 'raw cert-data) (cons 'formatted (fmt-bytes cert-data))))
        (cons 'ecdh (list (cons 'raw ecdh) (cons 'formatted (fmt-bytes ecdh))))
        (cons 'ecdh-id (list (cons 'raw ecdh-id) (cons 'formatted (fmt-hex ecdh-id))))
        (cons 'ecdh-len (list (cons 'raw ecdh-len) (cons 'formatted (number->string ecdh-len))))
        (cons 'ecdh-content (list (cons 'raw ecdh-content) (cons 'formatted (fmt-bytes ecdh-content))))
        (cons 'challenge (list (cons 'raw challenge) (cons 'formatted (fmt-bytes challenge))))
        (cons 'key-data (list (cons 'raw key-data) (cons 'formatted (fmt-bytes key-data))))
        (cons 'key-data-len (list (cons 'raw key-data-len) (cons 'formatted (number->string key-data-len))))
        (cons 'key-data-content (list (cons 'raw key-data-content) (cons 'formatted (fmt-bytes key-data-content))))
        (cons 'cert-ver (list (cons 'raw cert-ver) (cons 'formatted (fmt-bytes cert-ver))))
        (cons 'sta-key-id (list (cons 'raw sta-key-id) (cons 'formatted (fmt-hex sta-key-id))))
        (cons 'nonce (list (cons 'raw nonce) (cons 'formatted (fmt-bytes nonce))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'fragm-seq (list (cons 'raw fragm-seq) (cons 'formatted (number->string fragm-seq))))
        (cons 'data-pack-num (list (cons 'raw data-pack-num) (cons 'formatted (fmt-bytes data-pack-num))))
        (cons 'identity-list (list (cons 'raw identity-list) (cons 'formatted (fmt-bytes identity-list))))
        (cons 'reserved-byte (list (cons 'raw reserved-byte) (cons 'formatted (fmt-hex reserved-byte))))
        (cons 'no-of-ids (list (cons 'raw no-of-ids) (cons 'formatted (number->string no-of-ids))))
        (cons 'sign-alg (list (cons 'raw sign-alg) (cons 'formatted (fmt-bytes sign-alg))))
        (cons 'hash-alg-id (list (cons 'raw hash-alg-id) (cons 'formatted (fmt-hex hash-alg-id))))
        (cons 'sign-alg-id (list (cons 'raw sign-alg-id) (cons 'formatted (fmt-hex sign-alg-id))))
        (cons 'param (list (cons 'raw param) (cons 'formatted (fmt-bytes param))))
        (cons 'param-id (list (cons 'raw param-id) (cons 'formatted (fmt-bytes param-id))))
        (cons 'param-content (list (cons 'raw param-content) (cons 'formatted (fmt-bytes param-content))))
        (cons 'sign-val (list (cons 'raw sign-val) (cons 'formatted (fmt-bytes sign-val))))
        (cons 'sign-content (list (cons 'raw sign-content) (cons 'formatted (fmt-bytes sign-content))))
        (cons 'sign (list (cons 'raw sign) (cons 'formatted (fmt-bytes sign))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        )))

    (catch (e)
      (err (str "WAI parse error: " e)))))

;; dissect-wai: parse WAI from bytevector
;; Returns (ok fields-alist) or (err message)