;; packet-teap.c
;; Routines for TEAP (Tunnel Extensible Authentication Protocol)
;; RFC 7170
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/teap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-teap.c
;; RFC 7170

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
(def (dissect-teap buffer)
  "Tunnel Extensible Authentication Protocol"
  (try
    (let* (
           (attr-pac-key (unwrap (slice buffer 4 1)))
           (attr-pac-opaque (unwrap (slice buffer 4 1)))
           (attr-pac-lifetime (unwrap (read-u32be buffer 4)))
           (attr-pac-a-id (unwrap (slice buffer 8 1)))
           (attr-pac-i-id (unwrap (slice buffer 8 1)))
           (attr-pac-reserved (unwrap (slice buffer 8 1)))
           (attr-pac-a-id-info (unwrap (slice buffer 8 1)))
           (attr-val (unwrap (slice buffer 8 1)))
           (tlv-mandatory (unwrap (read-u8 buffer 8)))
           (tlv-reserved (unwrap (read-u16be buffer 8)))
           (tlv-len (unwrap (read-u16be buffer 10)))
           (auth-id (unwrap (slice buffer 12 1)))
           (nak-type (unwrap (read-u16be buffer 16)))
           (vendor-id (unwrap (read-u32be buffer 18)))
           (crypto-reserved (unwrap (read-u8 buffer 22)))
           (crypto-version (unwrap (read-u8 buffer 23)))
           (crypto-rcv-version (unwrap (read-u8 buffer 24)))
           (crypto-nonce (unwrap (slice buffer 26 32)))
           (crypto-emsk (unwrap (slice buffer 58 20)))
           (crypto-msk (unwrap (slice buffer 78 20)))
           (prompt (unwrap (slice buffer 98 1)))
           (user-len (unwrap (read-u8 buffer 98)))
           (username (unwrap (slice buffer 99 1)))
           (pass-len (unwrap (read-u8 buffer 99)))
           (password (unwrap (slice buffer 100 1)))
           (tlv-val (unwrap (slice buffer 100 1)))
           )

      (ok (list
        (cons 'attr-pac-key (list (cons 'raw attr-pac-key) (cons 'formatted (fmt-bytes attr-pac-key))))
        (cons 'attr-pac-opaque (list (cons 'raw attr-pac-opaque) (cons 'formatted (fmt-bytes attr-pac-opaque))))
        (cons 'attr-pac-lifetime (list (cons 'raw attr-pac-lifetime) (cons 'formatted (number->string attr-pac-lifetime))))
        (cons 'attr-pac-a-id (list (cons 'raw attr-pac-a-id) (cons 'formatted (utf8->string attr-pac-a-id))))
        (cons 'attr-pac-i-id (list (cons 'raw attr-pac-i-id) (cons 'formatted (utf8->string attr-pac-i-id))))
        (cons 'attr-pac-reserved (list (cons 'raw attr-pac-reserved) (cons 'formatted (fmt-bytes attr-pac-reserved))))
        (cons 'attr-pac-a-id-info (list (cons 'raw attr-pac-a-id-info) (cons 'formatted (utf8->string attr-pac-a-id-info))))
        (cons 'attr-val (list (cons 'raw attr-val) (cons 'formatted (fmt-bytes attr-val))))
        (cons 'tlv-mandatory (list (cons 'raw tlv-mandatory) (cons 'formatted (number->string tlv-mandatory))))
        (cons 'tlv-reserved (list (cons 'raw tlv-reserved) (cons 'formatted (number->string tlv-reserved))))
        (cons 'tlv-len (list (cons 'raw tlv-len) (cons 'formatted (number->string tlv-len))))
        (cons 'auth-id (list (cons 'raw auth-id) (cons 'formatted (fmt-bytes auth-id))))
        (cons 'nak-type (list (cons 'raw nak-type) (cons 'formatted (fmt-hex nak-type))))
        (cons 'vendor-id (list (cons 'raw vendor-id) (cons 'formatted (fmt-hex vendor-id))))
        (cons 'crypto-reserved (list (cons 'raw crypto-reserved) (cons 'formatted (number->string crypto-reserved))))
        (cons 'crypto-version (list (cons 'raw crypto-version) (cons 'formatted (number->string crypto-version))))
        (cons 'crypto-rcv-version (list (cons 'raw crypto-rcv-version) (cons 'formatted (number->string crypto-rcv-version))))
        (cons 'crypto-nonce (list (cons 'raw crypto-nonce) (cons 'formatted (fmt-bytes crypto-nonce))))
        (cons 'crypto-emsk (list (cons 'raw crypto-emsk) (cons 'formatted (fmt-bytes crypto-emsk))))
        (cons 'crypto-msk (list (cons 'raw crypto-msk) (cons 'formatted (fmt-bytes crypto-msk))))
        (cons 'prompt (list (cons 'raw prompt) (cons 'formatted (utf8->string prompt))))
        (cons 'user-len (list (cons 'raw user-len) (cons 'formatted (number->string user-len))))
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'pass-len (list (cons 'raw pass-len) (cons 'formatted (number->string pass-len))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (utf8->string password))))
        (cons 'tlv-val (list (cons 'raw tlv-val) (cons 'formatted (fmt-bytes tlv-val))))
        )))

    (catch (e)
      (err (str "TEAP parse error: " e)))))

;; dissect-teap: parse TEAP from bytevector
;; Returns (ok fields-alist) or (err message)