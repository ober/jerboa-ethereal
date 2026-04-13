;; packet-zrtp.c
;; Routines for zrtp packet dissection
;; IETF draft draft-zimmermann-avt-zrtp-22
;; RFC 6189
;; Copyright 2007, Sagar Pai <sagar@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-pop.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/zrtp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zrtp.c
;; RFC 6189

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
(def (dissect-zrtp buffer)
  "ZRTP"
  (try
    (let* (
           (msg-ping-version (unwrap (slice buffer 24 4)))
           (msg-ping-endpointhash (unwrap (read-u64be buffer 24)))
           (msg-pingack-endpointhash (unwrap (read-u64be buffer 24)))
           (msg-ping-ssrc (unwrap (read-u32be buffer 24)))
           (msg-cfb (unwrap (slice buffer 24 16)))
           (msg-nonce (unwrap (slice buffer 48 16)))
           (msg-key-id (unwrap (slice buffer 48 8)))
           (msg-rs1ID (unwrap (slice buffer 56 8)))
           (msg-rs2ID (unwrap (slice buffer 56 8)))
           (msg-auxs (unwrap (slice buffer 56 8)))
           (msg-pbxs (unwrap (slice buffer 56 8)))
           (msg-zid (unwrap (slice buffer 56 12)))
           (msg-hash (unwrap (slice buffer 56 4)))
           (msg-cipher (unwrap (slice buffer 56 4)))
           (msg-at (unwrap (slice buffer 56 4)))
           (msg-keya (unwrap (slice buffer 56 4)))
           (msg-sas (unwrap (slice buffer 56 4)))
           (msg-hvi (unwrap (slice buffer 56 32)))
           (msg-hmac (unwrap (slice buffer 64 8)))
           (msg-sigcap (unwrap (read-u8 buffer 88)))
           (msg-mitm (unwrap (read-u8 buffer 88)))
           (msg-passive (unwrap (read-u8 buffer 88)))
           (msg-hash-count (unwrap (read-u8 buffer 88)))
           (msg-cipher-count (unwrap (read-u8 buffer 88)))
           (msg-authtag-count (unwrap (read-u8 buffer 88)))
           (msg-key-count (unwrap (read-u8 buffer 88)))
           (msg-sas-count (unwrap (read-u8 buffer 88)))
           )

      (ok (list
        (cons 'msg-ping-version (list (cons 'raw msg-ping-version) (cons 'formatted (utf8->string msg-ping-version))))
        (cons 'msg-ping-endpointhash (list (cons 'raw msg-ping-endpointhash) (cons 'formatted (fmt-hex msg-ping-endpointhash))))
        (cons 'msg-pingack-endpointhash (list (cons 'raw msg-pingack-endpointhash) (cons 'formatted (fmt-hex msg-pingack-endpointhash))))
        (cons 'msg-ping-ssrc (list (cons 'raw msg-ping-ssrc) (cons 'formatted (fmt-hex msg-ping-ssrc))))
        (cons 'msg-cfb (list (cons 'raw msg-cfb) (cons 'formatted (fmt-bytes msg-cfb))))
        (cons 'msg-nonce (list (cons 'raw msg-nonce) (cons 'formatted (fmt-bytes msg-nonce))))
        (cons 'msg-key-id (list (cons 'raw msg-key-id) (cons 'formatted (fmt-bytes msg-key-id))))
        (cons 'msg-rs1ID (list (cons 'raw msg-rs1ID) (cons 'formatted (fmt-bytes msg-rs1ID))))
        (cons 'msg-rs2ID (list (cons 'raw msg-rs2ID) (cons 'formatted (fmt-bytes msg-rs2ID))))
        (cons 'msg-auxs (list (cons 'raw msg-auxs) (cons 'formatted (fmt-bytes msg-auxs))))
        (cons 'msg-pbxs (list (cons 'raw msg-pbxs) (cons 'formatted (fmt-bytes msg-pbxs))))
        (cons 'msg-zid (list (cons 'raw msg-zid) (cons 'formatted (fmt-bytes msg-zid))))
        (cons 'msg-hash (list (cons 'raw msg-hash) (cons 'formatted (utf8->string msg-hash))))
        (cons 'msg-cipher (list (cons 'raw msg-cipher) (cons 'formatted (utf8->string msg-cipher))))
        (cons 'msg-at (list (cons 'raw msg-at) (cons 'formatted (utf8->string msg-at))))
        (cons 'msg-keya (list (cons 'raw msg-keya) (cons 'formatted (utf8->string msg-keya))))
        (cons 'msg-sas (list (cons 'raw msg-sas) (cons 'formatted (utf8->string msg-sas))))
        (cons 'msg-hvi (list (cons 'raw msg-hvi) (cons 'formatted (fmt-bytes msg-hvi))))
        (cons 'msg-hmac (list (cons 'raw msg-hmac) (cons 'formatted (fmt-bytes msg-hmac))))
        (cons 'msg-sigcap (list (cons 'raw msg-sigcap) (cons 'formatted (number->string msg-sigcap))))
        (cons 'msg-mitm (list (cons 'raw msg-mitm) (cons 'formatted (number->string msg-mitm))))
        (cons 'msg-passive (list (cons 'raw msg-passive) (cons 'formatted (number->string msg-passive))))
        (cons 'msg-hash-count (list (cons 'raw msg-hash-count) (cons 'formatted (number->string msg-hash-count))))
        (cons 'msg-cipher-count (list (cons 'raw msg-cipher-count) (cons 'formatted (number->string msg-cipher-count))))
        (cons 'msg-authtag-count (list (cons 'raw msg-authtag-count) (cons 'formatted (number->string msg-authtag-count))))
        (cons 'msg-key-count (list (cons 'raw msg-key-count) (cons 'formatted (number->string msg-key-count))))
        (cons 'msg-sas-count (list (cons 'raw msg-sas-count) (cons 'formatted (number->string msg-sas-count))))
        )))

    (catch (e)
      (err (str "ZRTP parse error: " e)))))

;; dissect-zrtp: parse ZRTP from bytevector
;; Returns (ok fields-alist) or (err message)