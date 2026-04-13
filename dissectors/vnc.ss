;; packet-vnc.c
;; Routines for VNC dissection (Virtual Network Computing)
;; Copyright 2005, Ulf Lamping <ulf.lamping@web.de>
;; Copyright 2006-2007, Stephen Fisher (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vnc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vnc.c
;; RFC 6143

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
(def (dissect-vnc buffer)
  "Virtual Network Computing"
  (try
    (let* (
           (tight-num-tunnel-types (unwrap (read-u32be buffer 1)))
           (client-proto-ver (unwrap (slice buffer 4 7)))
           (server-proto-ver (unwrap (slice buffer 4 7)))
           (tight-tunnel-type-code (unwrap (read-u32be buffer 5)))
           (tight-tunnel-type-vendor (unwrap (slice buffer 5 4)))
           (tight-tunnel-type-signature (unwrap (slice buffer 5 8)))
           (num-security-types (unwrap (read-u8 buffer 16)))
           (tight-num-auth-types (unwrap (read-u32be buffer 21)))
           (tight-signature (unwrap (slice buffer 33 8)))
           (auth-challenge (unwrap (slice buffer 33 16)))
           (auth-response (unwrap (slice buffer 33 16)))
           (ard-auth-generator (unwrap (read-u16be buffer 33)))
           (ard-auth-key-len (unwrap (read-u16be buffer 33)))
           (ard-auth-modulus (unwrap (slice buffer 37 1)))
           (ard-auth-server-key (unwrap (slice buffer 37 1)))
           (ard-auth-credentials (unwrap (slice buffer 37 128)))
           (ard-auth-client-key (unwrap (slice buffer 37 1)))
           (auth-result (unwrap (read-u8 buffer 37)))
           (auth-error-length (unwrap (read-u32be buffer 41)))
           (auth-error (unwrap (slice buffer 45 1)))
           (vencrypt-server-major-ver (unwrap (read-u8 buffer 45)))
           (vencrypt-server-minor-ver (unwrap (read-u8 buffer 45)))
           (vencrypt-client-major-ver (unwrap (read-u8 buffer 45)))
           (vencrypt-client-minor-ver (unwrap (read-u8 buffer 45)))
           (vencrypt-version-ack (unwrap (read-u8 buffer 45)))
           (vencrypt-num-auth-types (unwrap (read-u32be buffer 46)))
           (vencrypt-auth-type-ack (unwrap (read-u8 buffer 55)))
           (share-desktop-flag (unwrap (read-u8 buffer 55)))
           (width (unwrap (read-u16be buffer 55)))
           (height (unwrap (read-u16be buffer 57)))
           (server-bits-per-pixel (unwrap (read-u8 buffer 59)))
           (server-depth (unwrap (read-u8 buffer 60)))
           (server-big-endian-flag (unwrap (read-u8 buffer 61)))
           (server-true-color-flag (unwrap (read-u8 buffer 62)))
           (server-red-max (unwrap (read-u16be buffer 63)))
           (server-green-max (unwrap (read-u16be buffer 65)))
           (server-blue-max (unwrap (read-u16be buffer 67)))
           (server-red-shift (unwrap (read-u8 buffer 69)))
           (server-green-shift (unwrap (read-u8 buffer 70)))
           (server-blue-shift (unwrap (read-u8 buffer 71)))
           (desktop-name-len (unwrap (read-u32be buffer 75)))
           (desktop-name (unwrap (slice buffer 79 1)))
           (num-server-message-types (unwrap (read-u16be buffer 79)))
           (num-client-message-types (unwrap (read-u16be buffer 81)))
           (num-encoding-types (unwrap (read-u16be buffer 83)))
           )

      (ok (list
        (cons 'tight-num-tunnel-types (list (cons 'raw tight-num-tunnel-types) (cons 'formatted (number->string tight-num-tunnel-types))))
        (cons 'client-proto-ver (list (cons 'raw client-proto-ver) (cons 'formatted (utf8->string client-proto-ver))))
        (cons 'server-proto-ver (list (cons 'raw server-proto-ver) (cons 'formatted (utf8->string server-proto-ver))))
        (cons 'tight-tunnel-type-code (list (cons 'raw tight-tunnel-type-code) (cons 'formatted (number->string tight-tunnel-type-code))))
        (cons 'tight-tunnel-type-vendor (list (cons 'raw tight-tunnel-type-vendor) (cons 'formatted (utf8->string tight-tunnel-type-vendor))))
        (cons 'tight-tunnel-type-signature (list (cons 'raw tight-tunnel-type-signature) (cons 'formatted (utf8->string tight-tunnel-type-signature))))
        (cons 'num-security-types (list (cons 'raw num-security-types) (cons 'formatted (number->string num-security-types))))
        (cons 'tight-num-auth-types (list (cons 'raw tight-num-auth-types) (cons 'formatted (number->string tight-num-auth-types))))
        (cons 'tight-signature (list (cons 'raw tight-signature) (cons 'formatted (utf8->string tight-signature))))
        (cons 'auth-challenge (list (cons 'raw auth-challenge) (cons 'formatted (fmt-bytes auth-challenge))))
        (cons 'auth-response (list (cons 'raw auth-response) (cons 'formatted (fmt-bytes auth-response))))
        (cons 'ard-auth-generator (list (cons 'raw ard-auth-generator) (cons 'formatted (number->string ard-auth-generator))))
        (cons 'ard-auth-key-len (list (cons 'raw ard-auth-key-len) (cons 'formatted (number->string ard-auth-key-len))))
        (cons 'ard-auth-modulus (list (cons 'raw ard-auth-modulus) (cons 'formatted (fmt-bytes ard-auth-modulus))))
        (cons 'ard-auth-server-key (list (cons 'raw ard-auth-server-key) (cons 'formatted (fmt-bytes ard-auth-server-key))))
        (cons 'ard-auth-credentials (list (cons 'raw ard-auth-credentials) (cons 'formatted (fmt-bytes ard-auth-credentials))))
        (cons 'ard-auth-client-key (list (cons 'raw ard-auth-client-key) (cons 'formatted (fmt-bytes ard-auth-client-key))))
        (cons 'auth-result (list (cons 'raw auth-result) (cons 'formatted (if (= auth-result 0) "OK" "Failed"))))
        (cons 'auth-error-length (list (cons 'raw auth-error-length) (cons 'formatted (number->string auth-error-length))))
        (cons 'auth-error (list (cons 'raw auth-error) (cons 'formatted (utf8->string auth-error))))
        (cons 'vencrypt-server-major-ver (list (cons 'raw vencrypt-server-major-ver) (cons 'formatted (number->string vencrypt-server-major-ver))))
        (cons 'vencrypt-server-minor-ver (list (cons 'raw vencrypt-server-minor-ver) (cons 'formatted (number->string vencrypt-server-minor-ver))))
        (cons 'vencrypt-client-major-ver (list (cons 'raw vencrypt-client-major-ver) (cons 'formatted (number->string vencrypt-client-major-ver))))
        (cons 'vencrypt-client-minor-ver (list (cons 'raw vencrypt-client-minor-ver) (cons 'formatted (number->string vencrypt-client-minor-ver))))
        (cons 'vencrypt-version-ack (list (cons 'raw vencrypt-version-ack) (cons 'formatted (if (= vencrypt-version-ack 0) "False" "True"))))
        (cons 'vencrypt-num-auth-types (list (cons 'raw vencrypt-num-auth-types) (cons 'formatted (number->string vencrypt-num-auth-types))))
        (cons 'vencrypt-auth-type-ack (list (cons 'raw vencrypt-auth-type-ack) (cons 'formatted (if (= vencrypt-auth-type-ack 0) "False" "True"))))
        (cons 'share-desktop-flag (list (cons 'raw share-desktop-flag) (cons 'formatted (number->string share-desktop-flag))))
        (cons 'width (list (cons 'raw width) (cons 'formatted (number->string width))))
        (cons 'height (list (cons 'raw height) (cons 'formatted (number->string height))))
        (cons 'server-bits-per-pixel (list (cons 'raw server-bits-per-pixel) (cons 'formatted (number->string server-bits-per-pixel))))
        (cons 'server-depth (list (cons 'raw server-depth) (cons 'formatted (number->string server-depth))))
        (cons 'server-big-endian-flag (list (cons 'raw server-big-endian-flag) (cons 'formatted (number->string server-big-endian-flag))))
        (cons 'server-true-color-flag (list (cons 'raw server-true-color-flag) (cons 'formatted (number->string server-true-color-flag))))
        (cons 'server-red-max (list (cons 'raw server-red-max) (cons 'formatted (number->string server-red-max))))
        (cons 'server-green-max (list (cons 'raw server-green-max) (cons 'formatted (number->string server-green-max))))
        (cons 'server-blue-max (list (cons 'raw server-blue-max) (cons 'formatted (number->string server-blue-max))))
        (cons 'server-red-shift (list (cons 'raw server-red-shift) (cons 'formatted (number->string server-red-shift))))
        (cons 'server-green-shift (list (cons 'raw server-green-shift) (cons 'formatted (number->string server-green-shift))))
        (cons 'server-blue-shift (list (cons 'raw server-blue-shift) (cons 'formatted (number->string server-blue-shift))))
        (cons 'desktop-name-len (list (cons 'raw desktop-name-len) (cons 'formatted (number->string desktop-name-len))))
        (cons 'desktop-name (list (cons 'raw desktop-name) (cons 'formatted (utf8->string desktop-name))))
        (cons 'num-server-message-types (list (cons 'raw num-server-message-types) (cons 'formatted (number->string num-server-message-types))))
        (cons 'num-client-message-types (list (cons 'raw num-client-message-types) (cons 'formatted (number->string num-client-message-types))))
        (cons 'num-encoding-types (list (cons 'raw num-encoding-types) (cons 'formatted (number->string num-encoding-types))))
        )))

    (catch (e)
      (err (str "VNC parse error: " e)))))

;; dissect-vnc: parse VNC from bytevector
;; Returns (ok fields-alist) or (err message)