;; packet-dtls.c
;; Routines for dtls dissection
;; Copyright (c) 2006, Authesserre Samuel <sauthess@gmail.com>
;; Copyright (c) 2007, Mikael Magnusson <mikma@users.sourceforge.net>
;; Copyright (c) 2013, Hauke Mehrtens <hauke@hauke-m.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;
;; DTLS dissection and decryption.
;; See RFC 4347 for details about DTLS specs.
;;
;; Notes :
;; This dissector is based on the TLS dissector (packet-tls.c); Because of the similarity
;; of DTLS and TLS, decryption works like TLS with RSA key exchange.
;; This dissector uses the sames things (file, libraries) as the TLS dissector (gnutls, packet-tls-utils.h)
;; to make it easily maintainable.
;;
;; It was developed to dissect and decrypt the OpenSSL v 0.9.8f DTLS implementation.
;; It is limited to this implementation; there is no complete implementation.
;;
;; Implemented :
;; - DTLS dissection
;; - DTLS decryption (openssl one)
;;
;; Todo :
;; - activate correct Mac calculation when openssl will be corrected
;; (or if an other implementation works),
;; corrected code is ready and commented in packet-tls-utils.h file.
;; - add missing things (desegmentation, reordering... that aren't present in actual OpenSSL implementation)
;;

;; jerboa-ethereal/dissectors/dtls.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dtls.c
;; RFC 4347

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
(def (dissect-dtls buffer)
  "Datagram Transport Layer Security"
  (try
    (let* (
           (record-appdata-proto (unwrap (slice buffer 0 1)))
           (stream (unwrap (read-u32be buffer 0)))
           (record-epoch (unwrap (read-u16be buffer 21)))
           (record-sequence-number (unwrap (read-u64be buffer 23)))
           (uni-hdr (unwrap (read-u8 buffer 34)))
           (uni-hdr-fixed (extract-bits uni-hdr 0x0 0))
           (uni-hdr-cid (extract-bits uni-hdr 0x0 0))
           (uni-hdr-seq (extract-bits uni-hdr 0x0 0))
           (uni-hdr-len (extract-bits uni-hdr 0x0 0))
           (uni-hdr-epoch (extract-bits uni-hdr 0x3 0))
           (record-connection-id (unwrap (slice buffer 35 1)))
           (record-sequence-suffix (unwrap (read-u16be buffer 35)))
           (record-length (unwrap (read-u16be buffer 35)))
           (handshake-length (unwrap (read-u24be buffer 37)))
           (handshake-message-seq (unwrap (read-u16be buffer 40)))
           (handshake-fragment-offset (unwrap (read-u24be buffer 42)))
           (handshake-fragment-length (unwrap (read-u24be buffer 45)))
           (heartbeat-message-payload-length (unwrap (read-u16be buffer 49)))
           (heartbeat-message-payload (unwrap (slice buffer 51 1)))
           (heartbeat-message-padding (unwrap (slice buffer 51 1)))
           (hs-ext-use-srtp-protection-profiles-length (unwrap (read-u16be buffer 55)))
           (hs-ext-use-srtp-mki-length (unwrap (read-u8 buffer 59)))
           (hs-ext-use-srtp-mki (unwrap (slice buffer 59 1)))
           )

      (ok (list
        (cons 'record-appdata-proto (list (cons 'raw record-appdata-proto) (cons 'formatted (utf8->string record-appdata-proto))))
        (cons 'stream (list (cons 'raw stream) (cons 'formatted (number->string stream))))
        (cons 'record-epoch (list (cons 'raw record-epoch) (cons 'formatted (number->string record-epoch))))
        (cons 'record-sequence-number (list (cons 'raw record-sequence-number) (cons 'formatted (number->string record-sequence-number))))
        (cons 'uni-hdr (list (cons 'raw uni-hdr) (cons 'formatted (fmt-hex uni-hdr))))
        (cons 'uni-hdr-fixed (list (cons 'raw uni-hdr-fixed) (cons 'formatted (if (= uni-hdr-fixed 0) "Not set" "Set"))))
        (cons 'uni-hdr-cid (list (cons 'raw uni-hdr-cid) (cons 'formatted (if (= uni-hdr-cid 0) "Not set" "Set"))))
        (cons 'uni-hdr-seq (list (cons 'raw uni-hdr-seq) (cons 'formatted (if (= uni-hdr-seq 0) "8 bits" "16 bits"))))
        (cons 'uni-hdr-len (list (cons 'raw uni-hdr-len) (cons 'formatted (if (= uni-hdr-len 0) "Not set" "Set"))))
        (cons 'uni-hdr-epoch (list (cons 'raw uni-hdr-epoch) (cons 'formatted (if (= uni-hdr-epoch 0) "Not set" "Set"))))
        (cons 'record-connection-id (list (cons 'raw record-connection-id) (cons 'formatted (fmt-bytes record-connection-id))))
        (cons 'record-sequence-suffix (list (cons 'raw record-sequence-suffix) (cons 'formatted (number->string record-sequence-suffix))))
        (cons 'record-length (list (cons 'raw record-length) (cons 'formatted (number->string record-length))))
        (cons 'handshake-length (list (cons 'raw handshake-length) (cons 'formatted (number->string handshake-length))))
        (cons 'handshake-message-seq (list (cons 'raw handshake-message-seq) (cons 'formatted (number->string handshake-message-seq))))
        (cons 'handshake-fragment-offset (list (cons 'raw handshake-fragment-offset) (cons 'formatted (number->string handshake-fragment-offset))))
        (cons 'handshake-fragment-length (list (cons 'raw handshake-fragment-length) (cons 'formatted (number->string handshake-fragment-length))))
        (cons 'heartbeat-message-payload-length (list (cons 'raw heartbeat-message-payload-length) (cons 'formatted (number->string heartbeat-message-payload-length))))
        (cons 'heartbeat-message-payload (list (cons 'raw heartbeat-message-payload) (cons 'formatted (fmt-bytes heartbeat-message-payload))))
        (cons 'heartbeat-message-padding (list (cons 'raw heartbeat-message-padding) (cons 'formatted (fmt-bytes heartbeat-message-padding))))
        (cons 'hs-ext-use-srtp-protection-profiles-length (list (cons 'raw hs-ext-use-srtp-protection-profiles-length) (cons 'formatted (number->string hs-ext-use-srtp-protection-profiles-length))))
        (cons 'hs-ext-use-srtp-mki-length (list (cons 'raw hs-ext-use-srtp-mki-length) (cons 'formatted (number->string hs-ext-use-srtp-mki-length))))
        (cons 'hs-ext-use-srtp-mki (list (cons 'raw hs-ext-use-srtp-mki) (cons 'formatted (fmt-bytes hs-ext-use-srtp-mki))))
        )))

    (catch (e)
      (err (str "DTLS parse error: " e)))))

;; dissect-dtls: parse DTLS from bytevector
;; Returns (ok fields-alist) or (err message)