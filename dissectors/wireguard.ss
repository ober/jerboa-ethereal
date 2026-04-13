;; packet-wireguard.c
;; Routines for WireGuard dissection
;; Copyright 2018, Peter Wu <peter@lekensteyn.nl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wireguard.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wireguard.c

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
(def (dissect-wireguard buffer)
  "WireGuard Protocol"
  (try
    (let* (
           (handshake-ok (unwrap (read-u8 buffer 0)))
           (stream (unwrap (read-u32be buffer 0)))
           (receiver-pubkey-known-privkey (unwrap (read-u8 buffer 0)))
           (receiver-pubkey (unwrap (slice buffer 0 1)))
           (static-known-pubkey (unwrap (read-u8 buffer 0)))
           (reserved (unwrap (slice buffer 1 3)))
           (sender (unwrap (read-u32be buffer 4)))
           (counter (unwrap (read-u64be buffer 8)))
           (nonce (unwrap (slice buffer 8 24)))
           (receiver (unwrap (read-u32be buffer 8)))
           (encrypted-cookie (unwrap (slice buffer 32 16)))
           (mac1 (unwrap (slice buffer 116 16)))
           (mac2 (unwrap (slice buffer 132 16)))
           )

      (ok (list
        (cons 'handshake-ok (list (cons 'raw handshake-ok) (cons 'formatted (number->string handshake-ok))))
        (cons 'stream (list (cons 'raw stream) (cons 'formatted (number->string stream))))
        (cons 'receiver-pubkey-known-privkey (list (cons 'raw receiver-pubkey-known-privkey) (cons 'formatted (number->string receiver-pubkey-known-privkey))))
        (cons 'receiver-pubkey (list (cons 'raw receiver-pubkey) (cons 'formatted (utf8->string receiver-pubkey))))
        (cons 'static-known-pubkey (list (cons 'raw static-known-pubkey) (cons 'formatted (number->string static-known-pubkey))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'sender (list (cons 'raw sender) (cons 'formatted (fmt-hex sender))))
        (cons 'counter (list (cons 'raw counter) (cons 'formatted (number->string counter))))
        (cons 'nonce (list (cons 'raw nonce) (cons 'formatted (fmt-bytes nonce))))
        (cons 'receiver (list (cons 'raw receiver) (cons 'formatted (fmt-hex receiver))))
        (cons 'encrypted-cookie (list (cons 'raw encrypted-cookie) (cons 'formatted (fmt-bytes encrypted-cookie))))
        (cons 'mac1 (list (cons 'raw mac1) (cons 'formatted (fmt-bytes mac1))))
        (cons 'mac2 (list (cons 'raw mac2) (cons 'formatted (fmt-bytes mac2))))
        )))

    (catch (e)
      (err (str "WIREGUARD parse error: " e)))))

;; dissect-wireguard: parse WIREGUARD from bytevector
;; Returns (ok fields-alist) or (err message)