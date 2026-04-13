;; packet-hpfeeds.c
;; Routines for Honeypot Protocol Feeds packet disassembly
;; Copyright 2013, Sebastiano DI PAOLA - <sebastiano.dipaola@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hpfeeds.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hpfeeds.c

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
(def (dissect-hpfeeds buffer)
  "HPFEEDS HoneyPot Feeds Protocol"
  (try
    (let* (
           (errmsg (unwrap (slice buffer 0 1)))
           (server-len (unwrap (read-u8 buffer 0)))
           (msg-length (unwrap (read-u32be buffer 0)))
           (server (unwrap (slice buffer 1 1)))
           (nonce (unwrap (slice buffer 1 1)))
           (secret (unwrap (slice buffer 2 1)))
           (chan-len (unwrap (read-u8 buffer 4)))
           (payload (unwrap (slice buffer 5 1)))
           (ident-len (unwrap (read-u8 buffer 5)))
           (ident (unwrap (slice buffer 6 1)))
           (channel (unwrap (slice buffer 6 1)))
           )

      (ok (list
        (cons 'errmsg (list (cons 'raw errmsg) (cons 'formatted (utf8->string errmsg))))
        (cons 'server-len (list (cons 'raw server-len) (cons 'formatted (number->string server-len))))
        (cons 'msg-length (list (cons 'raw msg-length) (cons 'formatted (number->string msg-length))))
        (cons 'server (list (cons 'raw server) (cons 'formatted (utf8->string server))))
        (cons 'nonce (list (cons 'raw nonce) (cons 'formatted (fmt-bytes nonce))))
        (cons 'secret (list (cons 'raw secret) (cons 'formatted (fmt-bytes secret))))
        (cons 'chan-len (list (cons 'raw chan-len) (cons 'formatted (number->string chan-len))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'ident-len (list (cons 'raw ident-len) (cons 'formatted (number->string ident-len))))
        (cons 'ident (list (cons 'raw ident) (cons 'formatted (utf8->string ident))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (utf8->string channel))))
        )))

    (catch (e)
      (err (str "HPFEEDS parse error: " e)))))

;; dissect-hpfeeds: parse HPFEEDS from bytevector
;; Returns (ok fields-alist) or (err message)