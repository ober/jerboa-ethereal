;; packet-bittorrent.c
;; Routines for bittorrent packet dissection
;; Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-pop.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bittorrent.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bittorrent.c

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
(def (dissect-bittorrent buffer)
  "BitTorrent"
  (try
    (let* (
           (msg-len (unwrap (read-u32be buffer 0)))
           (continuous-data (unwrap (slice buffer 0 1)))
           (msg-type-len (unwrap (read-u32be buffer 0)))
           (msg-type (unwrap (slice buffer 0 1)))
           (piece-length (unwrap (read-u32be buffer 13)))
           (port (unwrap (read-u16be buffer 13)))
           (extended-id (unwrap (read-u8 buffer 13)))
           (extended (unwrap (slice buffer 14 1)))
           (piece-index (unwrap (read-u32be buffer 14)))
           (bitfield-data (unwrap (slice buffer 14 1)))
           (piece-begin (unwrap (read-u32be buffer 18)))
           (piece-data (unwrap (slice buffer 22 1)))
           (jpc-addrlen (unwrap (read-u32be buffer 22)))
           (jpc-addr (unwrap (slice buffer 22 1)))
           (jpc-session (unwrap (read-u32be buffer 22)))
           )

      (ok (list
        (cons 'msg-len (list (cons 'raw msg-len) (cons 'formatted (number->string msg-len))))
        (cons 'continuous-data (list (cons 'raw continuous-data) (cons 'formatted (fmt-bytes continuous-data))))
        (cons 'msg-type-len (list (cons 'raw msg-type-len) (cons 'formatted (number->string msg-type-len))))
        (cons 'msg-type (list (cons 'raw msg-type) (cons 'formatted (utf8->string msg-type))))
        (cons 'piece-length (list (cons 'raw piece-length) (cons 'formatted (fmt-hex piece-length))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'extended-id (list (cons 'raw extended-id) (cons 'formatted (number->string extended-id))))
        (cons 'extended (list (cons 'raw extended) (cons 'formatted (fmt-bytes extended))))
        (cons 'piece-index (list (cons 'raw piece-index) (cons 'formatted (fmt-hex piece-index))))
        (cons 'bitfield-data (list (cons 'raw bitfield-data) (cons 'formatted (fmt-bytes bitfield-data))))
        (cons 'piece-begin (list (cons 'raw piece-begin) (cons 'formatted (fmt-hex piece-begin))))
        (cons 'piece-data (list (cons 'raw piece-data) (cons 'formatted (fmt-bytes piece-data))))
        (cons 'jpc-addrlen (list (cons 'raw jpc-addrlen) (cons 'formatted (number->string jpc-addrlen))))
        (cons 'jpc-addr (list (cons 'raw jpc-addr) (cons 'formatted (utf8->string jpc-addr))))
        (cons 'jpc-session (list (cons 'raw jpc-session) (cons 'formatted (fmt-hex jpc-session))))
        )))

    (catch (e)
      (err (str "BITTORRENT parse error: " e)))))

;; dissect-bittorrent: parse BITTORRENT from bytevector
;; Returns (ok fields-alist) or (err message)