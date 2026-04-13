;; packet-netsync.c
;; Routines for Monotone Netsync packet disassembly
;;
;; Copyright (c) 2005 by Erwin Rol <erwin@erwinrol.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netsync.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netsync.c

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
(def (dissect-netsync buffer)
  "Monotone Netsync"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (cmd-nonce (unwrap (slice buffer 1 1)))
           (cmd-auth-id (unwrap (slice buffer 2 1)))
           (cmd-auth-nonce1 (unwrap (slice buffer 2 1)))
           (cmd-auth-nonce2 (unwrap (slice buffer 2 1)))
           (cmd-refine-tree-node (unwrap (slice buffer 2 1)))
           (cmd-done-level (unwrap (read-u32be buffer 2)))
           (cmd-done-type (unwrap (read-u8 buffer 2)))
           (size (unwrap (read-u32be buffer 2)))
           (data (unwrap (slice buffer 2 1)))
           (cmd-send-data-type (unwrap (read-u8 buffer 3)))
           (cmd-send-data-id (unwrap (slice buffer 4 1)))
           (cmd-send-delta-type (unwrap (read-u8 buffer 4)))
           (cmd-send-delta-base-id (unwrap (slice buffer 5 1)))
           (cmd-send-delta-ident-id (unwrap (slice buffer 5 1)))
           (cmd-data-type (unwrap (read-u8 buffer 5)))
           (cmd-data-id (unwrap (slice buffer 6 1)))
           (cmd-data-compressed (unwrap (read-u8 buffer 6)))
           (cmd-delta-type (unwrap (read-u8 buffer 7)))
           (cmd-delta-base-id (unwrap (slice buffer 8 1)))
           (cmd-delta-ident-id (unwrap (slice buffer 8 1)))
           (cmd-delta-compressed (unwrap (read-u8 buffer 8)))
           (cmd-nonexistent-type (unwrap (read-u8 buffer 9)))
           (cmd-nonexistent-id (unwrap (slice buffer 10 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'cmd-nonce (list (cons 'raw cmd-nonce) (cons 'formatted (fmt-bytes cmd-nonce))))
        (cons 'cmd-auth-id (list (cons 'raw cmd-auth-id) (cons 'formatted (fmt-bytes cmd-auth-id))))
        (cons 'cmd-auth-nonce1 (list (cons 'raw cmd-auth-nonce1) (cons 'formatted (fmt-bytes cmd-auth-nonce1))))
        (cons 'cmd-auth-nonce2 (list (cons 'raw cmd-auth-nonce2) (cons 'formatted (fmt-bytes cmd-auth-nonce2))))
        (cons 'cmd-refine-tree-node (list (cons 'raw cmd-refine-tree-node) (cons 'formatted (fmt-bytes cmd-refine-tree-node))))
        (cons 'cmd-done-level (list (cons 'raw cmd-done-level) (cons 'formatted (number->string cmd-done-level))))
        (cons 'cmd-done-type (list (cons 'raw cmd-done-type) (cons 'formatted (number->string cmd-done-type))))
        (cons 'size (list (cons 'raw size) (cons 'formatted (number->string size))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'cmd-send-data-type (list (cons 'raw cmd-send-data-type) (cons 'formatted (number->string cmd-send-data-type))))
        (cons 'cmd-send-data-id (list (cons 'raw cmd-send-data-id) (cons 'formatted (fmt-bytes cmd-send-data-id))))
        (cons 'cmd-send-delta-type (list (cons 'raw cmd-send-delta-type) (cons 'formatted (number->string cmd-send-delta-type))))
        (cons 'cmd-send-delta-base-id (list (cons 'raw cmd-send-delta-base-id) (cons 'formatted (fmt-bytes cmd-send-delta-base-id))))
        (cons 'cmd-send-delta-ident-id (list (cons 'raw cmd-send-delta-ident-id) (cons 'formatted (fmt-bytes cmd-send-delta-ident-id))))
        (cons 'cmd-data-type (list (cons 'raw cmd-data-type) (cons 'formatted (number->string cmd-data-type))))
        (cons 'cmd-data-id (list (cons 'raw cmd-data-id) (cons 'formatted (fmt-bytes cmd-data-id))))
        (cons 'cmd-data-compressed (list (cons 'raw cmd-data-compressed) (cons 'formatted (number->string cmd-data-compressed))))
        (cons 'cmd-delta-type (list (cons 'raw cmd-delta-type) (cons 'formatted (number->string cmd-delta-type))))
        (cons 'cmd-delta-base-id (list (cons 'raw cmd-delta-base-id) (cons 'formatted (fmt-bytes cmd-delta-base-id))))
        (cons 'cmd-delta-ident-id (list (cons 'raw cmd-delta-ident-id) (cons 'formatted (fmt-bytes cmd-delta-ident-id))))
        (cons 'cmd-delta-compressed (list (cons 'raw cmd-delta-compressed) (cons 'formatted (number->string cmd-delta-compressed))))
        (cons 'cmd-nonexistent-type (list (cons 'raw cmd-nonexistent-type) (cons 'formatted (number->string cmd-nonexistent-type))))
        (cons 'cmd-nonexistent-id (list (cons 'raw cmd-nonexistent-id) (cons 'formatted (fmt-bytes cmd-nonexistent-id))))
        )))

    (catch (e)
      (err (str "NETSYNC parse error: " e)))))

;; dissect-netsync: parse NETSYNC from bytevector
;; Returns (ok fields-alist) or (err message)