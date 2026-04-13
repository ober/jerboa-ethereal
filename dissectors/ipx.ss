;; packet-ipx.c
;; Routines for NetWare's IPX
;; Gilbert Ramirez <gram@alumni.rice.edu>
;; NDPS support added by Greg Morris (gmorris@novell.com)
;;
;; Portions Copyright (c) 2000-2002 by Gilbert Ramirez.
;; Portions Copyright (c) Novell, Inc. 2002-2003
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ipx.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ipx.c

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
(def (dissect-ipx buffer)
  "Internetwork Packet eXchange"
  (try
    (let* (
           (number (unwrap (slice buffer 0 6)))
           (response (unwrap (read-u8 buffer 0)))
           (request (unwrap (read-u8 buffer 0)))
           (conn (unwrap (read-u8 buffer 0)))
           (rexmt-frame (unwrap (read-u32be buffer 0)))
           (dst (unwrap (slice buffer 0 1)))
           (addr (unwrap (slice buffer 0 1)))
           (src (unwrap (slice buffer 0 1)))
           (datastream-type (unwrap (read-u8 buffer 1)))
           (src-id (unwrap (read-u16be buffer 2)))
           (dst-id (unwrap (read-u16be buffer 4)))
           (hops (unwrap (read-u8 buffer 4)))
           (seq-nr (unwrap (read-u16be buffer 6)))
           (ack-nr (unwrap (read-u16be buffer 8)))
           (all-nr (unwrap (read-u16be buffer 10)))
           (node (unwrap (slice buffer 10 6)))
           (dnode (unwrap (slice buffer 10 6)))
           (neg-size (unwrap (read-u16be buffer 12)))
           (snode (unwrap (slice buffer 22 6)))
           )

      (ok (list
        (cons 'number (list (cons 'raw number) (cons 'formatted (fmt-bytes number))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (number->string response))))
        (cons 'request (list (cons 'raw request) (cons 'formatted (number->string request))))
        (cons 'conn (list (cons 'raw conn) (cons 'formatted (number->string conn))))
        (cons 'rexmt-frame (list (cons 'raw rexmt-frame) (cons 'formatted (number->string rexmt-frame))))
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (utf8->string dst))))
        (cons 'addr (list (cons 'raw addr) (cons 'formatted (utf8->string addr))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (utf8->string src))))
        (cons 'datastream-type (list (cons 'raw datastream-type) (cons 'formatted (fmt-hex datastream-type))))
        (cons 'src-id (list (cons 'raw src-id) (cons 'formatted (number->string src-id))))
        (cons 'dst-id (list (cons 'raw dst-id) (cons 'formatted (number->string dst-id))))
        (cons 'hops (list (cons 'raw hops) (cons 'formatted (number->string hops))))
        (cons 'seq-nr (list (cons 'raw seq-nr) (cons 'formatted (number->string seq-nr))))
        (cons 'ack-nr (list (cons 'raw ack-nr) (cons 'formatted (number->string ack-nr))))
        (cons 'all-nr (list (cons 'raw all-nr) (cons 'formatted (number->string all-nr))))
        (cons 'node (list (cons 'raw node) (cons 'formatted (fmt-mac node))))
        (cons 'dnode (list (cons 'raw dnode) (cons 'formatted (fmt-mac dnode))))
        (cons 'neg-size (list (cons 'raw neg-size) (cons 'formatted (number->string neg-size))))
        (cons 'snode (list (cons 'raw snode) (cons 'formatted (fmt-mac snode))))
        )))

    (catch (e)
      (err (str "IPX parse error: " e)))))

;; dissect-ipx: parse IPX from bytevector
;; Returns (ok fields-alist) or (err message)