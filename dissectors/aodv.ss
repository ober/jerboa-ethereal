;; packet-aodv.c
;; Routines for AODV dissection
;; Copyright 2000, Erik Nordstrom <erik.nordstrom@it.uu.se>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/aodv.ss
;; Auto-generated from wireshark/epan/dissectors/packet-aodv.c
;; RFC 3561

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
(def (dissect-aodv buffer)
  "Ad hoc On-demand Distance Vector Routing Protocol"
  (try
    (let* (
           (flags (unwrap (read-u16be buffer 1)))
           (flags-rerr-nodelete (extract-bits flags 0x0 0))
           (ext-interval (unwrap (read-u32be buffer 2)))
           (ext-timestamp (unwrap (read-u64be buffer 2)))
           (prefix-sz (unwrap (read-u8 buffer 2)))
           (hopcount (unwrap (read-u8 buffer 3)))
           (destcount (unwrap (read-u8 buffer 3)))
           (rreq-id (unwrap (read-u32be buffer 4)))
           (dest-ip (unwrap (read-u32be buffer 4)))
           (dest-seqno (unwrap (read-u32be buffer 4)))
           (unreach-dest-ip (unwrap (read-u32be buffer 8)))
           (orig-ipv6 (unwrap (slice buffer 8 16)))
           (lifetime (unwrap (read-u32be buffer 8)))
           (unreach-dest-ipv6 (unwrap (slice buffer 8 16)))
           (orig-ip (unwrap (read-u32be buffer 12)))
           (orig-seqno (unwrap (read-u32be buffer 12)))
           (dest-ipv6 (unwrap (slice buffer 16 16)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (number->string flags))))
        (cons 'flags-rerr-nodelete (list (cons 'raw flags-rerr-nodelete) (cons 'formatted (if (= flags-rerr-nodelete 0) "Not set" "Set"))))
        (cons 'ext-interval (list (cons 'raw ext-interval) (cons 'formatted (number->string ext-interval))))
        (cons 'ext-timestamp (list (cons 'raw ext-timestamp) (cons 'formatted (number->string ext-timestamp))))
        (cons 'prefix-sz (list (cons 'raw prefix-sz) (cons 'formatted (number->string prefix-sz))))
        (cons 'hopcount (list (cons 'raw hopcount) (cons 'formatted (number->string hopcount))))
        (cons 'destcount (list (cons 'raw destcount) (cons 'formatted (number->string destcount))))
        (cons 'rreq-id (list (cons 'raw rreq-id) (cons 'formatted (number->string rreq-id))))
        (cons 'dest-ip (list (cons 'raw dest-ip) (cons 'formatted (fmt-ipv4 dest-ip))))
        (cons 'dest-seqno (list (cons 'raw dest-seqno) (cons 'formatted (number->string dest-seqno))))
        (cons 'unreach-dest-ip (list (cons 'raw unreach-dest-ip) (cons 'formatted (fmt-ipv4 unreach-dest-ip))))
        (cons 'orig-ipv6 (list (cons 'raw orig-ipv6) (cons 'formatted (fmt-ipv6-address orig-ipv6))))
        (cons 'lifetime (list (cons 'raw lifetime) (cons 'formatted (number->string lifetime))))
        (cons 'unreach-dest-ipv6 (list (cons 'raw unreach-dest-ipv6) (cons 'formatted (fmt-ipv6-address unreach-dest-ipv6))))
        (cons 'orig-ip (list (cons 'raw orig-ip) (cons 'formatted (fmt-ipv4 orig-ip))))
        (cons 'orig-seqno (list (cons 'raw orig-seqno) (cons 'formatted (number->string orig-seqno))))
        (cons 'dest-ipv6 (list (cons 'raw dest-ipv6) (cons 'formatted (fmt-ipv6-address dest-ipv6))))
        )))

    (catch (e)
      (err (str "AODV parse error: " e)))))

;; dissect-aodv: parse AODV from bytevector
;; Returns (ok fields-alist) or (err message)