;; packet-hip.c
;; Definitions and routines for HIP control packet disassembly
;; Samu Varjonen <samu.varjonen@hiit.fi>
;;
;; Based on dissector originally created by
;; Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
;; Thomas Henderson <thomas.r.henderson@boeing.com>
;; Samu Varjonen <samu.varjonen@hiit.fi>
;; Thomas Jansen <mithi@mithi.net>
;;
;; Packet dissector for Host Identity Protocol (HIP) packets.
;; This tool displays the TLV structure, verifies checksums,
;; and shows NULL encrypted parameters, but will not verify
;; signatures or decode encrypted parameters.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hip.c
;; RFC 5201

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
(def (dissect-hip buffer)
  "Host Identity Protocol"
  (try
    (let* (
           (proto (unwrap (read-u8 buffer 2)))
           (hdr-len (unwrap (read-u8 buffer 2)))
           (shim6-fixed-bit-p (unwrap (read-u8 buffer 2)))
           (packet-type (unwrap (read-u8 buffer 2)))
           (version (unwrap (read-u8 buffer 2)))
           (shim6-fixed-bit-s (unwrap (read-u8 buffer 2)))
           (controls (unwrap (read-u16be buffer 2)))
           (controls-anon (unwrap (read-u8 buffer 2)))
           (hit-sndr (unwrap (slice buffer 10 16)))
           (hit-rcvr (unwrap (slice buffer 26 16)))
           (type (unwrap (read-u16be buffer 42)))
           (tlv-hmac (unwrap (slice buffer 194 1)))
           )

      (ok (list
        (cons 'proto (list (cons 'raw proto) (cons 'formatted (number->string proto))))
        (cons 'hdr-len (list (cons 'raw hdr-len) (cons 'formatted (number->string hdr-len))))
        (cons 'shim6-fixed-bit-p (list (cons 'raw shim6-fixed-bit-p) (cons 'formatted (number->string shim6-fixed-bit-p))))
        (cons 'packet-type (list (cons 'raw packet-type) (cons 'formatted (number->string packet-type))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'shim6-fixed-bit-s (list (cons 'raw shim6-fixed-bit-s) (cons 'formatted (number->string shim6-fixed-bit-s))))
        (cons 'controls (list (cons 'raw controls) (cons 'formatted (fmt-hex controls))))
        (cons 'controls-anon (list (cons 'raw controls-anon) (cons 'formatted (number->string controls-anon))))
        (cons 'hit-sndr (list (cons 'raw hit-sndr) (cons 'formatted (fmt-bytes hit-sndr))))
        (cons 'hit-rcvr (list (cons 'raw hit-rcvr) (cons 'formatted (fmt-bytes hit-rcvr))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (number->string type))))
        (cons 'tlv-hmac (list (cons 'raw tlv-hmac) (cons 'formatted (fmt-bytes tlv-hmac))))
        )))

    (catch (e)
      (err (str "HIP parse error: " e)))))

;; dissect-hip: parse HIP from bytevector
;; Returns (ok fields-alist) or (err message)