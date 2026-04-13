;; packet-mgcp.c
;; Routines for mgcp packet disassembly
;; RFC 2705
;; RFC 3435 (obsoletes 2705): Media Gateway Control Protocol (MGCP) Version 1.0
;; RFC 3660: Basic MGCP Packages
;; RFC 3661: MGCP Return Code Usage
;; NCS 1.0: PacketCable Network-Based Call Signaling Protocol Specification,
;; PKT-SP-EC-MGCP-I09-040113, January 13, 2004, Cable Television
;; Laboratories, Inc., http://www.PacketCable.com/
;; NCS 1.5: PKT-SP-NCS1.5-I04-120412, April 12, 2012 Cable Television
;; Laboratories, Inc., http://www.PacketCable.com/
;; www.iana.org/assignments/mgcp-localconnectionoptions
;;
;; Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
;; Copyright (c) 2004 by Thomas Anders <thomas.anders [AT] blue-cable.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mgcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mgcp.c
;; RFC 2705

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
(def (dissect-mgcp buffer)
  "Media Gateway Control Protocol"
  (try
    (let* (
           (req-dup-frame (unwrap (read-u32be buffer 0)))
           (req-dup (unwrap (read-u32be buffer 0)))
           (req (unwrap (read-u8 buffer 0)))
           (rsp-dup-frame (unwrap (read-u32be buffer 0)))
           (rsp-dup (unwrap (read-u32be buffer 0)))
           (dup (unwrap (read-u32be buffer 0)))
           (rsp (unwrap (read-u8 buffer 0)))
           (messagecount (unwrap (read-u32be buffer 0)))
           (param-connectionparam (unwrap (slice buffer 7 1)))
           (param-localconnoptions (unwrap (slice buffer 7 1)))
           (param-localvoicemetrics (unwrap (slice buffer 7 1)))
           (param-remotevoicemetrics (unwrap (slice buffer 16 1)))
           (unknown-parameter (unwrap (slice buffer 25 1)))
           (malformed-parameter (unwrap (slice buffer 25 1)))
           )

      (ok (list
        (cons 'req-dup-frame (list (cons 'raw req-dup-frame) (cons 'formatted (number->string req-dup-frame))))
        (cons 'req-dup (list (cons 'raw req-dup) (cons 'formatted (number->string req-dup))))
        (cons 'req (list (cons 'raw req) (cons 'formatted (number->string req))))
        (cons 'rsp-dup-frame (list (cons 'raw rsp-dup-frame) (cons 'formatted (number->string rsp-dup-frame))))
        (cons 'rsp-dup (list (cons 'raw rsp-dup) (cons 'formatted (number->string rsp-dup))))
        (cons 'dup (list (cons 'raw dup) (cons 'formatted (number->string dup))))
        (cons 'rsp (list (cons 'raw rsp) (cons 'formatted (number->string rsp))))
        (cons 'messagecount (list (cons 'raw messagecount) (cons 'formatted (number->string messagecount))))
        (cons 'param-connectionparam (list (cons 'raw param-connectionparam) (cons 'formatted (utf8->string param-connectionparam))))
        (cons 'param-localconnoptions (list (cons 'raw param-localconnoptions) (cons 'formatted (utf8->string param-localconnoptions))))
        (cons 'param-localvoicemetrics (list (cons 'raw param-localvoicemetrics) (cons 'formatted (utf8->string param-localvoicemetrics))))
        (cons 'param-remotevoicemetrics (list (cons 'raw param-remotevoicemetrics) (cons 'formatted (utf8->string param-remotevoicemetrics))))
        (cons 'unknown-parameter (list (cons 'raw unknown-parameter) (cons 'formatted (utf8->string unknown-parameter))))
        (cons 'malformed-parameter (list (cons 'raw malformed-parameter) (cons 'formatted (utf8->string malformed-parameter))))
        )))

    (catch (e)
      (err (str "MGCP parse error: " e)))))

;; dissect-mgcp: parse MGCP from bytevector
;; Returns (ok fields-alist) or (err message)