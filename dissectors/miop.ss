;; packet-miop.c
;; Routines for CORBA MIOP packet disassembly
;; Significantly based on packet-giop.c
;; Copyright 2009 Alvaro Vega Garcia <avega at tid dot es>
;;
;; According with Unreliable Multicast Draft Adopted Specification
;; 2001 October (OMG)
;; Chapter 29: Unreliable Multicast Inter-ORB Protocol (MIOP)
;; http://www.omg.org/technology/documents/specialized_corba.htm
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/miop.ss
;; Auto-generated from wireshark/epan/dissectors/packet-miop.c

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
(def (dissect-miop buffer)
  "Unreliable Multicast Inter-ORB Protocol"
  (try
    (let* (
           (magic (unwrap (slice buffer 0 4)))
           (hdr-version (unwrap (read-u8 buffer 4)))
           (flags (unwrap (read-u8 buffer 4)))
           (packet-length (unwrap (read-u16be buffer 4)))
           (packet-number (unwrap (read-u32be buffer 6)))
           (number-of-packets (unwrap (read-u32be buffer 10)))
           (unique-id-len (unwrap (read-u32be buffer 14)))
           (unique-id (unwrap (slice buffer 18 1)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (utf8->string magic))))
        (cons 'hdr-version (list (cons 'raw hdr-version) (cons 'formatted (fmt-hex hdr-version))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-oct flags))))
        (cons 'packet-length (list (cons 'raw packet-length) (cons 'formatted (number->string packet-length))))
        (cons 'packet-number (list (cons 'raw packet-number) (cons 'formatted (number->string packet-number))))
        (cons 'number-of-packets (list (cons 'raw number-of-packets) (cons 'formatted (number->string number-of-packets))))
        (cons 'unique-id-len (list (cons 'raw unique-id-len) (cons 'formatted (number->string unique-id-len))))
        (cons 'unique-id (list (cons 'raw unique-id) (cons 'formatted (fmt-bytes unique-id))))
        )))

    (catch (e)
      (err (str "MIOP parse error: " e)))))

;; dissect-miop: parse MIOP from bytevector
;; Returns (ok fields-alist) or (err message)