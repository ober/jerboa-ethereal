;; packet-carp.c
;; Routines for the Common Address Redundancy Protocol (CARP)
;; Copyright 2013, Uli Heilmeier <uh@heilmeier.eu>
;; Based on packet-vrrp.c by Heikki Vatiainen <hessu@cs.tut.fi>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/carp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-carp.c

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
(def (dissect-carp buffer)
  "Common Address Redundancy Protocol"
  (try
    (let* (
           (ver-type (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (vhid (unwrap (read-u8 buffer 0)))
           (advskew (unwrap (read-u8 buffer 0)))
           (authlen (unwrap (read-u8 buffer 0)))
           (demotion (unwrap (read-u8 buffer 0)))
           (advbase (unwrap (read-u8 buffer 0)))
           (counter (unwrap (read-u64be buffer 2)))
           (hmac (unwrap (slice buffer 10 20)))
           )

      (ok (list
        (cons 'ver-type (list (cons 'raw ver-type) (cons 'formatted (number->string ver-type))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'vhid (list (cons 'raw vhid) (cons 'formatted (number->string vhid))))
        (cons 'advskew (list (cons 'raw advskew) (cons 'formatted (number->string advskew))))
        (cons 'authlen (list (cons 'raw authlen) (cons 'formatted (number->string authlen))))
        (cons 'demotion (list (cons 'raw demotion) (cons 'formatted (number->string demotion))))
        (cons 'advbase (list (cons 'raw advbase) (cons 'formatted (number->string advbase))))
        (cons 'counter (list (cons 'raw counter) (cons 'formatted (number->string counter))))
        (cons 'hmac (list (cons 'raw hmac) (cons 'formatted (fmt-bytes hmac))))
        )))

    (catch (e)
      (err (str "CARP parse error: " e)))))

;; dissect-carp: parse CARP from bytevector
;; Returns (ok fields-alist) or (err message)