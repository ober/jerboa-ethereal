;; packet-rip.c
;; Routines for RIPv1 and RIPv2 packet disassembly
;; RFC1058 (STD 34), RFC1388, RFC1723, RFC2453 (STD 56)
;; (c) Copyright Hannes R. Boehm <hannes@boehm.org>
;;
;; RFC2082 ( Keyed Message Digest Algorithm )
;; Emanuele Caratti  <wiz@iol.it>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rip.c
;; RFC 1058

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
(def (dissect-rip buffer)
  "Routing Information Protocol"
  (try
    (let* (
           (route-tag (unwrap (read-u16be buffer 0)))
           (netmask (unwrap (read-u32be buffer 0)))
           (next-hop (unwrap (read-u32be buffer 0)))
           (metric (unwrap (read-u16be buffer 0)))
           (ip (unwrap (read-u32be buffer 0)))
           (auth-passwd (unwrap (slice buffer 0 16)))
           (digest-offset (unwrap (read-u16be buffer 0)))
           (key-id (unwrap (read-u8 buffer 0)))
           (auth-data-len (unwrap (read-u8 buffer 0)))
           (auth-seq-num (unwrap (read-u32be buffer 0)))
           (zero-padding (unwrap (slice buffer 0 8)))
           (routing-domain (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'route-tag (list (cons 'raw route-tag) (cons 'formatted (number->string route-tag))))
        (cons 'netmask (list (cons 'raw netmask) (cons 'formatted (fmt-ipv4 netmask))))
        (cons 'next-hop (list (cons 'raw next-hop) (cons 'formatted (fmt-ipv4 next-hop))))
        (cons 'metric (list (cons 'raw metric) (cons 'formatted (number->string metric))))
        (cons 'ip (list (cons 'raw ip) (cons 'formatted (fmt-ipv4 ip))))
        (cons 'auth-passwd (list (cons 'raw auth-passwd) (cons 'formatted (utf8->string auth-passwd))))
        (cons 'digest-offset (list (cons 'raw digest-offset) (cons 'formatted (number->string digest-offset))))
        (cons 'key-id (list (cons 'raw key-id) (cons 'formatted (number->string key-id))))
        (cons 'auth-data-len (list (cons 'raw auth-data-len) (cons 'formatted (number->string auth-data-len))))
        (cons 'auth-seq-num (list (cons 'raw auth-seq-num) (cons 'formatted (number->string auth-seq-num))))
        (cons 'zero-padding (list (cons 'raw zero-padding) (cons 'formatted (utf8->string zero-padding))))
        (cons 'routing-domain (list (cons 'raw routing-domain) (cons 'formatted (number->string routing-domain))))
        )))

    (catch (e)
      (err (str "RIP parse error: " e)))))

;; dissect-rip: parse RIP from bytevector
;; Returns (ok fields-alist) or (err message)