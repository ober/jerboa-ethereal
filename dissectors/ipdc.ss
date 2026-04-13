;; packet-ipdc.c
;; Routines for IP Device Control (SS7 over IP) dissection
;; Copyright Lucent Technologies 2004
;; Josh Bailey <joshbailey@lucent.com> and Ruud Linders <ruud@lucent.com>
;;
;; Using IPDC spec 0.20.2
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ipdc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ipdc.c

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
(def (dissect-ipdc buffer)
  "IP Device Control (SS7 over IP)"
  (try
    (let* (
           (nr (unwrap (read-u8 buffer 0)))
           (ns (unwrap (read-u8 buffer 1)))
           (payload-len (unwrap (read-u16be buffer 2)))
           (protocol-id (unwrap (read-u8 buffer 4)))
           (trans-id-size (unwrap (read-u8 buffer 5)))
           (trans-id (unwrap (slice buffer 6 1)))
           (ascii (unwrap (slice buffer 6 1)))
           (uint (unwrap (read-u32be buffer 6)))
           (ipv4 (unwrap (read-u32be buffer 6)))
           (enctype (unwrap (read-u16be buffer 6)))
           (type-unknown (unwrap (slice buffer 6 1)))
           )

      (ok (list
        (cons 'nr (list (cons 'raw nr) (cons 'formatted (number->string nr))))
        (cons 'ns (list (cons 'raw ns) (cons 'formatted (number->string ns))))
        (cons 'payload-len (list (cons 'raw payload-len) (cons 'formatted (number->string payload-len))))
        (cons 'protocol-id (list (cons 'raw protocol-id) (cons 'formatted (fmt-hex protocol-id))))
        (cons 'trans-id-size (list (cons 'raw trans-id-size) (cons 'formatted (number->string trans-id-size))))
        (cons 'trans-id (list (cons 'raw trans-id) (cons 'formatted (fmt-bytes trans-id))))
        (cons 'ascii (list (cons 'raw ascii) (cons 'formatted (utf8->string ascii))))
        (cons 'uint (list (cons 'raw uint) (cons 'formatted (number->string uint))))
        (cons 'ipv4 (list (cons 'raw ipv4) (cons 'formatted (fmt-ipv4 ipv4))))
        (cons 'enctype (list (cons 'raw enctype) (cons 'formatted (number->string enctype))))
        (cons 'type-unknown (list (cons 'raw type-unknown) (cons 'formatted (fmt-bytes type-unknown))))
        )))

    (catch (e)
      (err (str "IPDC parse error: " e)))))

;; dissect-ipdc: parse IPDC from bytevector
;; Returns (ok fields-alist) or (err message)