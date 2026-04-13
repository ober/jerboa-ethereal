;; packet-lisp-data.c
;; Routines for LISP Data Message dissection
;; Copyright 2010, Lorand Jakab <lj@lispmon.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lisp-data.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lisp_data.c
;; RFC 6830

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
(def (dissect-lisp-data buffer)
  "Locator/ID Separation Protocol (Data)"
  (try
    (let* (
           (data-flags (unwrap (read-u8 buffer 0)))
           (data-flags-res (unwrap (read-u8 buffer 0)))
           (data-nonce (unwrap (read-u24be buffer 1)))
           (data-mapver (unwrap (read-u24be buffer 1)))
           (data-srcmapver (unwrap (read-u24be buffer 1)))
           (data-dstmapver (unwrap (read-u24be buffer 1)))
           (data-iid (unwrap (read-u24be buffer 4)))
           (data-lsb8 (unwrap (read-u8 buffer 7)))
           (data-lsb (unwrap (read-u32be buffer 8)))
           )

      (ok (list
        (cons 'data-flags (list (cons 'raw data-flags) (cons 'formatted (fmt-hex data-flags))))
        (cons 'data-flags-res (list (cons 'raw data-flags-res) (cons 'formatted (fmt-hex data-flags-res))))
        (cons 'data-nonce (list (cons 'raw data-nonce) (cons 'formatted (number->string data-nonce))))
        (cons 'data-mapver (list (cons 'raw data-mapver) (cons 'formatted (fmt-hex data-mapver))))
        (cons 'data-srcmapver (list (cons 'raw data-srcmapver) (cons 'formatted (number->string data-srcmapver))))
        (cons 'data-dstmapver (list (cons 'raw data-dstmapver) (cons 'formatted (number->string data-dstmapver))))
        (cons 'data-iid (list (cons 'raw data-iid) (cons 'formatted (number->string data-iid))))
        (cons 'data-lsb8 (list (cons 'raw data-lsb8) (cons 'formatted (fmt-hex data-lsb8))))
        (cons 'data-lsb (list (cons 'raw data-lsb) (cons 'formatted (fmt-hex data-lsb))))
        )))

    (catch (e)
      (err (str "LISP-DATA parse error: " e)))))

;; dissect-lisp-data: parse LISP-DATA from bytevector
;; Returns (ok fields-alist) or (err message)