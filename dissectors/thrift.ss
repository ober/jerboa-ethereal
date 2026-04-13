;; packet-thrift.c
;; Routines for thrift protocol dissection.
;; Based on work by John Song <jsong@facebook.com> and
;; Bill Fumerola <bill@facebook.com>
;;
;; https://github.com/andrewcox/wireshark-with-thrift-plugin/blob/wireshark-1.8.6-with-thrift-plugin/plugins/thrift/packet-thrift.cpp
;;
;; Copyright 2015, Anders Broman <anders.broman[at]ericsson.com>
;; Copyright 2021, Richard van der Hoff <richard[at]matrix.org>
;; Copyright 2019-2024, Triton Circonflexe <triton[at]kumal.info>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/thrift.ss
;; Auto-generated from wireshark/epan/dissectors/packet-thrift.c

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
(def (dissect-thrift buffer)
  "Thrift Protocol"
  (try
    (let* (
           (u64 (unwrap (read-u64be buffer 0)))
           (str-len (unwrap (read-u32be buffer 0)))
           (i64 (unwrap (read-u64be buffer 0)))
           (frame-length (unwrap (read-u32be buffer 0)))
           (seq-id (unwrap (read-u32be buffer 0)))
           (method (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'u64 (list (cons 'raw u64) (cons 'formatted (number->string u64))))
        (cons 'str-len (list (cons 'raw str-len) (cons 'formatted (number->string str-len))))
        (cons 'i64 (list (cons 'raw i64) (cons 'formatted (number->string i64))))
        (cons 'frame-length (list (cons 'raw frame-length) (cons 'formatted (number->string frame-length))))
        (cons 'seq-id (list (cons 'raw seq-id) (cons 'formatted (number->string seq-id))))
        (cons 'method (list (cons 'raw method) (cons 'formatted (utf8->string method))))
        )))

    (catch (e)
      (err (str "THRIFT parse error: " e)))))

;; dissect-thrift: parse THRIFT from bytevector
;; Returns (ok fields-alist) or (err message)