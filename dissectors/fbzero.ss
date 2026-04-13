;; packet-fbzero.c
;; Routines for Zero Protocol dissection
;; Copyright 2016-2017, Alexis La Goutte <alexis.lagoutte at gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fbzero.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fbzero.c

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
(def (dissect-fbzero buffer)
  "(Facebook) Zero Protocol"
  (try
    (let* (
           (zero-tag-type (unwrap (slice buffer 0 4)))
           (zero-puflags (unwrap (read-u8 buffer 0)))
           (zero-puflags-vrsn (unwrap (read-u8 buffer 0)))
           (zero-puflags-unknown (unwrap (read-u8 buffer 0)))
           (zero-version (unwrap (slice buffer 1 3)))
           (zero-tag-offset-end (unwrap (read-u32be buffer 4)))
           (zero-tag-length (unwrap (read-u32be buffer 4)))
           (zero-payload (unwrap (slice buffer 4 1)))
           (zero-length (unwrap (read-u32be buffer 66)))
           (zero-tag (unwrap (slice buffer 70 4)))
           (zero-tag-number (unwrap (read-u16be buffer 74)))
           (zero-padding (unwrap (slice buffer 76 2)))
           (zero-unknown (unwrap (slice buffer 78 1)))
           )

      (ok (list
        (cons 'zero-tag-type (list (cons 'raw zero-tag-type) (cons 'formatted (utf8->string zero-tag-type))))
        (cons 'zero-puflags (list (cons 'raw zero-puflags) (cons 'formatted (fmt-hex zero-puflags))))
        (cons 'zero-puflags-vrsn (list (cons 'raw zero-puflags-vrsn) (cons 'formatted (if (= zero-puflags-vrsn 0) "False" "True"))))
        (cons 'zero-puflags-unknown (list (cons 'raw zero-puflags-unknown) (cons 'formatted (fmt-hex zero-puflags-unknown))))
        (cons 'zero-version (list (cons 'raw zero-version) (cons 'formatted (utf8->string zero-version))))
        (cons 'zero-tag-offset-end (list (cons 'raw zero-tag-offset-end) (cons 'formatted (number->string zero-tag-offset-end))))
        (cons 'zero-tag-length (list (cons 'raw zero-tag-length) (cons 'formatted (number->string zero-tag-length))))
        (cons 'zero-payload (list (cons 'raw zero-payload) (cons 'formatted (fmt-bytes zero-payload))))
        (cons 'zero-length (list (cons 'raw zero-length) (cons 'formatted (number->string zero-length))))
        (cons 'zero-tag (list (cons 'raw zero-tag) (cons 'formatted (utf8->string zero-tag))))
        (cons 'zero-tag-number (list (cons 'raw zero-tag-number) (cons 'formatted (number->string zero-tag-number))))
        (cons 'zero-padding (list (cons 'raw zero-padding) (cons 'formatted (fmt-bytes zero-padding))))
        (cons 'zero-unknown (list (cons 'raw zero-unknown) (cons 'formatted (fmt-bytes zero-unknown))))
        )))

    (catch (e)
      (err (str "FBZERO parse error: " e)))))

;; dissect-fbzero: parse FBZERO from bytevector
;; Returns (ok fields-alist) or (err message)