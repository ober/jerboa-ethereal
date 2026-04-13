;; packet-jpeg.c
;;
;; Routines for RFC 2435 JPEG dissection
;;
;; Copyright 2006
;; Erwin Rol <erwin@erwinrol.com>
;; Copyright 2001,
;; Francisco Javier Cabello Torres, <fjcabello@vtools.es>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/jpeg.ss
;; Auto-generated from wireshark/epan/dissectors/packet-jpeg.c
;; RFC 2435

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
(def (dissect-jpeg buffer)
  "RFC 2435 JPEG"
  (try
    (let* (
           (jpeg-main-hdr-offs (unwrap (read-u24be buffer 1)))
           (jpeg-main-hdr-q (unwrap (read-u8 buffer 5)))
           (jpeg-main-hdr-width (unwrap (read-u8 buffer 6)))
           (jpeg-main-hdr-height (unwrap (read-u8 buffer 7)))
           (jpeg-restart-hdr-interval (unwrap (read-u16be buffer 8)))
           (jpeg-restart-hdr-f (unwrap (read-u16be buffer 10)))
           (jpeg-restart-hdr-l (unwrap (read-u16be buffer 10)))
           (jpeg-restart-hdr-count (unwrap (read-u16be buffer 10)))
           (jpeg-qtable-hdr-mbz (unwrap (read-u8 buffer 12)))
           (jpeg-qtable-hdr-prec (unwrap (read-u8 buffer 13)))
           (jpeg-qtable-hdr-length (unwrap (read-u16be buffer 14)))
           (jpeg-qtable-hdr-data (unwrap (slice buffer 16 1)))
           (jpeg-payload (unwrap (slice buffer 16 1)))
           )

      (ok (list
        (cons 'jpeg-main-hdr-offs (list (cons 'raw jpeg-main-hdr-offs) (cons 'formatted (number->string jpeg-main-hdr-offs))))
        (cons 'jpeg-main-hdr-q (list (cons 'raw jpeg-main-hdr-q) (cons 'formatted (number->string jpeg-main-hdr-q))))
        (cons 'jpeg-main-hdr-width (list (cons 'raw jpeg-main-hdr-width) (cons 'formatted (number->string jpeg-main-hdr-width))))
        (cons 'jpeg-main-hdr-height (list (cons 'raw jpeg-main-hdr-height) (cons 'formatted (number->string jpeg-main-hdr-height))))
        (cons 'jpeg-restart-hdr-interval (list (cons 'raw jpeg-restart-hdr-interval) (cons 'formatted (number->string jpeg-restart-hdr-interval))))
        (cons 'jpeg-restart-hdr-f (list (cons 'raw jpeg-restart-hdr-f) (cons 'formatted (number->string jpeg-restart-hdr-f))))
        (cons 'jpeg-restart-hdr-l (list (cons 'raw jpeg-restart-hdr-l) (cons 'formatted (number->string jpeg-restart-hdr-l))))
        (cons 'jpeg-restart-hdr-count (list (cons 'raw jpeg-restart-hdr-count) (cons 'formatted (number->string jpeg-restart-hdr-count))))
        (cons 'jpeg-qtable-hdr-mbz (list (cons 'raw jpeg-qtable-hdr-mbz) (cons 'formatted (number->string jpeg-qtable-hdr-mbz))))
        (cons 'jpeg-qtable-hdr-prec (list (cons 'raw jpeg-qtable-hdr-prec) (cons 'formatted (number->string jpeg-qtable-hdr-prec))))
        (cons 'jpeg-qtable-hdr-length (list (cons 'raw jpeg-qtable-hdr-length) (cons 'formatted (number->string jpeg-qtable-hdr-length))))
        (cons 'jpeg-qtable-hdr-data (list (cons 'raw jpeg-qtable-hdr-data) (cons 'formatted (fmt-bytes jpeg-qtable-hdr-data))))
        (cons 'jpeg-payload (list (cons 'raw jpeg-payload) (cons 'formatted (fmt-bytes jpeg-payload))))
        )))

    (catch (e)
      (err (str "JPEG parse error: " e)))))

;; dissect-jpeg: parse JPEG from bytevector
;; Returns (ok fields-alist) or (err message)