;; packet-id3v2.c
;; Routines for ID3v2 dissection
;; Copyright 2022, Jeff Morriss <jeff.morriss.ws [AT] gmai.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/id3v2.ss
;; Auto-generated from wireshark/epan/dissectors/packet-id3v2.c

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
(def (dissect-id3v2 buffer)
  "ID3v2"
  (try
    (let* (
           (frame-comment-language (unwrap (slice buffer 1 3)))
           (padding (unwrap (slice buffer 7 1)))
           (frame-id (unwrap (slice buffer 7 4)))
           (frame-size (unwrap (read-u8 buffer 11)))
           (frame-flags (unwrap (read-u16be buffer 15)))
           (frame-ufi-owner (unwrap (slice buffer 17 1)))
           (frame-ufi-id (unwrap (slice buffer 17 1)))
           (frame-private (unwrap (slice buffer 17 1)))
           (undecoded (unwrap (slice buffer 17 1)))
           )

      (ok (list
        (cons 'frame-comment-language (list (cons 'raw frame-comment-language) (cons 'formatted (utf8->string frame-comment-language))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'frame-id (list (cons 'raw frame-id) (cons 'formatted (utf8->string frame-id))))
        (cons 'frame-size (list (cons 'raw frame-size) (cons 'formatted (number->string frame-size))))
        (cons 'frame-flags (list (cons 'raw frame-flags) (cons 'formatted (fmt-hex frame-flags))))
        (cons 'frame-ufi-owner (list (cons 'raw frame-ufi-owner) (cons 'formatted (utf8->string frame-ufi-owner))))
        (cons 'frame-ufi-id (list (cons 'raw frame-ufi-id) (cons 'formatted (fmt-bytes frame-ufi-id))))
        (cons 'frame-private (list (cons 'raw frame-private) (cons 'formatted (fmt-bytes frame-private))))
        (cons 'undecoded (list (cons 'raw undecoded) (cons 'formatted (fmt-bytes undecoded))))
        )))

    (catch (e)
      (err (str "ID3V2 parse error: " e)))))

;; dissect-id3v2: parse ID3V2 from bytevector
;; Returns (ok fields-alist) or (err message)