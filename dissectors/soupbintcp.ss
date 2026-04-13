;; packet-soupbintcp.c
;; Routines for SoupBinTCP 3.0 protocol dissection
;; Copyright 2013 David Arnold <davida@pobox.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/soupbintcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-soupbintcp.c

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
(def (dissect-soupbintcp buffer)
  "SoupBinTCP"
  (try
    (let* (
           (text (unwrap (slice buffer 3 1)))
           (next-seq-num (unwrap (slice buffer 13 20)))
           (seq-num (unwrap (slice buffer 13 1)))
           (username (unwrap (slice buffer 13 6)))
           (password (unwrap (slice buffer 19 10)))
           (session (unwrap (slice buffer 29 10)))
           (req-seq-num (unwrap (slice buffer 39 20)))
           (message (unwrap (slice buffer 39 1)))
           (packet-length (unwrap (read-u16be buffer 59)))
           )

      (ok (list
        (cons 'text (list (cons 'raw text) (cons 'formatted (utf8->string text))))
        (cons 'next-seq-num (list (cons 'raw next-seq-num) (cons 'formatted (utf8->string next-seq-num))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (utf8->string seq-num))))
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (utf8->string password))))
        (cons 'session (list (cons 'raw session) (cons 'formatted (utf8->string session))))
        (cons 'req-seq-num (list (cons 'raw req-seq-num) (cons 'formatted (utf8->string req-seq-num))))
        (cons 'message (list (cons 'raw message) (cons 'formatted (fmt-bytes message))))
        (cons 'packet-length (list (cons 'raw packet-length) (cons 'formatted (number->string packet-length))))
        )))

    (catch (e)
      (err (str "SOUPBINTCP parse error: " e)))))

;; dissect-soupbintcp: parse SOUPBINTCP from bytevector
;; Returns (ok fields-alist) or (err message)