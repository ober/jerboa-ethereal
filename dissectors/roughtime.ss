;; packet-roughtime.c
;; Dissector for Roughtime Time Synchronization
;;
;; Copyright (c) 2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/roughtime.ss
;; Auto-generated from wireshark/epan/dissectors/packet-roughtime.c

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
(def (dissect-roughtime buffer)
  "Roughtime"
  (try
    (let* (
           (hdr (unwrap (slice buffer 0 8)))
           (proto (unwrap (slice buffer 0 1)))
           (num-tags (unwrap (read-u32be buffer 0)))
           (offset (unwrap (read-u32be buffer 4)))
           (tag (unwrap (slice buffer 8 3)))
           (msg-len (unwrap (read-u32be buffer 8)))
           (nonce (unwrap (slice buffer 12 1)))
           (sig (unwrap (slice buffer 12 1)))
           (srv (unwrap (slice buffer 12 1)))
           (index (unwrap (read-u32be buffer 12)))
           (path (unwrap (slice buffer 12 1)))
           (radius (unwrap (read-u32be buffer 12)))
           (root (unwrap (slice buffer 12 1)))
           (pubk (unwrap (slice buffer 12 1)))
           (value (unwrap (slice buffer 12 1)))
           )

      (ok (list
        (cons 'hdr (list (cons 'raw hdr) (cons 'formatted (utf8->string hdr))))
        (cons 'proto (list (cons 'raw proto) (cons 'formatted (utf8->string proto))))
        (cons 'num-tags (list (cons 'raw num-tags) (cons 'formatted (number->string num-tags))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (number->string offset))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (utf8->string tag))))
        (cons 'msg-len (list (cons 'raw msg-len) (cons 'formatted (number->string msg-len))))
        (cons 'nonce (list (cons 'raw nonce) (cons 'formatted (fmt-bytes nonce))))
        (cons 'sig (list (cons 'raw sig) (cons 'formatted (fmt-bytes sig))))
        (cons 'srv (list (cons 'raw srv) (cons 'formatted (fmt-bytes srv))))
        (cons 'index (list (cons 'raw index) (cons 'formatted (number->string index))))
        (cons 'path (list (cons 'raw path) (cons 'formatted (fmt-bytes path))))
        (cons 'radius (list (cons 'raw radius) (cons 'formatted (number->string radius))))
        (cons 'root (list (cons 'raw root) (cons 'formatted (fmt-bytes root))))
        (cons 'pubk (list (cons 'raw pubk) (cons 'formatted (fmt-bytes pubk))))
        (cons 'value (list (cons 'raw value) (cons 'formatted (fmt-bytes value))))
        )))

    (catch (e)
      (err (str "ROUGHTIME parse error: " e)))))

;; dissect-roughtime: parse ROUGHTIME from bytevector
;; Returns (ok fields-alist) or (err message)