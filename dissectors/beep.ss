;; packet-beep.c
;; Routines for BEEP packet disassembly
;;
;; Copyright (c) 2000 by Richard Sharpe <rsharpe@ns.aus.com>
;; Modified 2001 Darren New <dnew@invisible.net> for BEEP.
;;
;; Original BXXP dissector developed with funding from InvisibleWorlds
;; (www.invisibleworlds.com) via Collab.Net.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/beep.ss
;; Auto-generated from wireshark/epan/dissectors/packet-beep.c

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
(def (dissect-beep buffer)
  "Blocks Extensible Exchange Protocol"
  (try
    (let* (
           (mime-header (unwrap (slice buffer 0 1)))
           (header (unwrap (slice buffer 0 1)))
           (req (unwrap (read-u8 buffer 0)))
           (payload (unwrap (slice buffer 0 1)))
           (cmd (unwrap (slice buffer 17 3)))
           (payload-undissected (unwrap (slice buffer 20 1)))
           )

      (ok (list
        (cons 'mime-header (list (cons 'raw mime-header) (cons 'formatted (utf8->string mime-header))))
        (cons 'header (list (cons 'raw header) (cons 'formatted (utf8->string header))))
        (cons 'req (list (cons 'raw req) (cons 'formatted (number->string req))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (utf8->string payload))))
        (cons 'cmd (list (cons 'raw cmd) (cons 'formatted (utf8->string cmd))))
        (cons 'payload-undissected (list (cons 'raw payload-undissected) (cons 'formatted (utf8->string payload-undissected))))
        )))

    (catch (e)
      (err (str "BEEP parse error: " e)))))

;; dissect-beep: parse BEEP from bytevector
;; Returns (ok fields-alist) or (err message)