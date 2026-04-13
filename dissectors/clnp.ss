;; packet-clnp.c
;; Routines for ISO/OSI network protocol packet disassembly
;;
;; Laurent Deniel <laurent.deniel@free.fr>
;; Ralf Schneider <Ralf.Schneider@t-online.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/clnp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-clnp.c
;; RFC 994

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
(def (dissect-clnp buffer)
  "clnp dissector"
  (try
    (let* (
           (dest (unwrap (slice buffer 1 1)))
           (src-length (unwrap (read-u8 buffer 1)))
           (src (unwrap (slice buffer 2 1)))
           (data-unit-identifier (unwrap (read-u16be buffer 2)))
           (segment-offset (unwrap (read-u16be buffer 2)))
           (total-length (unwrap (read-u16be buffer 2)))
           (dest-length (unwrap (read-u8 buffer 4)))
           )

      (ok (list
        (cons 'dest (list (cons 'raw dest) (cons 'formatted (fmt-bytes dest))))
        (cons 'src-length (list (cons 'raw src-length) (cons 'formatted (number->string src-length))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (fmt-bytes src))))
        (cons 'data-unit-identifier (list (cons 'raw data-unit-identifier) (cons 'formatted (number->string data-unit-identifier))))
        (cons 'segment-offset (list (cons 'raw segment-offset) (cons 'formatted (number->string segment-offset))))
        (cons 'total-length (list (cons 'raw total-length) (cons 'formatted (number->string total-length))))
        (cons 'dest-length (list (cons 'raw dest-length) (cons 'formatted (number->string dest-length))))
        )))

    (catch (e)
      (err (str "CLNP parse error: " e)))))

;; dissect-clnp: parse CLNP from bytevector
;; Returns (ok fields-alist) or (err message)