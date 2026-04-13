;; packet-h223.c
;; Routines for H.223 packet dissection
;; Copyright (c) 2004-5 MX Telecom Ltd <richardv@mxtelecom.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/h223.ss
;; Auto-generated from wireshark/epan/dissectors/packet-h223.c

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
(def (dissect-h223 buffer)
  "ITU-T Recommendation H.223"
  (try
    (let* (
           (mux-mpl (unwrap (read-u16be buffer 0)))
           (mux-correctedhdr (unwrap (read-u24be buffer 0)))
           (mux-rawhdr (unwrap (read-u24be buffer 0)))
           (mux-mc (unwrap (read-u8 buffer 0)))
           (al2-seqno (unwrap (read-u8 buffer 0)))
           (al2 (unwrap (read-u8 buffer 0)))
           (al1-framed (unwrap (read-u8 buffer 0)))
           (mux-hdlc2 (unwrap (read-u16be buffer 3)))
           )

      (ok (list
        (cons 'mux-mpl (list (cons 'raw mux-mpl) (cons 'formatted (number->string mux-mpl))))
        (cons 'mux-correctedhdr (list (cons 'raw mux-correctedhdr) (cons 'formatted (fmt-hex mux-correctedhdr))))
        (cons 'mux-rawhdr (list (cons 'raw mux-rawhdr) (cons 'formatted (fmt-hex mux-rawhdr))))
        (cons 'mux-mc (list (cons 'raw mux-mc) (cons 'formatted (number->string mux-mc))))
        (cons 'al2-seqno (list (cons 'raw al2-seqno) (cons 'formatted (number->string al2-seqno))))
        (cons 'al2 (list (cons 'raw al2) (cons 'formatted (number->string al2))))
        (cons 'al1-framed (list (cons 'raw al1-framed) (cons 'formatted (number->string al1-framed))))
        (cons 'mux-hdlc2 (list (cons 'raw mux-hdlc2) (cons 'formatted (fmt-hex mux-hdlc2))))
        )))

    (catch (e)
      (err (str "H223 parse error: " e)))))

;; dissect-h223: parse H223 from bytevector
;; Returns (ok fields-alist) or (err message)