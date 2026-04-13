;; packet-h263p.c
;;
;; Routines for RFC-4629-encapsulated H.263 dissection
;;
;; Copyright 2003 Niklas Ogren <niklas.ogren@7l.se>
;; Seven Levels Consultants AB
;;
;; Copyright 2008 Richard van der Hoff, MX Telecom
;; <richardv@mxtelecom.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/h263p.ss
;; Auto-generated from wireshark/epan/dissectors/packet-h263p.c
;; RFC 4629

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
(def (dissect-h263p buffer)
  "ITU-T Recommendation H.263 RTP Payload header (RFC4629)"
  (try
    (let* (
           (rr (unwrap (read-u16be buffer 0)))
           (pbit (unwrap (read-u8 buffer 0)))
           (vbit (unwrap (read-u8 buffer 0)))
           (plen (unwrap (read-u16be buffer 0)))
           (pebit (unwrap (read-u16be buffer 0)))
           (tid (unwrap (read-u8 buffer 0)))
           (trun (unwrap (read-u8 buffer 0)))
           (s (unwrap (read-u8 buffer 0)))
           (extra-hdr (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'rr (list (cons 'raw rr) (cons 'formatted (number->string rr))))
        (cons 'pbit (list (cons 'raw pbit) (cons 'formatted (number->string pbit))))
        (cons 'vbit (list (cons 'raw vbit) (cons 'formatted (number->string vbit))))
        (cons 'plen (list (cons 'raw plen) (cons 'formatted (number->string plen))))
        (cons 'pebit (list (cons 'raw pebit) (cons 'formatted (number->string pebit))))
        (cons 'tid (list (cons 'raw tid) (cons 'formatted (number->string tid))))
        (cons 'trun (list (cons 'raw trun) (cons 'formatted (number->string trun))))
        (cons 's (list (cons 'raw s) (cons 'formatted (number->string s))))
        (cons 'extra-hdr (list (cons 'raw extra-hdr) (cons 'formatted (fmt-bytes extra-hdr))))
        )))

    (catch (e)
      (err (str "H263P parse error: " e)))))

;; dissect-h263p: parse H263P from bytevector
;; Returns (ok fields-alist) or (err message)