;;
;; R09.x public transport priority telegrams
;;
;; Anlagen zu VOEV 04.05 "LSA/R09.14 and R09.16"
;; https://www.vdv.de/voev-04-05-1-erg.pdfx
;;
;; Copyright 2020, Tomas Kukosa
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/r09.ss
;; Auto-generated from wireshark/epan/dissectors/packet-r09.c

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
(def (dissect-r09 buffer)
  "R09.x"
  (try
    (let* (
           (ty (unwrap (read-u8 buffer 0)))
           (modus (unwrap (read-u8 buffer 0)))
           (tl (unwrap (read-u8 buffer 1)))
           (zw (unwrap (read-u8 buffer 1)))
           (mp16 (unwrap (read-u16be buffer 2)))
           (mp8 (unwrap (read-u8 buffer 2)))
           (ln (unwrap (slice buffer 4 2)))
           (pr (unwrap (read-u8 buffer 4)))
           (kn (unwrap (slice buffer 6 1)))
           (zn (unwrap (slice buffer 7 2)))
           (fn (unwrap (slice buffer 8 2)))
           (zl (unwrap (read-u8 buffer 8)))
           (un (unwrap (slice buffer 10 1)))
           )

      (ok (list
        (cons 'ty (list (cons 'raw ty) (cons 'formatted (number->string ty))))
        (cons 'modus (list (cons 'raw modus) (cons 'formatted (number->string modus))))
        (cons 'tl (list (cons 'raw tl) (cons 'formatted (number->string tl))))
        (cons 'zw (list (cons 'raw zw) (cons 'formatted (number->string zw))))
        (cons 'mp16 (list (cons 'raw mp16) (cons 'formatted (number->string mp16))))
        (cons 'mp8 (list (cons 'raw mp8) (cons 'formatted (number->string mp8))))
        (cons 'ln (list (cons 'raw ln) (cons 'formatted (utf8->string ln))))
        (cons 'pr (list (cons 'raw pr) (cons 'formatted (number->string pr))))
        (cons 'kn (list (cons 'raw kn) (cons 'formatted (utf8->string kn))))
        (cons 'zn (list (cons 'raw zn) (cons 'formatted (utf8->string zn))))
        (cons 'fn (list (cons 'raw fn) (cons 'formatted (utf8->string fn))))
        (cons 'zl (list (cons 'raw zl) (cons 'formatted (number->string zl))))
        (cons 'un (list (cons 'raw un) (cons 'formatted (utf8->string un))))
        )))

    (catch (e)
      (err (str "R09 parse error: " e)))))

;; dissect-r09: parse R09 from bytevector
;; Returns (ok fields-alist) or (err message)