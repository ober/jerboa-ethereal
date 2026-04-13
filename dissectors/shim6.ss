;; packet-shim6.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; RFC 5533
;;
;; SHIM6 support added by Matthijs Mekking <matthijs@NLnetLabs.nl>
;;

;; jerboa-ethereal/dissectors/shim6.ss
;; Auto-generated from wireshark/epan/dissectors/packet-shim6.c
;; RFC 5533

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
(def (dissect-shim6 buffer)
  "Shim6 Protocol"
  (try
    (let* (
           (nxt (unwrap (read-u8 buffer 0)))
           (len (unwrap (read-u8 buffer 1)))
           (len-oct (unwrap (read-u16be buffer 1)))
           (p (unwrap (read-u8 buffer 2)))
           (opt-critical (unwrap (read-u8 buffer 30)))
           (opt-len (unwrap (read-u16be buffer 30)))
           (opt-total-len (unwrap (read-u16be buffer 30)))
           (validator (unwrap (slice buffer 30 1)))
           (padding (unwrap (slice buffer 30 1)))
           (cga-parameter-data-structure (unwrap (slice buffer 30 1)))
           (cga-signature (unwrap (slice buffer 30 1)))
           (reserved (unwrap (slice buffer 30 4)))
           (sulid (unwrap (slice buffer 34 16)))
           (rulid (unwrap (slice buffer 50 16)))
           (opt-fii (unwrap (read-u32be buffer 66)))
           (psrc (unwrap (slice buffer 70 16)))
           (pdst (unwrap (slice buffer 86 16)))
           (pnonce (unwrap (read-u32be buffer 102)))
           (pdata (unwrap (read-u32be buffer 106)))
           (inonce (unwrap (read-u32be buffer 174)))
           (rnonce (unwrap (read-u32be buffer 200)))
           (psent (unwrap (read-u8 buffer 220)))
           (precvd (unwrap (read-u8 buffer 220)))
           (reap (unwrap (read-u8 buffer 221)))
           (reserved2 (unwrap (slice buffer 221 3)))
           )

      (ok (list
        (cons 'nxt (list (cons 'raw nxt) (cons 'formatted (number->string nxt))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'len-oct (list (cons 'raw len-oct) (cons 'formatted (number->string len-oct))))
        (cons 'p (list (cons 'raw p) (cons 'formatted (number->string p))))
        (cons 'opt-critical (list (cons 'raw opt-critical) (cons 'formatted (if (= opt-critical 0) "False" "True"))))
        (cons 'opt-len (list (cons 'raw opt-len) (cons 'formatted (number->string opt-len))))
        (cons 'opt-total-len (list (cons 'raw opt-total-len) (cons 'formatted (number->string opt-total-len))))
        (cons 'validator (list (cons 'raw validator) (cons 'formatted (fmt-bytes validator))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'cga-parameter-data-structure (list (cons 'raw cga-parameter-data-structure) (cons 'formatted (fmt-bytes cga-parameter-data-structure))))
        (cons 'cga-signature (list (cons 'raw cga-signature) (cons 'formatted (fmt-bytes cga-signature))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'sulid (list (cons 'raw sulid) (cons 'formatted (fmt-ipv6-address sulid))))
        (cons 'rulid (list (cons 'raw rulid) (cons 'formatted (fmt-ipv6-address rulid))))
        (cons 'opt-fii (list (cons 'raw opt-fii) (cons 'formatted (number->string opt-fii))))
        (cons 'psrc (list (cons 'raw psrc) (cons 'formatted (fmt-ipv6-address psrc))))
        (cons 'pdst (list (cons 'raw pdst) (cons 'formatted (fmt-ipv6-address pdst))))
        (cons 'pnonce (list (cons 'raw pnonce) (cons 'formatted (number->string pnonce))))
        (cons 'pdata (list (cons 'raw pdata) (cons 'formatted (fmt-hex pdata))))
        (cons 'inonce (list (cons 'raw inonce) (cons 'formatted (number->string inonce))))
        (cons 'rnonce (list (cons 'raw rnonce) (cons 'formatted (number->string rnonce))))
        (cons 'psent (list (cons 'raw psent) (cons 'formatted (number->string psent))))
        (cons 'precvd (list (cons 'raw precvd) (cons 'formatted (number->string precvd))))
        (cons 'reap (list (cons 'raw reap) (cons 'formatted (number->string reap))))
        (cons 'reserved2 (list (cons 'raw reserved2) (cons 'formatted (fmt-bytes reserved2))))
        )))

    (catch (e)
      (err (str "SHIM6 parse error: " e)))))

;; dissect-shim6: parse SHIM6 from bytevector
;; Returns (ok fields-alist) or (err message)