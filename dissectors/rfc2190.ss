;; packet-rfc2190.c
;;
;; Routines for RFC2190-encapsulated H.263 dissection
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

;; jerboa-ethereal/dissectors/rfc2190.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rfc2190.c
;; RFC 2190

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
(def (dissect-rfc2190 buffer)
  "H.263 RTP Payload header (RFC2190)"
  (try
    (let* (
           (ftype (unwrap (read-u8 buffer 0)))
           (pbframes (unwrap (read-u8 buffer 0)))
           (sbit (unwrap (read-u8 buffer 0)))
           (ebit (unwrap (read-u8 buffer 0)))
           (picture-coding-type-modeA (unwrap (read-u8 buffer 0)))
           (unrestricted-motion-vector-modeA (unwrap (read-u8 buffer 0)))
           (syntax-based-arithmetic-modeA (unwrap (read-u8 buffer 0)))
           (advanced-prediction-modeA (unwrap (read-u8 buffer 0)))
           (r-modeA (unwrap (read-u16be buffer 0)))
           (quant (unwrap (read-u8 buffer 0)))
           (gobn (unwrap (read-u8 buffer 0)))
           (mba (unwrap (read-u16be buffer 0)))
           (r-modeB (unwrap (read-u8 buffer 0)))
           (picture-coding-type-modeB (unwrap (read-u8 buffer 0)))
           (unrestricted-motion-vector-modeB (unwrap (read-u8 buffer 0)))
           (syntax-based-arithmetic-modeB (unwrap (read-u8 buffer 0)))
           (advanced-prediction-modeB (unwrap (read-u8 buffer 0)))
           (hmv1 (unwrap (read-u16be buffer 0)))
           (vmv1 (unwrap (read-u16be buffer 0)))
           (hmv2 (unwrap (read-u16be buffer 0)))
           (vmv2 (unwrap (read-u8 buffer 0)))
           (rr (unwrap (read-u24be buffer 0)))
           (dbq (unwrap (read-u8 buffer 2)))
           (trb (unwrap (read-u8 buffer 2)))
           (tr (unwrap (read-u8 buffer 2)))
           )

      (ok (list
        (cons 'ftype (list (cons 'raw ftype) (cons 'formatted (number->string ftype))))
        (cons 'pbframes (list (cons 'raw pbframes) (cons 'formatted (number->string pbframes))))
        (cons 'sbit (list (cons 'raw sbit) (cons 'formatted (number->string sbit))))
        (cons 'ebit (list (cons 'raw ebit) (cons 'formatted (number->string ebit))))
        (cons 'picture-coding-type-modeA (list (cons 'raw picture-coding-type-modeA) (cons 'formatted (number->string picture-coding-type-modeA))))
        (cons 'unrestricted-motion-vector-modeA (list (cons 'raw unrestricted-motion-vector-modeA) (cons 'formatted (number->string unrestricted-motion-vector-modeA))))
        (cons 'syntax-based-arithmetic-modeA (list (cons 'raw syntax-based-arithmetic-modeA) (cons 'formatted (number->string syntax-based-arithmetic-modeA))))
        (cons 'advanced-prediction-modeA (list (cons 'raw advanced-prediction-modeA) (cons 'formatted (number->string advanced-prediction-modeA))))
        (cons 'r-modeA (list (cons 'raw r-modeA) (cons 'formatted (number->string r-modeA))))
        (cons 'quant (list (cons 'raw quant) (cons 'formatted (number->string quant))))
        (cons 'gobn (list (cons 'raw gobn) (cons 'formatted (number->string gobn))))
        (cons 'mba (list (cons 'raw mba) (cons 'formatted (number->string mba))))
        (cons 'r-modeB (list (cons 'raw r-modeB) (cons 'formatted (number->string r-modeB))))
        (cons 'picture-coding-type-modeB (list (cons 'raw picture-coding-type-modeB) (cons 'formatted (number->string picture-coding-type-modeB))))
        (cons 'unrestricted-motion-vector-modeB (list (cons 'raw unrestricted-motion-vector-modeB) (cons 'formatted (number->string unrestricted-motion-vector-modeB))))
        (cons 'syntax-based-arithmetic-modeB (list (cons 'raw syntax-based-arithmetic-modeB) (cons 'formatted (number->string syntax-based-arithmetic-modeB))))
        (cons 'advanced-prediction-modeB (list (cons 'raw advanced-prediction-modeB) (cons 'formatted (number->string advanced-prediction-modeB))))
        (cons 'hmv1 (list (cons 'raw hmv1) (cons 'formatted (number->string hmv1))))
        (cons 'vmv1 (list (cons 'raw vmv1) (cons 'formatted (number->string vmv1))))
        (cons 'hmv2 (list (cons 'raw hmv2) (cons 'formatted (number->string hmv2))))
        (cons 'vmv2 (list (cons 'raw vmv2) (cons 'formatted (number->string vmv2))))
        (cons 'rr (list (cons 'raw rr) (cons 'formatted (number->string rr))))
        (cons 'dbq (list (cons 'raw dbq) (cons 'formatted (number->string dbq))))
        (cons 'trb (list (cons 'raw trb) (cons 'formatted (number->string trb))))
        (cons 'tr (list (cons 'raw tr) (cons 'formatted (number->string tr))))
        )))

    (catch (e)
      (err (str "RFC2190 parse error: " e)))))

;; dissect-rfc2190: parse RFC2190 from bytevector
;; Returns (ok fields-alist) or (err message)