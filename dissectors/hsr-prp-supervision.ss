;; packet-hsr-prp-supervision.c
;; Routines for HSR/PRP supervision dissection (IEC62439 Part 3)
;; Copyright 2009, Florian Reichert <refl[AT]zhaw.ch>
;; Copyright 2011, Martin Renold <reld[AT]zhaw.ch>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald[AT]wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hsr-prp-supervision.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hsr_prp_supervision.c

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
(def (dissect-hsr-prp-supervision buffer)
  "HSR/PRP Supervision (IEC62439 Part 3)"
  (try
    (let* (
           (prp-supervision-path (unwrap (read-u16be buffer 0)))
           (prp-supervision-version (unwrap (read-u16be buffer 0)))
           (prp-supervision-seqno (unwrap (read-u16be buffer 2)))
           (prp-supervision-tlv-length (unwrap (read-u8 buffer 5)))
           (prp-supervision-source-mac-address-A (unwrap (slice buffer 6 6)))
           (prp-supervision-source-mac-address-B (unwrap (slice buffer 6 6)))
           (prp-supervision-source-mac-address (unwrap (slice buffer 6 6)))
           (prp-supervision-red-box-mac-address (unwrap (slice buffer 6 6)))
           (prp-supervision-vdan-mac-address (unwrap (slice buffer 6 6)))
           )

      (ok (list
        (cons 'prp-supervision-path (list (cons 'raw prp-supervision-path) (cons 'formatted (number->string prp-supervision-path))))
        (cons 'prp-supervision-version (list (cons 'raw prp-supervision-version) (cons 'formatted (number->string prp-supervision-version))))
        (cons 'prp-supervision-seqno (list (cons 'raw prp-supervision-seqno) (cons 'formatted (number->string prp-supervision-seqno))))
        (cons 'prp-supervision-tlv-length (list (cons 'raw prp-supervision-tlv-length) (cons 'formatted (number->string prp-supervision-tlv-length))))
        (cons 'prp-supervision-source-mac-address-A (list (cons 'raw prp-supervision-source-mac-address-A) (cons 'formatted (fmt-mac prp-supervision-source-mac-address-A))))
        (cons 'prp-supervision-source-mac-address-B (list (cons 'raw prp-supervision-source-mac-address-B) (cons 'formatted (fmt-mac prp-supervision-source-mac-address-B))))
        (cons 'prp-supervision-source-mac-address (list (cons 'raw prp-supervision-source-mac-address) (cons 'formatted (fmt-mac prp-supervision-source-mac-address))))
        (cons 'prp-supervision-red-box-mac-address (list (cons 'raw prp-supervision-red-box-mac-address) (cons 'formatted (fmt-mac prp-supervision-red-box-mac-address))))
        (cons 'prp-supervision-vdan-mac-address (list (cons 'raw prp-supervision-vdan-mac-address) (cons 'formatted (fmt-mac prp-supervision-vdan-mac-address))))
        )))

    (catch (e)
      (err (str "HSR-PRP-SUPERVISION parse error: " e)))))

;; dissect-hsr-prp-supervision: parse HSR-PRP-SUPERVISION from bytevector
;; Returns (ok fields-alist) or (err message)