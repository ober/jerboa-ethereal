;; packet-mpls-y1711.c
;; Routines for (old) ITU-T MPLS OAM: it conforms to ITU-T Y.1711 and RFC 3429
;;
;; Copyright 2006, 2011 _FF_
;;
;; Francesco Fondelli <francesco dot fondelli, gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mpls-y1711.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mpls_y1711.c
;; RFC 3429

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
(def (dissect-mpls-y1711 buffer)
  "MPLS ITU-T Y.1711 OAM"
  (try
    (let* (
           (y1711-defect-location (unwrap (read-u32be buffer 83)))
           (y1711-lsr-id (unwrap (read-u32be buffer 116)))
           (y1711-lsp-id (unwrap (read-u32be buffer 120)))
           (y1711-bip16 (unwrap (read-u16be buffer 141)))
           )

      (ok (list
        (cons 'y1711-defect-location (list (cons 'raw y1711-defect-location) (cons 'formatted (number->string y1711-defect-location))))
        (cons 'y1711-lsr-id (list (cons 'raw y1711-lsr-id) (cons 'formatted (fmt-ipv4 y1711-lsr-id))))
        (cons 'y1711-lsp-id (list (cons 'raw y1711-lsp-id) (cons 'formatted (number->string y1711-lsp-id))))
        (cons 'y1711-bip16 (list (cons 'raw y1711-bip16) (cons 'formatted (fmt-hex y1711-bip16))))
        )))

    (catch (e)
      (err (str "MPLS-Y1711 parse error: " e)))))

;; dissect-mpls-y1711: parse MPLS-Y1711 from bytevector
;; Returns (ok fields-alist) or (err message)