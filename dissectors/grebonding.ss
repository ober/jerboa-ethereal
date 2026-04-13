;; packet-grebonding.c
;; Routines for Huawei's GRE bonding control (RFC8157) dissection
;; Thomas Vogt
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/grebonding.ss
;; Auto-generated from wireshark/epan/dissectors/packet-grebonding.c
;; RFC 8157

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
(def (dissect-grebonding buffer)
  "Huawei GRE bonding"
  (try
    (let* (
           (attr-val-ipv4 (unwrap (read-u32be buffer 0)))
           (attr-filter-commit (unwrap (read-u32be buffer 0)))
           (attr-filter-packetid (unwrap (read-u16be buffer 0)))
           (attr-filter-packetsum (unwrap (read-u16be buffer 0)))
           (attr-length (unwrap (read-u16be buffer 0)))
           (attr-val-string (unwrap (slice buffer 3 1)))
           (attr-dt-bras-name (unwrap (slice buffer 3 1)))
           (attr-val-uint64 (unwrap (read-u64be buffer 3)))
           (attr-filter-item-length (unwrap (read-u16be buffer 8)))
           (attr-filter-item-enabled (unwrap (read-u16be buffer 8)))
           (attr-filter-item-desc-length (unwrap (read-u16be buffer 8)))
           (attr-filter-item-desc-val (unwrap (slice buffer 8 1)))
           (attr-val-ipv6 (unwrap (slice buffer 8 16)))
           )

      (ok (list
        (cons 'attr-val-ipv4 (list (cons 'raw attr-val-ipv4) (cons 'formatted (fmt-ipv4 attr-val-ipv4))))
        (cons 'attr-filter-commit (list (cons 'raw attr-filter-commit) (cons 'formatted (number->string attr-filter-commit))))
        (cons 'attr-filter-packetid (list (cons 'raw attr-filter-packetid) (cons 'formatted (number->string attr-filter-packetid))))
        (cons 'attr-filter-packetsum (list (cons 'raw attr-filter-packetsum) (cons 'formatted (number->string attr-filter-packetsum))))
        (cons 'attr-length (list (cons 'raw attr-length) (cons 'formatted (number->string attr-length))))
        (cons 'attr-val-string (list (cons 'raw attr-val-string) (cons 'formatted (utf8->string attr-val-string))))
        (cons 'attr-dt-bras-name (list (cons 'raw attr-dt-bras-name) (cons 'formatted (utf8->string attr-dt-bras-name))))
        (cons 'attr-val-uint64 (list (cons 'raw attr-val-uint64) (cons 'formatted (number->string attr-val-uint64))))
        (cons 'attr-filter-item-length (list (cons 'raw attr-filter-item-length) (cons 'formatted (number->string attr-filter-item-length))))
        (cons 'attr-filter-item-enabled (list (cons 'raw attr-filter-item-enabled) (cons 'formatted (number->string attr-filter-item-enabled))))
        (cons 'attr-filter-item-desc-length (list (cons 'raw attr-filter-item-desc-length) (cons 'formatted (number->string attr-filter-item-desc-length))))
        (cons 'attr-filter-item-desc-val (list (cons 'raw attr-filter-item-desc-val) (cons 'formatted (utf8->string attr-filter-item-desc-val))))
        (cons 'attr-val-ipv6 (list (cons 'raw attr-val-ipv6) (cons 'formatted (fmt-ipv6-address attr-val-ipv6))))
        )))

    (catch (e)
      (err (str "GREBONDING parse error: " e)))))

;; dissect-grebonding: parse GREBONDING from bytevector
;; Returns (ok fields-alist) or (err message)