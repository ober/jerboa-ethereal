;; packet-macsec.c
;; Routines for IEEE 802.1AE MACsec dissection
;; Copyright 2013, Allan W. Nielsen <anielsen@vitesse.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/macsec.ss
;; Auto-generated from wireshark/epan/dissectors/packet-macsec.c

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
(def (dissect-macsec buffer)
  "802.1AE Security Tag"
  (try
    (let* (
           (TCI (unwrap (read-u8 buffer 0)))
           (TCI-V (extract-bits TCI 0x0 0))
           (TCI-ES (extract-bits TCI 0x0 0))
           (TCI-SC (extract-bits TCI 0x0 0))
           (TCI-SCB (extract-bits TCI 0x0 0))
           (TCI-E (extract-bits TCI 0x0 0))
           (TCI-C (extract-bits TCI 0x0 0))
           (psk-table-index (unwrap (read-u16be buffer 0)))
           (psk-info (unwrap (slice buffer 0 1)))
           (psk (unwrap (slice buffer 0 1)))
           (ckn-table-index (unwrap (read-u16be buffer 0)))
           (ckn-info (unwrap (slice buffer 0 1)))
           (sak (unwrap (slice buffer 0 1)))
           (ICV-check-success (unwrap (read-u8 buffer 0)))
           (XPN (unwrap (read-u64be buffer 0)))
           (AN (unwrap (read-u8 buffer 0)))
           (SL (unwrap (read-u8 buffer 1)))
           (PN (unwrap (read-u32be buffer 2)))
           (SCI (unwrap (slice buffer 6 1)))
           (SCI-system-identifier (unwrap (slice buffer 6 6)))
           (SCI-port-identifier (unwrap (read-u16be buffer 6)))
           )

      (ok (list
        (cons 'TCI (list (cons 'raw TCI) (cons 'formatted (fmt-hex TCI))))
        (cons 'TCI-V (list (cons 'raw TCI-V) (cons 'formatted (if (= TCI-V 0) "Not set" "Set"))))
        (cons 'TCI-ES (list (cons 'raw TCI-ES) (cons 'formatted (if (= TCI-ES 0) "Not set" "Set"))))
        (cons 'TCI-SC (list (cons 'raw TCI-SC) (cons 'formatted (if (= TCI-SC 0) "Not set" "Set"))))
        (cons 'TCI-SCB (list (cons 'raw TCI-SCB) (cons 'formatted (if (= TCI-SCB 0) "Not set" "Set"))))
        (cons 'TCI-E (list (cons 'raw TCI-E) (cons 'formatted (if (= TCI-E 0) "Not set" "Set"))))
        (cons 'TCI-C (list (cons 'raw TCI-C) (cons 'formatted (if (= TCI-C 0) "Not set" "Set"))))
        (cons 'psk-table-index (list (cons 'raw psk-table-index) (cons 'formatted (number->string psk-table-index))))
        (cons 'psk-info (list (cons 'raw psk-info) (cons 'formatted (utf8->string psk-info))))
        (cons 'psk (list (cons 'raw psk) (cons 'formatted (fmt-bytes psk))))
        (cons 'ckn-table-index (list (cons 'raw ckn-table-index) (cons 'formatted (number->string ckn-table-index))))
        (cons 'ckn-info (list (cons 'raw ckn-info) (cons 'formatted (utf8->string ckn-info))))
        (cons 'sak (list (cons 'raw sak) (cons 'formatted (fmt-bytes sak))))
        (cons 'ICV-check-success (list (cons 'raw ICV-check-success) (cons 'formatted (number->string ICV-check-success))))
        (cons 'XPN (list (cons 'raw XPN) (cons 'formatted (number->string XPN))))
        (cons 'AN (list (cons 'raw AN) (cons 'formatted (fmt-hex AN))))
        (cons 'SL (list (cons 'raw SL) (cons 'formatted (number->string SL))))
        (cons 'PN (list (cons 'raw PN) (cons 'formatted (number->string PN))))
        (cons 'SCI (list (cons 'raw SCI) (cons 'formatted (fmt-bytes SCI))))
        (cons 'SCI-system-identifier (list (cons 'raw SCI-system-identifier) (cons 'formatted (fmt-mac SCI-system-identifier))))
        (cons 'SCI-port-identifier (list (cons 'raw SCI-port-identifier) (cons 'formatted (number->string SCI-port-identifier))))
        )))

    (catch (e)
      (err (str "MACSEC parse error: " e)))))

;; dissect-macsec: parse MACSEC from bytevector
;; Returns (ok fields-alist) or (err message)