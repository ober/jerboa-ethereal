;; packet-bssap.c
;; Routines for Base Station Subsystem Application Part (BSSAP/BSAP) dissection
;; Specifications from 3GPP2 (www.3gpp2.org) and 3GPP (www.3gpp.org)
;; IOS 4.0.1 (BSAP)
;; GSM 08.06 (BSSAP)
;;
;; Copyright 2003, Michael Lum <mlum [AT] telostech.com>
;; In association with Telos Technology Inc.
;;
;; Added BSSAP+ according to ETSI TS 129 018 V6.3.0 (2005-3GPP TS 29.018 version 6.3.0 Release 6)
;; Copyright 2006, Anders Broman <Anders.Broman [AT] ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bssap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bssap.c

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
(def (dissect-bssap buffer)
  "BSSAP"
  (try
    (let* (
           (length (unwrap (read-u8 buffer 0)))
           (dlci-rsvd (unwrap (read-u8 buffer 0)))
           (dlci-spare (unwrap (read-u8 buffer 0)))
           (plus-ie-len (unwrap (read-u8 buffer 0)))
           (cell-global-id (unwrap (slice buffer 0 1)))
           (e-bit (unwrap (read-u8 buffer 0)))
           (tunnel-prio (unwrap (read-u8 buffer 0)))
           (plus-ie-data (unwrap (slice buffer 0 1)))
           (loc-inf-age (unwrap (read-u16be buffer 0)))
           (ptmsi (unwrap (slice buffer 0 1)))
           (extension (unwrap (read-u8 buffer 0)))
           (tmsi (unwrap (slice buffer 0 1)))
           (tmsi-status (unwrap (read-u8 buffer 0)))
           (global-cn-id (unwrap (slice buffer 0 1)))
           (plmn-id (unwrap (slice buffer 0 3)))
           (cn-id (unwrap (read-u16be buffer 0)))
           (extraneous-data (unwrap (slice buffer 0 1)))
           (conditional-ie (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'dlci-rsvd (list (cons 'raw dlci-rsvd) (cons 'formatted (fmt-hex dlci-rsvd))))
        (cons 'dlci-spare (list (cons 'raw dlci-spare) (cons 'formatted (fmt-hex dlci-spare))))
        (cons 'plus-ie-len (list (cons 'raw plus-ie-len) (cons 'formatted (number->string plus-ie-len))))
        (cons 'cell-global-id (list (cons 'raw cell-global-id) (cons 'formatted (fmt-bytes cell-global-id))))
        (cons 'e-bit (list (cons 'raw e-bit) (cons 'formatted (if (= e-bit 0) "SGSN did not receive the payload in ciphered form" "SGSN received the payload in ciphered"))))
        (cons 'tunnel-prio (list (cons 'raw tunnel-prio) (cons 'formatted (number->string tunnel-prio))))
        (cons 'plus-ie-data (list (cons 'raw plus-ie-data) (cons 'formatted (fmt-bytes plus-ie-data))))
        (cons 'loc-inf-age (list (cons 'raw loc-inf-age) (cons 'formatted (number->string loc-inf-age))))
        (cons 'ptmsi (list (cons 'raw ptmsi) (cons 'formatted (fmt-bytes ptmsi))))
        (cons 'extension (list (cons 'raw extension) (cons 'formatted (if (= extension 0) "False" "True"))))
        (cons 'tmsi (list (cons 'raw tmsi) (cons 'formatted (fmt-bytes tmsi))))
        (cons 'tmsi-status (list (cons 'raw tmsi-status) (cons 'formatted (if (= tmsi-status 0) "No valid TMSI available" "Valid TMSI available"))))
        (cons 'global-cn-id (list (cons 'raw global-cn-id) (cons 'formatted (fmt-bytes global-cn-id))))
        (cons 'plmn-id (list (cons 'raw plmn-id) (cons 'formatted (fmt-bytes plmn-id))))
        (cons 'cn-id (list (cons 'raw cn-id) (cons 'formatted (number->string cn-id))))
        (cons 'extraneous-data (list (cons 'raw extraneous-data) (cons 'formatted (fmt-bytes extraneous-data))))
        (cons 'conditional-ie (list (cons 'raw conditional-ie) (cons 'formatted (fmt-bytes conditional-ie))))
        )))

    (catch (e)
      (err (str "BSSAP parse error: " e)))))

;; dissect-bssap: parse BSSAP from bytevector
;; Returns (ok fields-alist) or (err message)