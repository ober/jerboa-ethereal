;; packet-rfid-pn532-hci.c
;; Routines for NXP PN532 HCI Protocol
;;
;; http://www.nxp.com/documents/user_manual/141520.pdf
;;
;; Copyright 2013, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rfid-pn532-hci.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rfid_pn532_hci.c

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
(def (dissect-rfid-pn532-hci buffer)
  "NXP PN532 HCI"
  (try
    (let* (
           (code (unwrap (read-u16be buffer 0)))
           (application-level-error-code (unwrap (read-u8 buffer 8)))
           (length (unwrap (read-u16be buffer 9)))
           (hf-length (unwrap (read-u8 buffer 13)))
           (checksum (unwrap (read-u8 buffer 15)))
           (hf-postable (unwrap (slice buffer 16 1)))
           (hf-ignored (unwrap (slice buffer 16 1)))
           (hf-preamble (unwrap (slice buffer 17 1)))
           )

      (ok (list
        (cons 'code (list (cons 'raw code) (cons 'formatted (fmt-hex code))))
        (cons 'application-level-error-code (list (cons 'raw application-level-error-code) (cons 'formatted (fmt-hex application-level-error-code))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'hf-length (list (cons 'raw hf-length) (cons 'formatted (number->string hf-length))))
        (cons 'checksum (list (cons 'raw checksum) (cons 'formatted (fmt-hex checksum))))
        (cons 'hf-postable (list (cons 'raw hf-postable) (cons 'formatted (fmt-bytes hf-postable))))
        (cons 'hf-ignored (list (cons 'raw hf-ignored) (cons 'formatted (fmt-bytes hf-ignored))))
        (cons 'hf-preamble (list (cons 'raw hf-preamble) (cons 'formatted (fmt-bytes hf-preamble))))
        )))

    (catch (e)
      (err (str "RFID-PN532-HCI parse error: " e)))))

;; dissect-rfid-pn532-hci: parse RFID-PN532-HCI from bytevector
;; Returns (ok fields-alist) or (err message)