;;
;; Dissector for the Sony FeliCa Protocol
;;
;; References:
;; http://www.sony.net/Products/felica/business/tech-support/data/fl_usmnl_1.2.pdf
;; http://www.sony.net/Products/felica/business/tech-support/data/fp_usmnl_1.11.pdf
;; http://www.sony.net/Products/felica/business/tech-support/data/format_sequence_guidelines_1.1.pdf
;; http://www.sony.net/Products/felica/business/tech-support/data/card_usersmanual_2.0.pdf
;; http://code.google.com/u/101410204121169118393/updates
;; https://github.com/codebutler/farebot/wiki/Suica
;;
;; Copyright 2012, Tyson Key <tyson.key@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;

;; jerboa-ethereal/dissectors/rfid-felica.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rfid_felica.c

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
(def (dissect-rfid-felica buffer)
  "Sony FeliCa"
  (try
    (let* (
           (idm (unwrap (read-u64be buffer 1)))
           (timeslot (unwrap (read-u8 buffer 4)))
           (status-flag1 (unwrap (read-u8 buffer 9)))
           (nbr-of-svcs (unwrap (read-u8 buffer 9)))
           (pnm (unwrap (read-u64be buffer 9)))
           (status-flag2 (unwrap (read-u8 buffer 10)))
           (svc-code (unwrap (read-u16be buffer 10)))
           (nbr-of-blocks (unwrap (read-u8 buffer 12)))
           )

      (ok (list
        (cons 'idm (list (cons 'raw idm) (cons 'formatted (fmt-hex idm))))
        (cons 'timeslot (list (cons 'raw timeslot) (cons 'formatted (fmt-hex timeslot))))
        (cons 'status-flag1 (list (cons 'raw status-flag1) (cons 'formatted (fmt-hex status-flag1))))
        (cons 'nbr-of-svcs (list (cons 'raw nbr-of-svcs) (cons 'formatted (number->string nbr-of-svcs))))
        (cons 'pnm (list (cons 'raw pnm) (cons 'formatted (fmt-hex pnm))))
        (cons 'status-flag2 (list (cons 'raw status-flag2) (cons 'formatted (fmt-hex status-flag2))))
        (cons 'svc-code (list (cons 'raw svc-code) (cons 'formatted (fmt-hex svc-code))))
        (cons 'nbr-of-blocks (list (cons 'raw nbr-of-blocks) (cons 'formatted (number->string nbr-of-blocks))))
        )))

    (catch (e)
      (err (str "RFID-FELICA parse error: " e)))))

;; dissect-rfid-felica: parse RFID-FELICA from bytevector
;; Returns (ok fields-alist) or (err message)