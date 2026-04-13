;; packet-bthci_iso.c
;; Routines for the Bluetooth ISO dissection
;; Copyright 2020, Jakub Pawlowski <jpawlowski@google.com>
;; Copyright 2020, Allan M. Madsen <almomadk@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bthci-iso.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bthci_iso.c

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
(def (dissect-bthci-iso buffer)
  "Bluetooth HCI ISO Packet"
  (try
    (let* (
           (iso-disconnect-in (unwrap (read-u32be buffer 0)))
           (iso-connect-in (unwrap (read-u32be buffer 0)))
           (iso-continuation-to (unwrap (read-u32be buffer 0)))
           (iso-reassembled-in (unwrap (read-u32be buffer 0)))
           (iso-chandle (unwrap (read-u16be buffer 0)))
           (iso-ts-flag (unwrap (read-u8 buffer 0)))
           (iso-reserved (unwrap (read-u16be buffer 0)))
           (iso-data-length (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'iso-disconnect-in (list (cons 'raw iso-disconnect-in) (cons 'formatted (number->string iso-disconnect-in))))
        (cons 'iso-connect-in (list (cons 'raw iso-connect-in) (cons 'formatted (number->string iso-connect-in))))
        (cons 'iso-continuation-to (list (cons 'raw iso-continuation-to) (cons 'formatted (number->string iso-continuation-to))))
        (cons 'iso-reassembled-in (list (cons 'raw iso-reassembled-in) (cons 'formatted (number->string iso-reassembled-in))))
        (cons 'iso-chandle (list (cons 'raw iso-chandle) (cons 'formatted (fmt-hex iso-chandle))))
        (cons 'iso-ts-flag (list (cons 'raw iso-ts-flag) (cons 'formatted (number->string iso-ts-flag))))
        (cons 'iso-reserved (list (cons 'raw iso-reserved) (cons 'formatted (fmt-hex iso-reserved))))
        (cons 'iso-data-length (list (cons 'raw iso-data-length) (cons 'formatted (number->string iso-data-length))))
        )))

    (catch (e)
      (err (str "BTHCI-ISO parse error: " e)))))

;; dissect-bthci-iso: parse BTHCI-ISO from bytevector
;; Returns (ok fields-alist) or (err message)