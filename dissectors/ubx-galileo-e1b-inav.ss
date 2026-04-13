;; packet-ubx-galileo_e1b_inav.c
;; Dissection of Galileo E1-B I/NAV navigation messages
;; (as provided by UBX-RXM-SFRBX).
;;
;; By Timo Warns <timo.warns@gmail.com>
;; Copyright 2023 Timo Warns
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@unicom.net>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ubx-galileo-e1b-inav.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ubx_galileo_e1b_inav.c

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
(def (dissect-ubx-galileo-e1b-inav buffer)
  "Galileo E1-B I/NAV Navigation Message"
  (try
    (let* (
           (gal-inav-data-122-67 (unwrap (read-u64be buffer 0)))
           (gal-inav-type (unwrap (read-u8 buffer 0)))
           (gal-inav-even-odd (unwrap (read-u8 buffer 0)))
           (gal-inav-data-66-17 (unwrap (read-u64be buffer 8)))
           (gal-inav-tail (unwrap (read-u8 buffer 14)))
           (gal-inav-pad (unwrap (read-u8 buffer 15)))
           (gal-inav-data-16-1 (unwrap (read-u64be buffer 16)))
           (gal-inav-osnma-mack (unwrap (read-u64be buffer 18)))
           (gal-inav-osnma-hkroot (unwrap (read-u32be buffer 18)))
           (gal-inav-sar-rlm-data (unwrap (read-u32be buffer 23)))
           (gal-inav-sar-long-rlm (unwrap (read-u8 buffer 23)))
           (gal-inav-sar-start-bit (unwrap (read-u8 buffer 23)))
           (gal-inav-crc (unwrap (read-u32be buffer 26)))
           (gal-inav-spare (unwrap (read-u8 buffer 26)))
           )

      (ok (list
        (cons 'gal-inav-data-122-67 (list (cons 'raw gal-inav-data-122-67) (cons 'formatted (fmt-hex gal-inav-data-122-67))))
        (cons 'gal-inav-type (list (cons 'raw gal-inav-type) (cons 'formatted (number->string gal-inav-type))))
        (cons 'gal-inav-even-odd (list (cons 'raw gal-inav-even-odd) (cons 'formatted (if (= gal-inav-even-odd 0) "False" "True"))))
        (cons 'gal-inav-data-66-17 (list (cons 'raw gal-inav-data-66-17) (cons 'formatted (fmt-hex gal-inav-data-66-17))))
        (cons 'gal-inav-tail (list (cons 'raw gal-inav-tail) (cons 'formatted (fmt-hex gal-inav-tail))))
        (cons 'gal-inav-pad (list (cons 'raw gal-inav-pad) (cons 'formatted (fmt-hex gal-inav-pad))))
        (cons 'gal-inav-data-16-1 (list (cons 'raw gal-inav-data-16-1) (cons 'formatted (fmt-hex gal-inav-data-16-1))))
        (cons 'gal-inav-osnma-mack (list (cons 'raw gal-inav-osnma-mack) (cons 'formatted (fmt-hex gal-inav-osnma-mack))))
        (cons 'gal-inav-osnma-hkroot (list (cons 'raw gal-inav-osnma-hkroot) (cons 'formatted (fmt-hex gal-inav-osnma-hkroot))))
        (cons 'gal-inav-sar-rlm-data (list (cons 'raw gal-inav-sar-rlm-data) (cons 'formatted (fmt-hex gal-inav-sar-rlm-data))))
        (cons 'gal-inav-sar-long-rlm (list (cons 'raw gal-inav-sar-long-rlm) (cons 'formatted (number->string gal-inav-sar-long-rlm))))
        (cons 'gal-inav-sar-start-bit (list (cons 'raw gal-inav-sar-start-bit) (cons 'formatted (number->string gal-inav-sar-start-bit))))
        (cons 'gal-inav-crc (list (cons 'raw gal-inav-crc) (cons 'formatted (fmt-hex gal-inav-crc))))
        (cons 'gal-inav-spare (list (cons 'raw gal-inav-spare) (cons 'formatted (fmt-hex gal-inav-spare))))
        )))

    (catch (e)
      (err (str "UBX-GALILEO-E1B-INAV parse error: " e)))))

;; dissect-ubx-galileo-e1b-inav: parse UBX-GALILEO-E1B-INAV from bytevector
;; Returns (ok fields-alist) or (err message)