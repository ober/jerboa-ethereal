;; packet-ubx-gps_l1_lnav.c
;; Dissection of Global Positioning System (GPS) L1 C/A LNAV navigation messages
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

;; jerboa-ethereal/dissectors/ubx-gps-l1-lnav.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ubx_gps_l1_lnav.c

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
(def (dissect-ubx-gps-l1-lnav buffer)
  "GPS L1 Navigation Message"
  (try
    (let* (
           (gps-l1-tlm-parity (unwrap (read-u32be buffer 0)))
           (gps-l1-tlm-reserved (unwrap (read-u32be buffer 0)))
           (gps-l1-tlm-integrity (unwrap (read-u8 buffer 0)))
           (gps-l1-tlm-message (unwrap (read-u32be buffer 0)))
           (gps-l1-tlm-preamble (unwrap (read-u32be buffer 0)))
           (gps-l1-how-parity (unwrap (read-u32be buffer 4)))
           (gps-l1-how-parity-sol (unwrap (read-u32be buffer 4)))
           (gps-l1-how-subframe-id (unwrap (read-u32be buffer 4)))
           (gps-l1-how-anti-spoof (unwrap (read-u8 buffer 4)))
           (gps-l1-how-alert (unwrap (read-u8 buffer 4)))
           (gps-l1-sf2-w3-parity (unwrap (read-u32be buffer 8)))
           (gps-l1-sf2-w3-iode (unwrap (read-u32be buffer 8)))
           (gps-l1-sf1-w3-parity (unwrap (read-u32be buffer 8)))
           (gps-l1-sf1-w3-iodc-msbs (unwrap (read-u32be buffer 8)))
           (gps-l1-sf1-w3-week-no (unwrap (read-u32be buffer 8)))
           (gps-l1-sf2-w4-parity (unwrap (read-u32be buffer 12)))
           (gps-l1-sf2-w4-m0-msbs (unwrap (read-u32be buffer 12)))
           (gps-l1-sf1-w4-parity (unwrap (read-u32be buffer 12)))
           (gps-l1-sf1-w4-reserved (unwrap (read-u32be buffer 12)))
           (gps-l1-sf1-w4-l2-p-data-flag (unwrap (read-u8 buffer 12)))
           (gps-l1-sf2-w5-parity (unwrap (read-u32be buffer 16)))
           (gps-l1-sf2-w5-m0-lsbs (unwrap (read-u32be buffer 16)))
           (gps-l1-sf1-w5-parity (unwrap (read-u32be buffer 16)))
           (gps-l1-sf1-w5-reserved (unwrap (read-u32be buffer 16)))
           (gps-l1-sf2-w6-parity (unwrap (read-u32be buffer 20)))
           (gps-l1-sf2-w6-e-msbs (unwrap (read-u32be buffer 20)))
           (gps-l1-sf1-w6-parity (unwrap (read-u32be buffer 20)))
           (gps-l1-sf1-w6-reserved (unwrap (read-u32be buffer 20)))
           (gps-l1-sf2-w7-parity (unwrap (read-u32be buffer 24)))
           (gps-l1-sf2-w7-e-lsbs (unwrap (read-u32be buffer 24)))
           (gps-l1-sf1-w7-parity (unwrap (read-u32be buffer 24)))
           (gps-l1-sf1-w7-tgd (unwrap (read-u32be buffer 24)))
           (gps-l1-sf1-w7-reserved (unwrap (read-u32be buffer 24)))
           (gps-l1-sf2-w8-parity (unwrap (read-u32be buffer 28)))
           (gps-l1-sf1-w8-parity (unwrap (read-u32be buffer 28)))
           (gps-l1-sf1-w8-iodc-lsbs (unwrap (read-u32be buffer 28)))
           (gps-l1-sf2-w9-parity (unwrap (read-u32be buffer 32)))
           (gps-l1-sf1-w9-parity (unwrap (read-u32be buffer 32)))
           (gps-l1-sf1-w9-af1 (unwrap (read-u32be buffer 32)))
           (gps-l1-sf1-w9-af2 (unwrap (read-u32be buffer 32)))
           (gps-l1-sf2-w10-parity (unwrap (read-u32be buffer 36)))
           (gps-l1-sf2-w10-t (unwrap (read-u32be buffer 36)))
           (gps-l1-sf1-w10-parity (unwrap (read-u32be buffer 36)))
           (gps-l1-sf1-w10-t (unwrap (read-u32be buffer 36)))
           (gps-l1-sf1-w10-af0 (unwrap (read-u32be buffer 36)))
           )

      (ok (list
        (cons 'gps-l1-tlm-parity (list (cons 'raw gps-l1-tlm-parity) (cons 'formatted (fmt-hex gps-l1-tlm-parity))))
        (cons 'gps-l1-tlm-reserved (list (cons 'raw gps-l1-tlm-reserved) (cons 'formatted (fmt-hex gps-l1-tlm-reserved))))
        (cons 'gps-l1-tlm-integrity (list (cons 'raw gps-l1-tlm-integrity) (cons 'formatted (number->string gps-l1-tlm-integrity))))
        (cons 'gps-l1-tlm-message (list (cons 'raw gps-l1-tlm-message) (cons 'formatted (fmt-hex gps-l1-tlm-message))))
        (cons 'gps-l1-tlm-preamble (list (cons 'raw gps-l1-tlm-preamble) (cons 'formatted (fmt-hex gps-l1-tlm-preamble))))
        (cons 'gps-l1-how-parity (list (cons 'raw gps-l1-how-parity) (cons 'formatted (number->string gps-l1-how-parity))))
        (cons 'gps-l1-how-parity-sol (list (cons 'raw gps-l1-how-parity-sol) (cons 'formatted (fmt-hex gps-l1-how-parity-sol))))
        (cons 'gps-l1-how-subframe-id (list (cons 'raw gps-l1-how-subframe-id) (cons 'formatted (number->string gps-l1-how-subframe-id))))
        (cons 'gps-l1-how-anti-spoof (list (cons 'raw gps-l1-how-anti-spoof) (cons 'formatted (number->string gps-l1-how-anti-spoof))))
        (cons 'gps-l1-how-alert (list (cons 'raw gps-l1-how-alert) (cons 'formatted (number->string gps-l1-how-alert))))
        (cons 'gps-l1-sf2-w3-parity (list (cons 'raw gps-l1-sf2-w3-parity) (cons 'formatted (fmt-hex gps-l1-sf2-w3-parity))))
        (cons 'gps-l1-sf2-w3-iode (list (cons 'raw gps-l1-sf2-w3-iode) (cons 'formatted (number->string gps-l1-sf2-w3-iode))))
        (cons 'gps-l1-sf1-w3-parity (list (cons 'raw gps-l1-sf1-w3-parity) (cons 'formatted (fmt-hex gps-l1-sf1-w3-parity))))
        (cons 'gps-l1-sf1-w3-iodc-msbs (list (cons 'raw gps-l1-sf1-w3-iodc-msbs) (cons 'formatted (fmt-hex gps-l1-sf1-w3-iodc-msbs))))
        (cons 'gps-l1-sf1-w3-week-no (list (cons 'raw gps-l1-sf1-w3-week-no) (cons 'formatted (number->string gps-l1-sf1-w3-week-no))))
        (cons 'gps-l1-sf2-w4-parity (list (cons 'raw gps-l1-sf2-w4-parity) (cons 'formatted (fmt-hex gps-l1-sf2-w4-parity))))
        (cons 'gps-l1-sf2-w4-m0-msbs (list (cons 'raw gps-l1-sf2-w4-m0-msbs) (cons 'formatted (fmt-hex gps-l1-sf2-w4-m0-msbs))))
        (cons 'gps-l1-sf1-w4-parity (list (cons 'raw gps-l1-sf1-w4-parity) (cons 'formatted (fmt-hex gps-l1-sf1-w4-parity))))
        (cons 'gps-l1-sf1-w4-reserved (list (cons 'raw gps-l1-sf1-w4-reserved) (cons 'formatted (fmt-hex gps-l1-sf1-w4-reserved))))
        (cons 'gps-l1-sf1-w4-l2-p-data-flag (list (cons 'raw gps-l1-sf1-w4-l2-p-data-flag) (cons 'formatted (number->string gps-l1-sf1-w4-l2-p-data-flag))))
        (cons 'gps-l1-sf2-w5-parity (list (cons 'raw gps-l1-sf2-w5-parity) (cons 'formatted (fmt-hex gps-l1-sf2-w5-parity))))
        (cons 'gps-l1-sf2-w5-m0-lsbs (list (cons 'raw gps-l1-sf2-w5-m0-lsbs) (cons 'formatted (fmt-hex gps-l1-sf2-w5-m0-lsbs))))
        (cons 'gps-l1-sf1-w5-parity (list (cons 'raw gps-l1-sf1-w5-parity) (cons 'formatted (fmt-hex gps-l1-sf1-w5-parity))))
        (cons 'gps-l1-sf1-w5-reserved (list (cons 'raw gps-l1-sf1-w5-reserved) (cons 'formatted (fmt-hex gps-l1-sf1-w5-reserved))))
        (cons 'gps-l1-sf2-w6-parity (list (cons 'raw gps-l1-sf2-w6-parity) (cons 'formatted (fmt-hex gps-l1-sf2-w6-parity))))
        (cons 'gps-l1-sf2-w6-e-msbs (list (cons 'raw gps-l1-sf2-w6-e-msbs) (cons 'formatted (fmt-hex gps-l1-sf2-w6-e-msbs))))
        (cons 'gps-l1-sf1-w6-parity (list (cons 'raw gps-l1-sf1-w6-parity) (cons 'formatted (fmt-hex gps-l1-sf1-w6-parity))))
        (cons 'gps-l1-sf1-w6-reserved (list (cons 'raw gps-l1-sf1-w6-reserved) (cons 'formatted (fmt-hex gps-l1-sf1-w6-reserved))))
        (cons 'gps-l1-sf2-w7-parity (list (cons 'raw gps-l1-sf2-w7-parity) (cons 'formatted (fmt-hex gps-l1-sf2-w7-parity))))
        (cons 'gps-l1-sf2-w7-e-lsbs (list (cons 'raw gps-l1-sf2-w7-e-lsbs) (cons 'formatted (fmt-hex gps-l1-sf2-w7-e-lsbs))))
        (cons 'gps-l1-sf1-w7-parity (list (cons 'raw gps-l1-sf1-w7-parity) (cons 'formatted (fmt-hex gps-l1-sf1-w7-parity))))
        (cons 'gps-l1-sf1-w7-tgd (list (cons 'raw gps-l1-sf1-w7-tgd) (cons 'formatted (number->string gps-l1-sf1-w7-tgd))))
        (cons 'gps-l1-sf1-w7-reserved (list (cons 'raw gps-l1-sf1-w7-reserved) (cons 'formatted (fmt-hex gps-l1-sf1-w7-reserved))))
        (cons 'gps-l1-sf2-w8-parity (list (cons 'raw gps-l1-sf2-w8-parity) (cons 'formatted (fmt-hex gps-l1-sf2-w8-parity))))
        (cons 'gps-l1-sf1-w8-parity (list (cons 'raw gps-l1-sf1-w8-parity) (cons 'formatted (fmt-hex gps-l1-sf1-w8-parity))))
        (cons 'gps-l1-sf1-w8-iodc-lsbs (list (cons 'raw gps-l1-sf1-w8-iodc-lsbs) (cons 'formatted (fmt-hex gps-l1-sf1-w8-iodc-lsbs))))
        (cons 'gps-l1-sf2-w9-parity (list (cons 'raw gps-l1-sf2-w9-parity) (cons 'formatted (fmt-hex gps-l1-sf2-w9-parity))))
        (cons 'gps-l1-sf1-w9-parity (list (cons 'raw gps-l1-sf1-w9-parity) (cons 'formatted (fmt-hex gps-l1-sf1-w9-parity))))
        (cons 'gps-l1-sf1-w9-af1 (list (cons 'raw gps-l1-sf1-w9-af1) (cons 'formatted (number->string gps-l1-sf1-w9-af1))))
        (cons 'gps-l1-sf1-w9-af2 (list (cons 'raw gps-l1-sf1-w9-af2) (cons 'formatted (number->string gps-l1-sf1-w9-af2))))
        (cons 'gps-l1-sf2-w10-parity (list (cons 'raw gps-l1-sf2-w10-parity) (cons 'formatted (fmt-hex gps-l1-sf2-w10-parity))))
        (cons 'gps-l1-sf2-w10-t (list (cons 'raw gps-l1-sf2-w10-t) (cons 'formatted (fmt-hex gps-l1-sf2-w10-t))))
        (cons 'gps-l1-sf1-w10-parity (list (cons 'raw gps-l1-sf1-w10-parity) (cons 'formatted (fmt-hex gps-l1-sf1-w10-parity))))
        (cons 'gps-l1-sf1-w10-t (list (cons 'raw gps-l1-sf1-w10-t) (cons 'formatted (fmt-hex gps-l1-sf1-w10-t))))
        (cons 'gps-l1-sf1-w10-af0 (list (cons 'raw gps-l1-sf1-w10-af0) (cons 'formatted (number->string gps-l1-sf1-w10-af0))))
        )))

    (catch (e)
      (err (str "UBX-GPS-L1-LNAV parse error: " e)))))

;; dissect-ubx-gps-l1-lnav: parse UBX-GPS-L1-LNAV from bytevector
;; Returns (ok fields-alist) or (err message)