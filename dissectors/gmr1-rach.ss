;; packet-gmr1_rach.c
;;
;; Routines for GMR-1 RACH dissection in wireshark.
;; Copyright (c) 2012 Sylvain Munaut <tnt@246tNt.com>
;;
;; References:
;; [1] ETSI TS 101 376-4-8 V1.3.1 - GMR-1 04.008
;; [2] ETSI TS 101 376-4-8 V2.2.1 - GMPRS-1 04.008
;; [3] ETSI TS 101 376-4-8 V3.1.1 - GMR-1 3G 44.008
;;
;; Especially [1] 10.1.8
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gmr1-rach.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gmr1_rach.c

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
(def (dissect-gmr1-rach buffer)
  "GEO-Mobile Radio (1) RACH"
  (try
    (let* (
           (retry-cnt (unwrap (read-u8 buffer 0)))
           (rand-ref (unwrap (read-u8 buffer 0)))
           (gps-pos-cpi (unwrap (read-u8 buffer 0)))
           (mes-pwr-class (unwrap (read-u8 buffer 0)))
           (number (unwrap (slice buffer 0 7)))
           (msc-id (unwrap (read-u8 buffer 0)))
           (software-version (unwrap (read-u8 buffer 0)))
           (spare (unwrap (read-u32be buffer 0)))
           (gci (unwrap (read-u8 buffer 0)))
           (r (unwrap (read-u8 buffer 0)))
           (o (unwrap (read-u8 buffer 0)))
           (gmprs-dl-peak-tput (unwrap (read-u8 buffer 0)))
           (gmprs-reserved1 (unwrap (read-u16be buffer 0)))
           (gmprs-spare1 (unwrap (read-u8 buffer 0)))
           (gmprs-tlli (unwrap (read-u32be buffer 0)))
           (gmprs-spare2 (unwrap (read-u8 buffer 0)))
           (gmprs-rlc-mode (unwrap (read-u8 buffer 0)))
           (gmprs-llc-mode (unwrap (read-u8 buffer 0)))
           (gmprs-spare3 (unwrap (read-u8 buffer 0)))
           (prio (unwrap (read-u8 buffer 7)))
           )

      (ok (list
        (cons 'retry-cnt (list (cons 'raw retry-cnt) (cons 'formatted (number->string retry-cnt))))
        (cons 'rand-ref (list (cons 'raw rand-ref) (cons 'formatted (fmt-hex rand-ref))))
        (cons 'gps-pos-cpi (list (cons 'raw gps-pos-cpi) (cons 'formatted (if (= gps-pos-cpi 0) "GPS position is old position" "GPS position is current position"))))
        (cons 'mes-pwr-class (list (cons 'raw mes-pwr-class) (cons 'formatted (number->string mes-pwr-class))))
        (cons 'number (list (cons 'raw number) (cons 'formatted (utf8->string number))))
        (cons 'msc-id (list (cons 'raw msc-id) (cons 'formatted (number->string msc-id))))
        (cons 'software-version (list (cons 'raw software-version) (cons 'formatted (number->string software-version))))
        (cons 'spare (list (cons 'raw spare) (cons 'formatted (number->string spare))))
        (cons 'gci (list (cons 'raw gci) (cons 'formatted (if (= gci 0) "MES is not GPS capable" "MES is GPS capable"))))
        (cons 'r (list (cons 'raw r) (cons 'formatted (if (= r 0) "Retry (see specs for details)" "Normal case"))))
        (cons 'o (list (cons 'raw o) (cons 'formatted (if (= o 0) "Normal case" "Retry after failed optimal routing attempt"))))
        (cons 'gmprs-dl-peak-tput (list (cons 'raw gmprs-dl-peak-tput) (cons 'formatted (number->string gmprs-dl-peak-tput))))
        (cons 'gmprs-reserved1 (list (cons 'raw gmprs-reserved1) (cons 'formatted (fmt-hex gmprs-reserved1))))
        (cons 'gmprs-spare1 (list (cons 'raw gmprs-spare1) (cons 'formatted (number->string gmprs-spare1))))
        (cons 'gmprs-tlli (list (cons 'raw gmprs-tlli) (cons 'formatted (fmt-hex gmprs-tlli))))
        (cons 'gmprs-spare2 (list (cons 'raw gmprs-spare2) (cons 'formatted (number->string gmprs-spare2))))
        (cons 'gmprs-rlc-mode (list (cons 'raw gmprs-rlc-mode) (cons 'formatted (if (= gmprs-rlc-mode 0) "Acknowledged" "Unacknowledged"))))
        (cons 'gmprs-llc-mode (list (cons 'raw gmprs-llc-mode) (cons 'formatted (if (= gmprs-llc-mode 0) "SACK/ACK packets" "Data packets"))))
        (cons 'gmprs-spare3 (list (cons 'raw gmprs-spare3) (cons 'formatted (number->string gmprs-spare3))))
        (cons 'prio (list (cons 'raw prio) (cons 'formatted (if (= prio 0) "Normal Call" "Priority Call"))))
        )))

    (catch (e)
      (err (str "GMR1-RACH parse error: " e)))))

;; dissect-gmr1-rach: parse GMR1-RACH from bytevector
;; Returns (ok fields-alist) or (err message)