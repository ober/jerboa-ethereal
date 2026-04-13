;; packet-ositp.c
;; Routines for ISO/OSI transport protocol (connection-oriented
;; and connectionless) packet disassembly
;;
;; Laurent Deniel <laurent.deniel@free.fr>
;; Ralf Schneider <Ralf.Schneider@t-online.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ositp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ositp.c

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
(def (dissect-ositp buffer)
  "ositp dissector"
  (try
    (let* (
           (parameter-length (unwrap (read-u8 buffer 1)))
           (ack-time (unwrap (read-u16be buffer 2)))
           (res-error-rate-target-value (unwrap (read-u8 buffer 2)))
           (res-error-rate-min-accept (unwrap (read-u8 buffer 3)))
           (res-error-rate-tdsu (unwrap (read-u8 buffer 4)))
           (vp-priority (unwrap (read-u16be buffer 5)))
           (transit-delay-targ-calling-called (unwrap (read-u16be buffer 5)))
           (transit-delay-max-accept-calling-called (unwrap (read-u16be buffer 7)))
           (transit-delay-targ-called-calling (unwrap (read-u16be buffer 9)))
           (transit-delay-max-accept-called-calling (unwrap (read-u16be buffer 11)))
           (max-throughput-targ-calling-called (unwrap (read-u24be buffer 13)))
           (max-throughput-min-accept-calling-called (unwrap (read-u24be buffer 16)))
           (max-throughput-targ-called-calling (unwrap (read-u24be buffer 19)))
           (max-throughput-min-accept-called-calling (unwrap (read-u24be buffer 22)))
           (avg-throughput-targ-calling-called (unwrap (read-u24be buffer 25)))
           (avg-throughput-min-accept-calling-called (unwrap (read-u24be buffer 28)))
           (avg-throughput-targ-called-calling (unwrap (read-u24be buffer 31)))
           (avg-throughput-min-accept-called-calling (unwrap (read-u24be buffer 34)))
           (reassignment-time (unwrap (read-u16be buffer 37)))
           (lower-window-edge (unwrap (read-u32be buffer 37)))
           (sequence-number (unwrap (read-u16be buffer 41)))
           (tpdu-size (unwrap (read-u8 buffer 45)))
           (vp-src-tsap (unwrap (slice buffer 45 1)))
           (vp-src-tsap-bytes (unwrap (slice buffer 45 1)))
           (vp-dst-tsap (unwrap (slice buffer 45 1)))
           (vp-dst-tsap-bytes (unwrap (slice buffer 45 1)))
           (vp-version-nr (unwrap (read-u8 buffer 45)))
           (network-expedited-data (unwrap (read-u8 buffer 45)))
           (vp-opt-sel-class1-use (unwrap (read-u8 buffer 45)))
           (use-16-bit-checksum (unwrap (read-u8 buffer 45)))
           (transport-expedited-data-transfer (unwrap (read-u8 buffer 45)))
           (preferred-maximum-tpdu-size (unwrap (read-u32be buffer 45)))
           (inactivity-timer (unwrap (read-u32be buffer 45)))
           (parameter-value (unwrap (slice buffer 45 1)))
           (eot-extended (unwrap (read-u8 buffer 56)))
           (eot (unwrap (read-u8 buffer 60)))
           (tpdu-number-extended (unwrap (read-u32be buffer 65)))
           (tpdu-number (unwrap (read-u8 buffer 69)))
           (srcref (unwrap (read-u16be buffer 81)))
           (credit-cdt (unwrap (read-u8 buffer 84)))
           (credit (unwrap (read-u16be buffer 96)))
           (next-tpdu-number-extended (unwrap (read-u32be buffer 102)))
           (next-tpdu-number (unwrap (read-u8 buffer 106)))
           (destref (unwrap (read-u16be buffer 107)))
           (li (unwrap (read-u8 buffer 112)))
           )

      (ok (list
        (cons 'parameter-length (list (cons 'raw parameter-length) (cons 'formatted (number->string parameter-length))))
        (cons 'ack-time (list (cons 'raw ack-time) (cons 'formatted (number->string ack-time))))
        (cons 'res-error-rate-target-value (list (cons 'raw res-error-rate-target-value) (cons 'formatted (number->string res-error-rate-target-value))))
        (cons 'res-error-rate-min-accept (list (cons 'raw res-error-rate-min-accept) (cons 'formatted (number->string res-error-rate-min-accept))))
        (cons 'res-error-rate-tdsu (list (cons 'raw res-error-rate-tdsu) (cons 'formatted (number->string res-error-rate-tdsu))))
        (cons 'vp-priority (list (cons 'raw vp-priority) (cons 'formatted (number->string vp-priority))))
        (cons 'transit-delay-targ-calling-called (list (cons 'raw transit-delay-targ-calling-called) (cons 'formatted (number->string transit-delay-targ-calling-called))))
        (cons 'transit-delay-max-accept-calling-called (list (cons 'raw transit-delay-max-accept-calling-called) (cons 'formatted (number->string transit-delay-max-accept-calling-called))))
        (cons 'transit-delay-targ-called-calling (list (cons 'raw transit-delay-targ-called-calling) (cons 'formatted (number->string transit-delay-targ-called-calling))))
        (cons 'transit-delay-max-accept-called-calling (list (cons 'raw transit-delay-max-accept-called-calling) (cons 'formatted (number->string transit-delay-max-accept-called-calling))))
        (cons 'max-throughput-targ-calling-called (list (cons 'raw max-throughput-targ-calling-called) (cons 'formatted (number->string max-throughput-targ-calling-called))))
        (cons 'max-throughput-min-accept-calling-called (list (cons 'raw max-throughput-min-accept-calling-called) (cons 'formatted (number->string max-throughput-min-accept-calling-called))))
        (cons 'max-throughput-targ-called-calling (list (cons 'raw max-throughput-targ-called-calling) (cons 'formatted (number->string max-throughput-targ-called-calling))))
        (cons 'max-throughput-min-accept-called-calling (list (cons 'raw max-throughput-min-accept-called-calling) (cons 'formatted (number->string max-throughput-min-accept-called-calling))))
        (cons 'avg-throughput-targ-calling-called (list (cons 'raw avg-throughput-targ-calling-called) (cons 'formatted (number->string avg-throughput-targ-calling-called))))
        (cons 'avg-throughput-min-accept-calling-called (list (cons 'raw avg-throughput-min-accept-calling-called) (cons 'formatted (number->string avg-throughput-min-accept-calling-called))))
        (cons 'avg-throughput-targ-called-calling (list (cons 'raw avg-throughput-targ-called-calling) (cons 'formatted (number->string avg-throughput-targ-called-calling))))
        (cons 'avg-throughput-min-accept-called-calling (list (cons 'raw avg-throughput-min-accept-called-calling) (cons 'formatted (number->string avg-throughput-min-accept-called-calling))))
        (cons 'reassignment-time (list (cons 'raw reassignment-time) (cons 'formatted (number->string reassignment-time))))
        (cons 'lower-window-edge (list (cons 'raw lower-window-edge) (cons 'formatted (fmt-hex lower-window-edge))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (fmt-hex sequence-number))))
        (cons 'tpdu-size (list (cons 'raw tpdu-size) (cons 'formatted (number->string tpdu-size))))
        (cons 'vp-src-tsap (list (cons 'raw vp-src-tsap) (cons 'formatted (utf8->string vp-src-tsap))))
        (cons 'vp-src-tsap-bytes (list (cons 'raw vp-src-tsap-bytes) (cons 'formatted (fmt-bytes vp-src-tsap-bytes))))
        (cons 'vp-dst-tsap (list (cons 'raw vp-dst-tsap) (cons 'formatted (utf8->string vp-dst-tsap))))
        (cons 'vp-dst-tsap-bytes (list (cons 'raw vp-dst-tsap-bytes) (cons 'formatted (fmt-bytes vp-dst-tsap-bytes))))
        (cons 'vp-version-nr (list (cons 'raw vp-version-nr) (cons 'formatted (number->string vp-version-nr))))
        (cons 'network-expedited-data (list (cons 'raw network-expedited-data) (cons 'formatted (if (= network-expedited-data 0) "False" "True"))))
        (cons 'vp-opt-sel-class1-use (list (cons 'raw vp-opt-sel-class1-use) (cons 'formatted (if (= vp-opt-sel-class1-use 0) "Explicit AK variant" "Receipt confirmation"))))
        (cons 'use-16-bit-checksum (list (cons 'raw use-16-bit-checksum) (cons 'formatted (if (= use-16-bit-checksum 0) "False" "True"))))
        (cons 'transport-expedited-data-transfer (list (cons 'raw transport-expedited-data-transfer) (cons 'formatted (if (= transport-expedited-data-transfer 0) "False" "True"))))
        (cons 'preferred-maximum-tpdu-size (list (cons 'raw preferred-maximum-tpdu-size) (cons 'formatted (number->string preferred-maximum-tpdu-size))))
        (cons 'inactivity-timer (list (cons 'raw inactivity-timer) (cons 'formatted (number->string inactivity-timer))))
        (cons 'parameter-value (list (cons 'raw parameter-value) (cons 'formatted (fmt-bytes parameter-value))))
        (cons 'eot-extended (list (cons 'raw eot-extended) (cons 'formatted (if (= eot-extended 0) "False" "True"))))
        (cons 'eot (list (cons 'raw eot) (cons 'formatted (if (= eot 0) "False" "True"))))
        (cons 'tpdu-number-extended (list (cons 'raw tpdu-number-extended) (cons 'formatted (fmt-hex tpdu-number-extended))))
        (cons 'tpdu-number (list (cons 'raw tpdu-number) (cons 'formatted (fmt-hex tpdu-number))))
        (cons 'srcref (list (cons 'raw srcref) (cons 'formatted (fmt-hex srcref))))
        (cons 'credit-cdt (list (cons 'raw credit-cdt) (cons 'formatted (number->string credit-cdt))))
        (cons 'credit (list (cons 'raw credit) (cons 'formatted (fmt-hex credit))))
        (cons 'next-tpdu-number-extended (list (cons 'raw next-tpdu-number-extended) (cons 'formatted (fmt-hex next-tpdu-number-extended))))
        (cons 'next-tpdu-number (list (cons 'raw next-tpdu-number) (cons 'formatted (fmt-hex next-tpdu-number))))
        (cons 'destref (list (cons 'raw destref) (cons 'formatted (fmt-hex destref))))
        (cons 'li (list (cons 'raw li) (cons 'formatted (number->string li))))
        )))

    (catch (e)
      (err (str "OSITP parse error: " e)))))

;; dissect-ositp: parse OSITP from bytevector
;; Returns (ok fields-alist) or (err message)