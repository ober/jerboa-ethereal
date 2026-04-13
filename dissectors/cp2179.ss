;; packet-cp2179.c
;; Routines for Communication Protocol 2179 (aka "Cooper 2179") Dissection
;; By Qiaoyin Yang (qiaoyin[DOT]yang[AT]gmail.com
;; Copyright 2014-2015,Schweitzer Engineering Laboratories
;;
;; Enhancements by Chris Bontje (cbontje<at>gmail<dot>com, Aug 2018
;; ***********************************************************************************************
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; ***********************************************************************************************
;; CP2179 protocol is a serial based protocol. The 2179 protocol is implemented with minor variations between vendors.
;; The RTAC implemented the 2179 client supporting a limited function codes and command codes. The RTAC doesn't support
;; multiple function codes in a single request and the dissector also doesn't support decoding these or corresponding responses.
;; Dissector Notes:
;; A brief explanation of how a request and response messages are formulated in 2179 protocol.
;; The CP2179 request messages will follow the pattern below:
;; AA AA BB CC DD DD XX XX .... XX EE EE
;;
;; A = 16-bit address field. The Most significant 5 bit is the Client address, the 11 bits for RTU address.
;; B = 8-bit Function code
;; C = 8-bit Command code
;; D = 16-bit Number of characters in the data field.
;; X = data field
;; E = 16-bit CRC
;;
;; AA AA BB CC DD EE EE XX XX ... XX FF FF
;;
;; A = 16-bit address field. The Most significant 5 bit is the Client address, the 11 bits for RTU address.
;; B = 8-bit Function code
;; C = 8-bit Status
;; D = 8-bit Port Status
;; E = 16-bit Number of characters
;; X = data field
;; F = 16-bit CRC
;; **********************************************************************************************

;; jerboa-ethereal/dissectors/cp2179.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cp2179.c

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
(def (dissect-cp2179 buffer)
  "CP2179 Protocol"
  (try
    (let* (
           (request-frame (unwrap (read-u32be buffer 0)))
           (master-address (unwrap (read-u16be buffer 0)))
           (rtu-address (unwrap (read-u16be buffer 0)))
           (reserved (unwrap (read-u8 buffer 2)))
           (speccalc-request-point (unwrap (read-u8 buffer 8)))
           (scaninc-startreq-point (unwrap (read-u8 buffer 9)))
           (scaninc-stopreq-point (unwrap (read-u8 buffer 9)))
           (nop-flag (unwrap (read-u8 buffer 13)))
           (rst-flag (unwrap (read-u8 buffer 13)))
           (status-byte (unwrap (read-u8 buffer 14)))
           (port-status-byte (unwrap (read-u8 buffer 15)))
           (number-characters (unwrap (read-u16be buffer 16)))
           (sbo-request-point (unwrap (read-u8 buffer 18)))
           (resetacc-request-point (unwrap (read-u8 buffer 19)))
           (specialcalc (unwrap (read-u32be buffer 20)))
           (accumulator (unwrap (read-u16be buffer 30)))
           (simplestatusbit (unwrap (read-u16le buffer 34)))
           (simplestatusbit0 (extract-bits simplestatusbit 0x1 0))
           (simplestatusbit1 (extract-bits simplestatusbit 0x2 1))
           (simplestatusbit2 (extract-bits simplestatusbit 0x4 2))
           (simplestatusbit3 (extract-bits simplestatusbit 0x8 3))
           (simplestatusbit4 (extract-bits simplestatusbit 0x10 4))
           (simplestatusbit5 (extract-bits simplestatusbit 0x20 5))
           (simplestatusbit6 (extract-bits simplestatusbit 0x40 6))
           (simplestatusbit7 (extract-bits simplestatusbit 0x80 7))
           (simplestatusbit8 (extract-bits simplestatusbit 0x100 8))
           (simplestatusbit9 (extract-bits simplestatusbit 0x200 9))
           (simplestatusbit10 (extract-bits simplestatusbit 0x400 10))
           (simplestatusbit11 (extract-bits simplestatusbit 0x800 11))
           (simplestatusbit12 (extract-bits simplestatusbit 0x1000 12))
           (simplestatusbit13 (extract-bits simplestatusbit 0x2000 13))
           (simplestatusbit14 (extract-bits simplestatusbit 0x4000 14))
           (simplestatusbit15 (extract-bits simplestatusbit 0x8000 15))
           (2bitstatus (unwrap (read-u16le buffer 36)))
           (2bitstatuschg0 (extract-bits 2bitstatus 0x1 0))
           (2bitstatuschg1 (extract-bits 2bitstatus 0x2 1))
           (2bitstatuschg2 (extract-bits 2bitstatus 0x4 2))
           (2bitstatuschg3 (extract-bits 2bitstatus 0x8 3))
           (2bitstatuschg4 (extract-bits 2bitstatus 0x10 4))
           (2bitstatuschg5 (extract-bits 2bitstatus 0x20 5))
           (2bitstatuschg6 (extract-bits 2bitstatus 0x40 6))
           (2bitstatuschg7 (extract-bits 2bitstatus 0x80 7))
           (2bitstatusstatus0 (extract-bits 2bitstatus 0x100 8))
           (2bitstatusstatus1 (extract-bits 2bitstatus 0x200 9))
           (2bitstatusstatus2 (extract-bits 2bitstatus 0x400 10))
           (2bitstatusstatus3 (extract-bits 2bitstatus 0x800 11))
           (2bitstatusstatus4 (extract-bits 2bitstatus 0x1000 12))
           (2bitstatusstatus5 (extract-bits 2bitstatus 0x2000 13))
           (2bitstatusstatus6 (extract-bits 2bitstatus 0x4000 14))
           (2bitstatusstatus7 (extract-bits 2bitstatus 0x8000 15))
           (timetag-moredata (unwrap (read-u8 buffer 38)))
           (timetag-numsets (unwrap (read-u8 buffer 38)))
           (timetag-event-type (unwrap (read-u8 buffer 39)))
           (timetag-event-date-hundreds (unwrap (read-u8 buffer 39)))
           (timetag-event-date-tens (unwrap (read-u8 buffer 39)))
           (timetag-event-hour (unwrap (read-u8 buffer 39)))
           (timetag-event-minute (unwrap (read-u8 buffer 39)))
           (timetag-event-second (unwrap (read-u8 buffer 39)))
           (analog-16bit (unwrap (read-u16be buffer 45)))
           (crc (unwrap (read-u16be buffer 47)))
           )

      (ok (list
        (cons 'request-frame (list (cons 'raw request-frame) (cons 'formatted (number->string request-frame))))
        (cons 'master-address (list (cons 'raw master-address) (cons 'formatted (number->string master-address))))
        (cons 'rtu-address (list (cons 'raw rtu-address) (cons 'formatted (number->string rtu-address))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'speccalc-request-point (list (cons 'raw speccalc-request-point) (cons 'formatted (number->string speccalc-request-point))))
        (cons 'scaninc-startreq-point (list (cons 'raw scaninc-startreq-point) (cons 'formatted (number->string scaninc-startreq-point))))
        (cons 'scaninc-stopreq-point (list (cons 'raw scaninc-stopreq-point) (cons 'formatted (number->string scaninc-stopreq-point))))
        (cons 'nop-flag (list (cons 'raw nop-flag) (cons 'formatted (number->string nop-flag))))
        (cons 'rst-flag (list (cons 'raw rst-flag) (cons 'formatted (number->string rst-flag))))
        (cons 'status-byte (list (cons 'raw status-byte) (cons 'formatted (number->string status-byte))))
        (cons 'port-status-byte (list (cons 'raw port-status-byte) (cons 'formatted (number->string port-status-byte))))
        (cons 'number-characters (list (cons 'raw number-characters) (cons 'formatted (number->string number-characters))))
        (cons 'sbo-request-point (list (cons 'raw sbo-request-point) (cons 'formatted (number->string sbo-request-point))))
        (cons 'resetacc-request-point (list (cons 'raw resetacc-request-point) (cons 'formatted (number->string resetacc-request-point))))
        (cons 'specialcalc (list (cons 'raw specialcalc) (cons 'formatted (number->string specialcalc))))
        (cons 'accumulator (list (cons 'raw accumulator) (cons 'formatted (number->string accumulator))))
        (cons 'simplestatusbit (list (cons 'raw simplestatusbit) (cons 'formatted (fmt-hex simplestatusbit))))
        (cons 'simplestatusbit0 (list (cons 'raw simplestatusbit0) (cons 'formatted (if (= simplestatusbit0 0) "Not set" "Set"))))
        (cons 'simplestatusbit1 (list (cons 'raw simplestatusbit1) (cons 'formatted (if (= simplestatusbit1 0) "Not set" "Set"))))
        (cons 'simplestatusbit2 (list (cons 'raw simplestatusbit2) (cons 'formatted (if (= simplestatusbit2 0) "Not set" "Set"))))
        (cons 'simplestatusbit3 (list (cons 'raw simplestatusbit3) (cons 'formatted (if (= simplestatusbit3 0) "Not set" "Set"))))
        (cons 'simplestatusbit4 (list (cons 'raw simplestatusbit4) (cons 'formatted (if (= simplestatusbit4 0) "Not set" "Set"))))
        (cons 'simplestatusbit5 (list (cons 'raw simplestatusbit5) (cons 'formatted (if (= simplestatusbit5 0) "Not set" "Set"))))
        (cons 'simplestatusbit6 (list (cons 'raw simplestatusbit6) (cons 'formatted (if (= simplestatusbit6 0) "Not set" "Set"))))
        (cons 'simplestatusbit7 (list (cons 'raw simplestatusbit7) (cons 'formatted (if (= simplestatusbit7 0) "Not set" "Set"))))
        (cons 'simplestatusbit8 (list (cons 'raw simplestatusbit8) (cons 'formatted (if (= simplestatusbit8 0) "Not set" "Set"))))
        (cons 'simplestatusbit9 (list (cons 'raw simplestatusbit9) (cons 'formatted (if (= simplestatusbit9 0) "Not set" "Set"))))
        (cons 'simplestatusbit10 (list (cons 'raw simplestatusbit10) (cons 'formatted (if (= simplestatusbit10 0) "Not set" "Set"))))
        (cons 'simplestatusbit11 (list (cons 'raw simplestatusbit11) (cons 'formatted (if (= simplestatusbit11 0) "Not set" "Set"))))
        (cons 'simplestatusbit12 (list (cons 'raw simplestatusbit12) (cons 'formatted (if (= simplestatusbit12 0) "Not set" "Set"))))
        (cons 'simplestatusbit13 (list (cons 'raw simplestatusbit13) (cons 'formatted (if (= simplestatusbit13 0) "Not set" "Set"))))
        (cons 'simplestatusbit14 (list (cons 'raw simplestatusbit14) (cons 'formatted (if (= simplestatusbit14 0) "Not set" "Set"))))
        (cons 'simplestatusbit15 (list (cons 'raw simplestatusbit15) (cons 'formatted (if (= simplestatusbit15 0) "Not set" "Set"))))
        (cons '2bitstatus (list (cons 'raw 2bitstatus) (cons 'formatted (fmt-hex 2bitstatus))))
        (cons '2bitstatuschg0 (list (cons 'raw 2bitstatuschg0) (cons 'formatted (if (= 2bitstatuschg0 0) "Not set" "Set"))))
        (cons '2bitstatuschg1 (list (cons 'raw 2bitstatuschg1) (cons 'formatted (if (= 2bitstatuschg1 0) "Not set" "Set"))))
        (cons '2bitstatuschg2 (list (cons 'raw 2bitstatuschg2) (cons 'formatted (if (= 2bitstatuschg2 0) "Not set" "Set"))))
        (cons '2bitstatuschg3 (list (cons 'raw 2bitstatuschg3) (cons 'formatted (if (= 2bitstatuschg3 0) "Not set" "Set"))))
        (cons '2bitstatuschg4 (list (cons 'raw 2bitstatuschg4) (cons 'formatted (if (= 2bitstatuschg4 0) "Not set" "Set"))))
        (cons '2bitstatuschg5 (list (cons 'raw 2bitstatuschg5) (cons 'formatted (if (= 2bitstatuschg5 0) "Not set" "Set"))))
        (cons '2bitstatuschg6 (list (cons 'raw 2bitstatuschg6) (cons 'formatted (if (= 2bitstatuschg6 0) "Not set" "Set"))))
        (cons '2bitstatuschg7 (list (cons 'raw 2bitstatuschg7) (cons 'formatted (if (= 2bitstatuschg7 0) "Not set" "Set"))))
        (cons '2bitstatusstatus0 (list (cons 'raw 2bitstatusstatus0) (cons 'formatted (if (= 2bitstatusstatus0 0) "Not set" "Set"))))
        (cons '2bitstatusstatus1 (list (cons 'raw 2bitstatusstatus1) (cons 'formatted (if (= 2bitstatusstatus1 0) "Not set" "Set"))))
        (cons '2bitstatusstatus2 (list (cons 'raw 2bitstatusstatus2) (cons 'formatted (if (= 2bitstatusstatus2 0) "Not set" "Set"))))
        (cons '2bitstatusstatus3 (list (cons 'raw 2bitstatusstatus3) (cons 'formatted (if (= 2bitstatusstatus3 0) "Not set" "Set"))))
        (cons '2bitstatusstatus4 (list (cons 'raw 2bitstatusstatus4) (cons 'formatted (if (= 2bitstatusstatus4 0) "Not set" "Set"))))
        (cons '2bitstatusstatus5 (list (cons 'raw 2bitstatusstatus5) (cons 'formatted (if (= 2bitstatusstatus5 0) "Not set" "Set"))))
        (cons '2bitstatusstatus6 (list (cons 'raw 2bitstatusstatus6) (cons 'formatted (if (= 2bitstatusstatus6 0) "Not set" "Set"))))
        (cons '2bitstatusstatus7 (list (cons 'raw 2bitstatusstatus7) (cons 'formatted (if (= 2bitstatusstatus7 0) "Not set" "Set"))))
        (cons 'timetag-moredata (list (cons 'raw timetag-moredata) (cons 'formatted (number->string timetag-moredata))))
        (cons 'timetag-numsets (list (cons 'raw timetag-numsets) (cons 'formatted (number->string timetag-numsets))))
        (cons 'timetag-event-type (list (cons 'raw timetag-event-type) (cons 'formatted (number->string timetag-event-type))))
        (cons 'timetag-event-date-hundreds (list (cons 'raw timetag-event-date-hundreds) (cons 'formatted (number->string timetag-event-date-hundreds))))
        (cons 'timetag-event-date-tens (list (cons 'raw timetag-event-date-tens) (cons 'formatted (number->string timetag-event-date-tens))))
        (cons 'timetag-event-hour (list (cons 'raw timetag-event-hour) (cons 'formatted (number->string timetag-event-hour))))
        (cons 'timetag-event-minute (list (cons 'raw timetag-event-minute) (cons 'formatted (number->string timetag-event-minute))))
        (cons 'timetag-event-second (list (cons 'raw timetag-event-second) (cons 'formatted (number->string timetag-event-second))))
        (cons 'analog-16bit (list (cons 'raw analog-16bit) (cons 'formatted (number->string analog-16bit))))
        (cons 'crc (list (cons 'raw crc) (cons 'formatted (fmt-hex crc))))
        )))

    (catch (e)
      (err (str "CP2179 parse error: " e)))))

;; dissect-cp2179: parse CP2179 from bytevector
;; Returns (ok fields-alist) or (err message)