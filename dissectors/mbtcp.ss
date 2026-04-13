;; packet-mbtcp.c
;; Routines for Modbus/TCP and Modbus/UDP dissection
;; By Riaan Swart <rswart@cs.sun.ac.za>
;; Copyright 2001, Institute for Applied Computer Science
;; University of Stellenbosch
;;
;; See http://www.modbus.org/ for information on Modbus/TCP.
;;
;; Updated to v1.1b of the Modbus Application Protocol specification
;; Michael Mann * Copyright 2011
;;
;; ****************************************************************************************************
;; A brief explanation of the distinction between Modbus/TCP and Modbus RTU over TCP:
;;
;; Consider a Modbus poll message: Unit 01, Scan Holding Register Address 0 for 30 Registers
;;
;; The Modbus/TCP message structure will follow the pattern below:
;; 00 00 00 00 00 06 01 03 00 00 00 1E
;; AA AA BB BB CC CC DD EE FF FF GG GG
;;
;; A = 16-bit Transaction Identifier (typically increments, or is locked at zero)
;; B = 16-bit Protocol Identifier (typically zero)
;; C = 16-bit Length of data payload following (and inclusive of) the length byte
;; D = 8-bit Unit / Slave ID
;; E = 8-bit Modbus Function Code
;; F = 16-bit Reference Number / Register Base Address
;; G = 16-bit Word Count / Number of Registers to scan
;;
;; A identical Modbus RTU (or Modbus RTU over TCP) message will overlay partially with the msg above
;; and contain 16-bit CRC at the end:
;; 00 00 00 00 00 06 01 03 00 00 00 1E -- -- (Modbus/TCP message, repeated from above)
;; -- -- -- -- -- -- 01 03 00 00 00 1E C5 C2 (Modbus RTU over TCP message, includes 16-bit CRC footer)
;; AA AA BB BB CC CC DD EE FF FF GG GG HH HH
;;
;; A = Not present in Modbus RTU message
;; B = Not present in Modbus RTU message
;; C = Not present in Modbus RTU message
;; D = 8-bit Unit / Slave ID
;; E = 8-bit Modbus Function Code
;; F = 16-bit Reference Number / Register Base Address
;; G = 16-bit Word Count / Number of Registers to scan
;; H = 16-bit CRC
;;
;; ****************************************************************************************************
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mbtcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mbtcp.c

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
(def (dissect-mbtcp buffer)
  "Modbus/TCP"
  (try
    (let* (
           (request-frame (unwrap (read-u32be buffer 0)))
           (transid (unwrap (read-u16be buffer 0)))
           (exception (unwrap (read-u8 buffer 0)))
           (protid (unwrap (read-u16be buffer 2)))
           (len (unwrap (read-u16be buffer 4)))
           (unitid (unwrap (read-u8 buffer 6)))
           )

      (ok (list
        (cons 'request-frame (list (cons 'raw request-frame) (cons 'formatted (number->string request-frame))))
        (cons 'transid (list (cons 'raw transid) (cons 'formatted (number->string transid))))
        (cons 'exception (list (cons 'raw exception) (cons 'formatted (if (= exception 0) "False" "True"))))
        (cons 'protid (list (cons 'raw protid) (cons 'formatted (number->string protid))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'unitid (list (cons 'raw unitid) (cons 'formatted (number->string unitid))))
        )))

    (catch (e)
      (err (str "MBTCP parse error: " e)))))

;; dissect-mbtcp: parse MBTCP from bytevector
;; Returns (ok fields-alist) or (err message)