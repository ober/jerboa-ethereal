;; packet-gsm_a_rr.c
;; Routines for GSM A Interface (actually A-bis really) RR dissection - A.K.A. GSM layer 3 Radio Resource Protocol
;;
;; Copyright 2003, Michael Lum <mlum [AT] telostech.com>
;; In association with Telos Technology Inc.
;;
;; Added Dissection of Radio Resource Management Information Elements
;; and other enhancements and fixes.
;; Copyright 2005 - 2006, Anders Broman [AT] ericsson.com
;;
;; Added Dissection of E-UTRAN Description struct in
;; Cell selection indicator after release of all TCH and SDCCH IE
;; Lars Sundstrom X [AT] ericsson.com and Kjell Jansson [AT] ericsson.com
;; On Behalf of Ericsson AB
;;
;; Title        3GPP            Other
;;
;; Reference [3]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 4.7.0 Release 4)
;; (ETSI TS 124 008 V6.8.0 (2005-03))
;;
;; Reference [4]
;; Mobile radio interface layer 3 specification;
;; Radio Resource Control Protocol
;; (GSM 04.18 version 8.4.1 Release 1999)
;; (3GPP TS 04.18 version 8.26.0 Release 1999)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-a-rr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_a_rr.c

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
(def (dissect-gsm-a-rr buffer)
  "GSM A-I/F Radio Resource Management"
  (try
    (let* (
           (a-rr-padding (unwrap (slice buffer 0 1)))
           (a-rr-message-elements (unwrap (slice buffer 0 1)))
           (a-rr-arfcn-list (unwrap (slice buffer 21 1)))
           (a-rr-apdu-flags-cr (unwrap (read-u8 buffer 1962)))
           (a-rr-apdu-flags-fs (unwrap (read-u8 buffer 1962)))
           (a-rr-apdu-flags-ls (unwrap (read-u8 buffer 1962)))
           (a-rr-apdu-data (unwrap (slice buffer 1962 1)))
           (a-rr-ps-sd-tsc-ass (unwrap (read-u8 buffer 1964)))
           (a-rr-ps-sd-tsc-val (unwrap (read-u8 buffer 1964)))
           )

      (ok (list
        (cons 'a-rr-padding (list (cons 'raw a-rr-padding) (cons 'formatted (fmt-bytes a-rr-padding))))
        (cons 'a-rr-message-elements (list (cons 'raw a-rr-message-elements) (cons 'formatted (fmt-bytes a-rr-message-elements))))
        (cons 'a-rr-arfcn-list (list (cons 'raw a-rr-arfcn-list) (cons 'formatted (fmt-bytes a-rr-arfcn-list))))
        (cons 'a-rr-apdu-flags-cr (list (cons 'raw a-rr-apdu-flags-cr) (cons 'formatted (if (= a-rr-apdu-flags-cr 0) "False" "True"))))
        (cons 'a-rr-apdu-flags-fs (list (cons 'raw a-rr-apdu-flags-fs) (cons 'formatted (if (= a-rr-apdu-flags-fs 0) "False" "True"))))
        (cons 'a-rr-apdu-flags-ls (list (cons 'raw a-rr-apdu-flags-ls) (cons 'formatted (if (= a-rr-apdu-flags-ls 0) "False" "True"))))
        (cons 'a-rr-apdu-data (list (cons 'raw a-rr-apdu-data) (cons 'formatted (fmt-bytes a-rr-apdu-data))))
        (cons 'a-rr-ps-sd-tsc-ass (list (cons 'raw a-rr-ps-sd-tsc-ass) (cons 'formatted (if (= a-rr-ps-sd-tsc-ass 0) "False" "True"))))
        (cons 'a-rr-ps-sd-tsc-val (list (cons 'raw a-rr-ps-sd-tsc-val) (cons 'formatted (number->string a-rr-ps-sd-tsc-val))))
        )))

    (catch (e)
      (err (str "GSM-A-RR parse error: " e)))))

;; dissect-gsm-a-rr: parse GSM-A-RR from bytevector
;; Returns (ok fields-alist) or (err message)