;; packet-ansi_a.c
;; Routines for ANSI A Interface (IS-634/IOS) dissection
;;
;; Copyright 2003, Michael Lum <mlum [AT] telostech.com>
;; In association with Telos Technology Inc.
;; Copyright 2008, Michael Lum <michael.lum [AT] starsolutions.com>
;; In association with Star Solutions
;;
;; Title                3GPP2                   Other
;;
;; Inter-operability Specification (IOS) for CDMA
;; 2000 Access Network Interfaces
;; 3GPP2 A.S0001-1         TIA/EIA-2001
;;
;; 3GPP2 C.R1001-H v1.0    TSB-58-I (or J?)
;;
;; RFC 5188
;; RTP Payload Format for the Enhanced Variable Rate Wideband Codec (EVRC-WB)
;; and the Media Subtype Updates for EVRC-B Codec
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ansi-a.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ansi_a.c
;; RFC 5188

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
(def (dissect-ansi-a buffer)
  "ANSI A-I/F BSMAP"
  (try
    (let* (
           (a-reserved-bits-8-f0 (unwrap (read-u8 buffer 0)))
           (a-protocol-disc (unwrap (read-u8 buffer 0)))
           (a-bsmap-msgtype (unwrap (read-u8 buffer 0)))
           (a-dtap-msgtype (unwrap (read-u8 buffer 0)))
           (a-reserved-octet (unwrap (read-u8 buffer 1)))
           (a-reserved-bits-8-0f (unwrap (read-u8 buffer 1)))
           (a-ti-ti (unwrap (read-u8 buffer 1)))
           (a-ti-flag (unwrap (read-u8 buffer 1)))
           (a-so-proprietary-ind (unwrap (read-u8 buffer 56)))
           (a-so-revision (unwrap (read-u16be buffer 56)))
           (a-so-base-so-num (unwrap (read-u16be buffer 56)))
           (a-so (unwrap (read-u16be buffer 56)))
           )

      (ok (list
        (cons 'a-reserved-bits-8-f0 (list (cons 'raw a-reserved-bits-8-f0) (cons 'formatted (number->string a-reserved-bits-8-f0))))
        (cons 'a-protocol-disc (list (cons 'raw a-protocol-disc) (cons 'formatted (number->string a-protocol-disc))))
        (cons 'a-bsmap-msgtype (list (cons 'raw a-bsmap-msgtype) (cons 'formatted (fmt-hex a-bsmap-msgtype))))
        (cons 'a-dtap-msgtype (list (cons 'raw a-dtap-msgtype) (cons 'formatted (fmt-hex a-dtap-msgtype))))
        (cons 'a-reserved-octet (list (cons 'raw a-reserved-octet) (cons 'formatted (number->string a-reserved-octet))))
        (cons 'a-reserved-bits-8-0f (list (cons 'raw a-reserved-bits-8-0f) (cons 'formatted (number->string a-reserved-bits-8-0f))))
        (cons 'a-ti-ti (list (cons 'raw a-ti-ti) (cons 'formatted (number->string a-ti-ti))))
        (cons 'a-ti-flag (list (cons 'raw a-ti-flag) (cons 'formatted (if (= a-ti-flag 0) "False" "True"))))
        (cons 'a-so-proprietary-ind (list (cons 'raw a-so-proprietary-ind) (cons 'formatted (if (= a-so-proprietary-ind 0) "False" "True"))))
        (cons 'a-so-revision (list (cons 'raw a-so-revision) (cons 'formatted (number->string a-so-revision))))
        (cons 'a-so-base-so-num (list (cons 'raw a-so-base-so-num) (cons 'formatted (number->string a-so-base-so-num))))
        (cons 'a-so (list (cons 'raw a-so) (cons 'formatted (number->string a-so))))
        )))

    (catch (e)
      (err (str "ANSI-A parse error: " e)))))

;; dissect-ansi-a: parse ANSI-A from bytevector
;; Returns (ok fields-alist) or (err message)