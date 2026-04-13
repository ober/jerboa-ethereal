;; packet-gsm_a_bssmap.c
;; Routines for GSM A Interface BSSMAP dissection
;;
;; Copyright 2003, Michael Lum <mlum [AT] telostech.com>
;; In association with Telos Technology Inc.
;;
;; Updated to 3GPP TS 48.008 version 9.8.0 Release 9
;; Copyright 2008, Anders Broman <anders.broman [at] ericsson.com
;; Copyright 2012, Pascal Quantin <pascal.quantin [at] gmail.com
;; Title        3GPP            Other
;;
;; Reference [2]
;; Mobile-services Switching Centre - Base Station System
;; (MSC - BSS) interface;
;; Layer 3 specification
;; (GSM 08.08 version 7.7.0 Release 1998) TS 100 590 v7.7.0
;; 3GPP TS 48.008 version 8.4.0 Release 8
;; 3GPP TS 48.008 version 9.8.0 Release 9
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-a-bssmap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_a_bssmap.c

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
(def (dissect-gsm-a-bssmap buffer)
  "GSM A-I/F BSSMAP"
  (try
    (let* (
           (a-bssmap-message-elements (unwrap (slice buffer 0 1)))
           (a-bssmap-layer3-message-contents (unwrap (slice buffer 35 1)))
           (a-bssmap-vstk (unwrap (slice buffer 61 16)))
           (a-bssmap-data-id (unwrap (read-u8 buffer 61)))
           (a-bssmap-osmocom-osmux-cid (unwrap (read-u8 buffer 160)))
           )

      (ok (list
        (cons 'a-bssmap-message-elements (list (cons 'raw a-bssmap-message-elements) (cons 'formatted (fmt-bytes a-bssmap-message-elements))))
        (cons 'a-bssmap-layer3-message-contents (list (cons 'raw a-bssmap-layer3-message-contents) (cons 'formatted (fmt-bytes a-bssmap-layer3-message-contents))))
        (cons 'a-bssmap-vstk (list (cons 'raw a-bssmap-vstk) (cons 'formatted (fmt-bytes a-bssmap-vstk))))
        (cons 'a-bssmap-data-id (list (cons 'raw a-bssmap-data-id) (cons 'formatted (number->string a-bssmap-data-id))))
        (cons 'a-bssmap-osmocom-osmux-cid (list (cons 'raw a-bssmap-osmocom-osmux-cid) (cons 'formatted (number->string a-bssmap-osmocom-osmux-cid))))
        )))

    (catch (e)
      (err (str "GSM-A-BSSMAP parse error: " e)))))

;; dissect-gsm-a-bssmap: parse GSM-A-BSSMAP from bytevector
;; Returns (ok fields-alist) or (err message)