;; packet-gsm_cbch.c
;; Routines for GSM CBCH dissection - A.K.A. 3GPP 44.012 (GSM 04.12)
;;
;; Copyright 2011, Mike Morrin <mike.morrin [AT] ipaccess.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-cbch.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_cbch.c

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
(def (dissect-gsm-cbch buffer)
  "GSM Cell Broadcast Channel"
  (try
    (let* (
           (cbch-sched-spare (unwrap (read-u8 buffer 0)))
           (cbch-block (unwrap (read-u8 buffer 0)))
           (cbch-spare-bit (unwrap (read-u8 buffer 0)))
           (cbch-lb (unwrap (read-u8 buffer 0)))
           (cbch-slot (unwrap (read-u8 buffer 2)))
           (cbch-padding (unwrap (slice buffer 4 1)))
           )

      (ok (list
        (cons 'cbch-sched-spare (list (cons 'raw cbch-sched-spare) (cons 'formatted (number->string cbch-sched-spare))))
        (cons 'cbch-block (list (cons 'raw cbch-block) (cons 'formatted (fmt-hex cbch-block))))
        (cons 'cbch-spare-bit (list (cons 'raw cbch-spare-bit) (cons 'formatted (fmt-hex cbch-spare-bit))))
        (cons 'cbch-lb (list (cons 'raw cbch-lb) (cons 'formatted (number->string cbch-lb))))
        (cons 'cbch-slot (list (cons 'raw cbch-slot) (cons 'formatted (number->string cbch-slot))))
        (cons 'cbch-padding (list (cons 'raw cbch-padding) (cons 'formatted (fmt-bytes cbch-padding))))
        )))

    (catch (e)
      (err (str "GSM-CBCH parse error: " e)))))

;; dissect-gsm-cbch: parse GSM-CBCH from bytevector
;; Returns (ok fields-alist) or (err message)