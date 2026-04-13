;; packet-lbtrm.c
;; Routines for LBT-RM Packet dissection
;;
;; Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lbtrm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lbtrm.c

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
(def (dissect-lbtrm buffer)
  "LBT Reliable Multicast Protocol"
  (try
    (let* (
           (analysis-next-ncf-frame (unwrap (read-u32be buffer 0)))
           (analysis-prev-ncf-frame (unwrap (read-u32be buffer 0)))
           (analysis-next-nak-frame (unwrap (read-u32be buffer 0)))
           (analysis-prev-nak-frame (unwrap (read-u32be buffer 0)))
           (analysis-sm-duplicate (unwrap (read-u8 buffer 0)))
           (analysis-sm-ooo-gap (unwrap (read-u32be buffer 0)))
           (analysis-sm-sqn-gap (unwrap (read-u32be buffer 0)))
           (analysis-next-sm-frame (unwrap (read-u32be buffer 0)))
           (analysis-prev-sm-frame (unwrap (read-u32be buffer 0)))
           (analysis-data-duplicate (unwrap (read-u8 buffer 0)))
           (analysis-data-ooo-gap (unwrap (read-u32be buffer 0)))
           (analysis-data-sqn-gap (unwrap (read-u32be buffer 0)))
           (analysis-data-retransmission (unwrap (read-u8 buffer 0)))
           (analysis-next-data-frame (unwrap (read-u32be buffer 0)))
           (analysis-prev-data-frame (unwrap (read-u32be buffer 0)))
           (analysis-next-frame (unwrap (read-u32be buffer 0)))
           (analysis-prev-frame (unwrap (read-u32be buffer 0)))
           (tag (unwrap (slice buffer 0 1)))
           (channel (unwrap (read-u64be buffer 0)))
           )

      (ok (list
        (cons 'analysis-next-ncf-frame (list (cons 'raw analysis-next-ncf-frame) (cons 'formatted (number->string analysis-next-ncf-frame))))
        (cons 'analysis-prev-ncf-frame (list (cons 'raw analysis-prev-ncf-frame) (cons 'formatted (number->string analysis-prev-ncf-frame))))
        (cons 'analysis-next-nak-frame (list (cons 'raw analysis-next-nak-frame) (cons 'formatted (number->string analysis-next-nak-frame))))
        (cons 'analysis-prev-nak-frame (list (cons 'raw analysis-prev-nak-frame) (cons 'formatted (number->string analysis-prev-nak-frame))))
        (cons 'analysis-sm-duplicate (list (cons 'raw analysis-sm-duplicate) (cons 'formatted (number->string analysis-sm-duplicate))))
        (cons 'analysis-sm-ooo-gap (list (cons 'raw analysis-sm-ooo-gap) (cons 'formatted (number->string analysis-sm-ooo-gap))))
        (cons 'analysis-sm-sqn-gap (list (cons 'raw analysis-sm-sqn-gap) (cons 'formatted (number->string analysis-sm-sqn-gap))))
        (cons 'analysis-next-sm-frame (list (cons 'raw analysis-next-sm-frame) (cons 'formatted (number->string analysis-next-sm-frame))))
        (cons 'analysis-prev-sm-frame (list (cons 'raw analysis-prev-sm-frame) (cons 'formatted (number->string analysis-prev-sm-frame))))
        (cons 'analysis-data-duplicate (list (cons 'raw analysis-data-duplicate) (cons 'formatted (number->string analysis-data-duplicate))))
        (cons 'analysis-data-ooo-gap (list (cons 'raw analysis-data-ooo-gap) (cons 'formatted (number->string analysis-data-ooo-gap))))
        (cons 'analysis-data-sqn-gap (list (cons 'raw analysis-data-sqn-gap) (cons 'formatted (number->string analysis-data-sqn-gap))))
        (cons 'analysis-data-retransmission (list (cons 'raw analysis-data-retransmission) (cons 'formatted (number->string analysis-data-retransmission))))
        (cons 'analysis-next-data-frame (list (cons 'raw analysis-next-data-frame) (cons 'formatted (number->string analysis-next-data-frame))))
        (cons 'analysis-prev-data-frame (list (cons 'raw analysis-prev-data-frame) (cons 'formatted (number->string analysis-prev-data-frame))))
        (cons 'analysis-next-frame (list (cons 'raw analysis-next-frame) (cons 'formatted (number->string analysis-next-frame))))
        (cons 'analysis-prev-frame (list (cons 'raw analysis-prev-frame) (cons 'formatted (number->string analysis-prev-frame))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (utf8->string tag))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (fmt-hex channel))))
        )))

    (catch (e)
      (err (str "LBTRM parse error: " e)))))

;; dissect-lbtrm: parse LBTRM from bytevector
;; Returns (ok fields-alist) or (err message)