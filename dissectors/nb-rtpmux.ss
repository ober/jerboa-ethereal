;; packet-nb_rtpmux.c
;; Routines for 3GPP RTP Multiplex dissection, 3GPP TS 29.414
;; Copyright 2009, ip.access ltd <amp@ipaccess.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nb-rtpmux.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nb_rtpmux.c

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
(def (dissect-nb-rtpmux buffer)
  "3GPP Nb Interface RTP Multiplex"
  (try
    (let* (
           (rtpmux-dstport (unwrap (read-u16be buffer 0)))
           (rtpmux-length (unwrap (read-u8 buffer 0)))
           (r-bit (unwrap (read-u8 buffer 0)))
           (rtpmux-srcport (unwrap (read-u16be buffer 0)))
           (rtpmux-cmp-rtp-sequence-no (unwrap (read-u16be buffer 0)))
           (rtpmux-cmp-rtp-timestamp (unwrap (read-u16be buffer 0)))
           (rtpmux-cmp-rtp-data (unwrap (slice buffer 0 1)))
           (rtpmux-data (unwrap (slice buffer 0 1)))
           (rtpmux-compressed (unwrap (read-u8 buffer 2)))
           )

      (ok (list
        (cons 'rtpmux-dstport (list (cons 'raw rtpmux-dstport) (cons 'formatted (number->string rtpmux-dstport))))
        (cons 'rtpmux-length (list (cons 'raw rtpmux-length) (cons 'formatted (number->string rtpmux-length))))
        (cons 'r-bit (list (cons 'raw r-bit) (cons 'formatted (number->string r-bit))))
        (cons 'rtpmux-srcport (list (cons 'raw rtpmux-srcport) (cons 'formatted (number->string rtpmux-srcport))))
        (cons 'rtpmux-cmp-rtp-sequence-no (list (cons 'raw rtpmux-cmp-rtp-sequence-no) (cons 'formatted (number->string rtpmux-cmp-rtp-sequence-no))))
        (cons 'rtpmux-cmp-rtp-timestamp (list (cons 'raw rtpmux-cmp-rtp-timestamp) (cons 'formatted (number->string rtpmux-cmp-rtp-timestamp))))
        (cons 'rtpmux-cmp-rtp-data (list (cons 'raw rtpmux-cmp-rtp-data) (cons 'formatted (fmt-bytes rtpmux-cmp-rtp-data))))
        (cons 'rtpmux-data (list (cons 'raw rtpmux-data) (cons 'formatted (fmt-bytes rtpmux-data))))
        (cons 'rtpmux-compressed (list (cons 'raw rtpmux-compressed) (cons 'formatted (number->string rtpmux-compressed))))
        )))

    (catch (e)
      (err (str "NB-RTPMUX parse error: " e)))))

;; dissect-nb-rtpmux: parse NB-RTPMUX from bytevector
;; Returns (ok fields-alist) or (err message)