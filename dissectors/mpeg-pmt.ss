;; packet-mpeg-pmt.c
;; Routines for MPEG2 (ISO/ISO 13818-1) Program Map Table (PMT) dissection
;; Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mpeg-pmt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mpeg_pmt.c

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
(def (dissect-mpeg-pmt buffer)
  "MPEG2 Program Map Table"
  (try
    (let* (
           (pmt-reserved1 (unwrap (read-u8 buffer 2)))
           (pmt-version-number (unwrap (read-u8 buffer 2)))
           (pmt-current-next-indicator (unwrap (read-u8 buffer 2)))
           (pmt-section-number (unwrap (read-u8 buffer 3)))
           (pmt-last-section-number (unwrap (read-u8 buffer 4)))
           (pmt-reserved2 (unwrap (read-u16be buffer 5)))
           (pmt-pcr-pid (unwrap (read-u16be buffer 5)))
           (pmt-reserved3 (unwrap (read-u16be buffer 7)))
           (pmt-program-info-length (unwrap (read-u16be buffer 7)))
           (pmt-stream-reserved1 (unwrap (read-u16be buffer 10)))
           (pmt-stream-elementary-pid (unwrap (read-u16be buffer 10)))
           (pmt-stream-reserved2 (unwrap (read-u16be buffer 12)))
           (pmt-stream-es-info-length (unwrap (read-u16be buffer 12)))
           (pmt-program-number (unwrap (read-u16be buffer 14)))
           )

      (ok (list
        (cons 'pmt-reserved1 (list (cons 'raw pmt-reserved1) (cons 'formatted (fmt-hex pmt-reserved1))))
        (cons 'pmt-version-number (list (cons 'raw pmt-version-number) (cons 'formatted (fmt-hex pmt-version-number))))
        (cons 'pmt-current-next-indicator (list (cons 'raw pmt-current-next-indicator) (cons 'formatted (if (= pmt-current-next-indicator 0) "False" "True"))))
        (cons 'pmt-section-number (list (cons 'raw pmt-section-number) (cons 'formatted (number->string pmt-section-number))))
        (cons 'pmt-last-section-number (list (cons 'raw pmt-last-section-number) (cons 'formatted (number->string pmt-last-section-number))))
        (cons 'pmt-reserved2 (list (cons 'raw pmt-reserved2) (cons 'formatted (fmt-hex pmt-reserved2))))
        (cons 'pmt-pcr-pid (list (cons 'raw pmt-pcr-pid) (cons 'formatted (fmt-hex pmt-pcr-pid))))
        (cons 'pmt-reserved3 (list (cons 'raw pmt-reserved3) (cons 'formatted (fmt-hex pmt-reserved3))))
        (cons 'pmt-program-info-length (list (cons 'raw pmt-program-info-length) (cons 'formatted (number->string pmt-program-info-length))))
        (cons 'pmt-stream-reserved1 (list (cons 'raw pmt-stream-reserved1) (cons 'formatted (fmt-hex pmt-stream-reserved1))))
        (cons 'pmt-stream-elementary-pid (list (cons 'raw pmt-stream-elementary-pid) (cons 'formatted (fmt-hex pmt-stream-elementary-pid))))
        (cons 'pmt-stream-reserved2 (list (cons 'raw pmt-stream-reserved2) (cons 'formatted (fmt-hex pmt-stream-reserved2))))
        (cons 'pmt-stream-es-info-length (list (cons 'raw pmt-stream-es-info-length) (cons 'formatted (number->string pmt-stream-es-info-length))))
        (cons 'pmt-program-number (list (cons 'raw pmt-program-number) (cons 'formatted (fmt-hex pmt-program-number))))
        )))

    (catch (e)
      (err (str "MPEG-PMT parse error: " e)))))

;; dissect-mpeg-pmt: parse MPEG-PMT from bytevector
;; Returns (ok fields-alist) or (err message)