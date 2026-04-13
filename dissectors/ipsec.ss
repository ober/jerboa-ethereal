;; packet-ipsec.c
;; Routines for IPsec/IPComp packet disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ipsec.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ipsec.c
;; RFC 4305

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
(def (dissect-ipsec buffer)
  "Authentication Header"
  (try
    (let* (
           (next-header (unwrap (read-u8 buffer 0)))
           (sequence-analysis-previous-frame (unwrap (read-u32be buffer 0)))
           (sequence-analysis-expected-sn (unwrap (read-u32be buffer 0)))
           (pad (unwrap (slice buffer 0 1)))
           (pad-len (unwrap (read-u8 buffer 0)))
           (protocol (unwrap (read-u8 buffer 0)))
           (encrypted-data (unwrap (slice buffer 0 1)))
           (icv (unwrap (slice buffer 0 1)))
           (icv-good (unwrap (read-u8 buffer 0)))
           (icv-bad (unwrap (read-u8 buffer 0)))
           (flags (unwrap (read-u8 buffer 1)))
           (length (unwrap (read-u8 buffer 1)))
           (reserved (unwrap (slice buffer 2 2)))
           (spi (unwrap (read-u32be buffer 4)))
           (sequence (unwrap (read-u32be buffer 8)))
           (iv (unwrap (slice buffer 12 1)))
           )

      (ok (list
        (cons 'next-header (list (cons 'raw next-header) (cons 'formatted (fmt-hex next-header))))
        (cons 'sequence-analysis-previous-frame (list (cons 'raw sequence-analysis-previous-frame) (cons 'formatted (number->string sequence-analysis-previous-frame))))
        (cons 'sequence-analysis-expected-sn (list (cons 'raw sequence-analysis-expected-sn) (cons 'formatted (number->string sequence-analysis-expected-sn))))
        (cons 'pad (list (cons 'raw pad) (cons 'formatted (fmt-bytes pad))))
        (cons 'pad-len (list (cons 'raw pad-len) (cons 'formatted (number->string pad-len))))
        (cons 'protocol (list (cons 'raw protocol) (cons 'formatted (fmt-hex protocol))))
        (cons 'encrypted-data (list (cons 'raw encrypted-data) (cons 'formatted (fmt-bytes encrypted-data))))
        (cons 'icv (list (cons 'raw icv) (cons 'formatted (fmt-bytes icv))))
        (cons 'icv-good (list (cons 'raw icv-good) (cons 'formatted (number->string icv-good))))
        (cons 'icv-bad (list (cons 'raw icv-bad) (cons 'formatted (number->string icv-bad))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'spi (list (cons 'raw spi) (cons 'formatted (fmt-hex spi))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (number->string sequence))))
        (cons 'iv (list (cons 'raw iv) (cons 'formatted (fmt-bytes iv))))
        )))

    (catch (e)
      (err (str "IPSEC parse error: " e)))))

;; dissect-ipsec: parse IPSEC from bytevector
;; Returns (ok fields-alist) or (err message)