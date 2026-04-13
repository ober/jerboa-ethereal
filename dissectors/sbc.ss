;; packet-sbc.c
;; Routines for Bluetooth SBC dissection
;;
;; Copyright 2012, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sbc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sbc.c

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
(def (dissect-sbc buffer)
  "Bluetooth SBC Codec"
  (try
    (let* (
           (fragmented (unwrap (read-u8 buffer 0)))
           (starting-packet (unwrap (read-u8 buffer 0)))
           (last-packet (unwrap (read-u8 buffer 0)))
           (rfa (unwrap (read-u8 buffer 0)))
           (number-of-frames (unwrap (read-u8 buffer 0)))
           (syncword (unwrap (read-u8 buffer 1)))
           (bitpool (unwrap (read-u8 buffer 3)))
           (crc-check (unwrap (read-u8 buffer 4)))
           )

      (ok (list
        (cons 'fragmented (list (cons 'raw fragmented) (cons 'formatted (number->string fragmented))))
        (cons 'starting-packet (list (cons 'raw starting-packet) (cons 'formatted (number->string starting-packet))))
        (cons 'last-packet (list (cons 'raw last-packet) (cons 'formatted (number->string last-packet))))
        (cons 'rfa (list (cons 'raw rfa) (cons 'formatted (number->string rfa))))
        (cons 'number-of-frames (list (cons 'raw number-of-frames) (cons 'formatted (number->string number-of-frames))))
        (cons 'syncword (list (cons 'raw syncword) (cons 'formatted (fmt-hex syncword))))
        (cons 'bitpool (list (cons 'raw bitpool) (cons 'formatted (number->string bitpool))))
        (cons 'crc-check (list (cons 'raw crc-check) (cons 'formatted (fmt-hex crc-check))))
        )))

    (catch (e)
      (err (str "SBC parse error: " e)))))

;; dissect-sbc: parse SBC from bytevector
;; Returns (ok fields-alist) or (err message)