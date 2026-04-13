;; packet-hsms.c
;; Routines for High-speed SECS message service dissection
;; Copyright 2016, Benjamin Parzella <bparzella@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hsms.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hsms.c

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
(def (dissect-hsms buffer)
  "High-speed SECS Message Service Protocol"
  (try
    (let* (
           (packet-length (unwrap (read-u32be buffer 0)))
           (header-sessionid (unwrap (read-u16be buffer 4)))
           (header-wbit (unwrap (read-u8 buffer 6)))
           (header-stream (unwrap (read-u8 buffer 6)))
           (header-function (unwrap (read-u8 buffer 7)))
           (header-statusbyte2 (unwrap (read-u8 buffer 8)))
           (header-statusbyte3 (unwrap (read-u8 buffer 9)))
           (header-system (unwrap (read-u32be buffer 12)))
           )

      (ok (list
        (cons 'packet-length (list (cons 'raw packet-length) (cons 'formatted (number->string packet-length))))
        (cons 'header-sessionid (list (cons 'raw header-sessionid) (cons 'formatted (number->string header-sessionid))))
        (cons 'header-wbit (list (cons 'raw header-wbit) (cons 'formatted (number->string header-wbit))))
        (cons 'header-stream (list (cons 'raw header-stream) (cons 'formatted (number->string header-stream))))
        (cons 'header-function (list (cons 'raw header-function) (cons 'formatted (number->string header-function))))
        (cons 'header-statusbyte2 (list (cons 'raw header-statusbyte2) (cons 'formatted (number->string header-statusbyte2))))
        (cons 'header-statusbyte3 (list (cons 'raw header-statusbyte3) (cons 'formatted (number->string header-statusbyte3))))
        (cons 'header-system (list (cons 'raw header-system) (cons 'formatted (number->string header-system))))
        )))

    (catch (e)
      (err (str "HSMS parse error: " e)))))

;; dissect-hsms: parse HSMS from bytevector
;; Returns (ok fields-alist) or (err message)