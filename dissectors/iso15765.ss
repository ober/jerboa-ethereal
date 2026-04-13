;; packet-iso15765.c
;; Routines for iso15765 protocol packet disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/iso15765.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iso15765.c

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
(def (dissect-iso15765 buffer)
  "ISO15765 Protocol"
  (try
    (let* (
           (address (unwrap (read-u8 buffer 0)))
           (source-address (unwrap (read-u16be buffer 0)))
           (data-length-4bit (unwrap (read-u8 buffer 2)))
           (frame-length-12bit (unwrap (read-u16be buffer 9)))
           (fc-bs (unwrap (read-u8 buffer 13)))
           (fc-stmin-in-us (unwrap (read-u8 buffer 14)))
           (fc-stmin (unwrap (read-u8 buffer 14)))
           (autosar-ack (unwrap (read-u8 buffer 15)))
           (sequence-number (unwrap (read-u8 buffer 15)))
           (data-length-8bit (unwrap (read-u8 buffer 17)))
           (frame-length-32bit (unwrap (read-u32be buffer 19)))
           (segment-data (unwrap (slice buffer 23 1)))
           (padding (unwrap (slice buffer 23 1)))
           )

      (ok (list
        (cons 'address (list (cons 'raw address) (cons 'formatted (fmt-hex address))))
        (cons 'source-address (list (cons 'raw source-address) (cons 'formatted (fmt-hex source-address))))
        (cons 'data-length-4bit (list (cons 'raw data-length-4bit) (cons 'formatted (number->string data-length-4bit))))
        (cons 'frame-length-12bit (list (cons 'raw frame-length-12bit) (cons 'formatted (number->string frame-length-12bit))))
        (cons 'fc-bs (list (cons 'raw fc-bs) (cons 'formatted (fmt-hex fc-bs))))
        (cons 'fc-stmin-in-us (list (cons 'raw fc-stmin-in-us) (cons 'formatted (number->string fc-stmin-in-us))))
        (cons 'fc-stmin (list (cons 'raw fc-stmin) (cons 'formatted (number->string fc-stmin))))
        (cons 'autosar-ack (list (cons 'raw autosar-ack) (cons 'formatted (fmt-hex autosar-ack))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (fmt-hex sequence-number))))
        (cons 'data-length-8bit (list (cons 'raw data-length-8bit) (cons 'formatted (number->string data-length-8bit))))
        (cons 'frame-length-32bit (list (cons 'raw frame-length-32bit) (cons 'formatted (number->string frame-length-32bit))))
        (cons 'segment-data (list (cons 'raw segment-data) (cons 'formatted (fmt-bytes segment-data))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        )))

    (catch (e)
      (err (str "ISO15765 parse error: " e)))))

;; dissect-iso15765: parse ISO15765 from bytevector
;; Returns (ok fields-alist) or (err message)