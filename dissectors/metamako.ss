;; packet-metamako.c
;; Routines for dissection of Metamako trailers. Forked from
;; packet-vssmonitoring.c on 20th December, 2015.
;; See https://www.metamako.com for further details.
;;
;; Copyright VSS-Monitoring 2011
;; Copyright Metamako LP 2015
;;
;; 20111205 - First edition by Sake Blok (sake.blok@SYN-bit.nl)
;; 20151220 - Forked to become packet-metamako.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/metamako.ss
;; Auto-generated from wireshark/epan/dissectors/packet-metamako.c

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
(def (dissect-metamako buffer)
  "Metamako ethernet trailer"
  (try
    (let* (
           (flags (unwrap (read-u8 buffer 12)))
           (flags-ts-degraded (extract-bits flags 0x10 4))
           (flags-duplicate (extract-bits flags 0x4 2))
           (flags-has-ext (extract-bits flags 0x2 1))
           (reserved (extract-bits flags 0xC8 3))
           (src-device (unwrap (read-u16be buffer 12)))
           (src-port (unwrap (read-u16be buffer 14)))
           (origfcs (unwrap (read-u32be buffer 16)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-ts-degraded (list (cons 'raw flags-ts-degraded) (cons 'formatted (if (= flags-ts-degraded 0) "Not set" "Set"))))
        (cons 'flags-duplicate (list (cons 'raw flags-duplicate) (cons 'formatted (if (= flags-duplicate 0) "Not set" "Set"))))
        (cons 'flags-has-ext (list (cons 'raw flags-has-ext) (cons 'formatted (if (= flags-has-ext 0) "Not set" "Set"))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (if (= reserved 0) "Not set" "Set"))))
        (cons 'src-device (list (cons 'raw src-device) (cons 'formatted (number->string src-device))))
        (cons 'src-port (list (cons 'raw src-port) (cons 'formatted (number->string src-port))))
        (cons 'origfcs (list (cons 'raw origfcs) (cons 'formatted (fmt-hex origfcs))))
        )))

    (catch (e)
      (err (str "METAMAKO parse error: " e)))))

;; dissect-metamako: parse METAMAKO from bytevector
;; Returns (ok fields-alist) or (err message)