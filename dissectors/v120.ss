;; packet-v120.c
;; Routines for v120 frame disassembly
;; Bert Driehuis <driehuis@playbeing.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/v120.ss
;; Auto-generated from wireshark/epan/dissectors/packet-v120.c

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
(def (dissect-v120 buffer)
  "Async data over ISDN (V.120)"
  (try
    (let* (
           (header-rr (unwrap (read-u8 buffer 0)))
           (header-sr (unwrap (read-u8 buffer 0)))
           (header-dr (unwrap (read-u8 buffer 0)))
           (header-e (unwrap (read-u8 buffer 0)))
           (header-segf16 (unwrap (read-u8 buffer 0)))
           (header-segb16 (unwrap (read-u8 buffer 0)))
           (header-error-control16 (unwrap (read-u16be buffer 0)))
           (header-break16 (unwrap (read-u8 buffer 0)))
           (header-ext16 (unwrap (read-u8 buffer 0)))
           (header16 (unwrap (read-u16be buffer 0)))
           (header-segf8 (unwrap (read-u8 buffer 0)))
           (header-segb8 (unwrap (read-u8 buffer 0)))
           (header-error-control8 (unwrap (read-u8 buffer 0)))
           (header-break8 (unwrap (read-u8 buffer 0)))
           (header-ext8 (unwrap (read-u8 buffer 0)))
           (header8 (unwrap (read-u8 buffer 0)))
           (ea1 (unwrap (read-u8 buffer 0)))
           (ea0 (unwrap (read-u8 buffer 0)))
           (lli (unwrap (read-u16be buffer 0)))
           (rc (unwrap (read-u8 buffer 0)))
           (address (unwrap (read-u16be buffer 0)))
           )

      (ok (list
        (cons 'header-rr (list (cons 'raw header-rr) (cons 'formatted (if (= header-rr 0) "False" "True"))))
        (cons 'header-sr (list (cons 'raw header-sr) (cons 'formatted (if (= header-sr 0) "False" "True"))))
        (cons 'header-dr (list (cons 'raw header-dr) (cons 'formatted (if (= header-dr 0) "False" "True"))))
        (cons 'header-e (list (cons 'raw header-e) (cons 'formatted (if (= header-e 0) "False" "True"))))
        (cons 'header-segf16 (list (cons 'raw header-segf16) (cons 'formatted (if (= header-segf16 0) "False" "True"))))
        (cons 'header-segb16 (list (cons 'raw header-segb16) (cons 'formatted (if (= header-segb16 0) "False" "True"))))
        (cons 'header-error-control16 (list (cons 'raw header-error-control16) (cons 'formatted (fmt-hex header-error-control16))))
        (cons 'header-break16 (list (cons 'raw header-break16) (cons 'formatted (if (= header-break16 0) "False" "True"))))
        (cons 'header-ext16 (list (cons 'raw header-ext16) (cons 'formatted (if (= header-ext16 0) "False" "True"))))
        (cons 'header16 (list (cons 'raw header16) (cons 'formatted (fmt-hex header16))))
        (cons 'header-segf8 (list (cons 'raw header-segf8) (cons 'formatted (if (= header-segf8 0) "False" "True"))))
        (cons 'header-segb8 (list (cons 'raw header-segb8) (cons 'formatted (if (= header-segb8 0) "False" "True"))))
        (cons 'header-error-control8 (list (cons 'raw header-error-control8) (cons 'formatted (fmt-hex header-error-control8))))
        (cons 'header-break8 (list (cons 'raw header-break8) (cons 'formatted (if (= header-break8 0) "False" "True"))))
        (cons 'header-ext8 (list (cons 'raw header-ext8) (cons 'formatted (if (= header-ext8 0) "False" "True"))))
        (cons 'header8 (list (cons 'raw header8) (cons 'formatted (fmt-hex header8))))
        (cons 'ea1 (list (cons 'raw ea1) (cons 'formatted (if (= ea1 0) "False" "True"))))
        (cons 'ea0 (list (cons 'raw ea0) (cons 'formatted (if (= ea0 0) "False" "True"))))
        (cons 'lli (list (cons 'raw lli) (cons 'formatted (fmt-hex lli))))
        (cons 'rc (list (cons 'raw rc) (cons 'formatted (if (= rc 0) "False" "True"))))
        (cons 'address (list (cons 'raw address) (cons 'formatted (fmt-hex address))))
        )))

    (catch (e)
      (err (str "V120 parse error: " e)))))

;; dissect-v120: parse V120 from bytevector
;; Returns (ok fields-alist) or (err message)