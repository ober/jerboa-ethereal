;; packet-iso7816.c
;; Routines for packet dissection of generic ISO 7816 smart card messages
;; Copyright 2012-2013 by Martin Kaiser <martin@kaiser.cx>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/iso7816.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iso7816.c

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
(def (dissect-iso7816 buffer)
  "ISO/IEC 7816"
  (try
    (let* (
           (atr-ta1-fi (unwrap (read-u16be buffer 0)))
           (atr-ta1-di (unwrap (read-u8 buffer 0)))
           (atr-t0 (unwrap (read-u8 buffer 0)))
           (atr-td (unwrap (read-u8 buffer 0)))
           (atr-next-ta-present (unwrap (read-u8 buffer 0)))
           (atr-next-tb-present (unwrap (read-u8 buffer 0)))
           (atr-next-tc-present (unwrap (read-u8 buffer 0)))
           (atr-next-td-present (unwrap (read-u8 buffer 0)))
           (atr-k (unwrap (read-u8 buffer 0)))
           (atr-t (unwrap (read-u8 buffer 0)))
           (atr-tb (unwrap (read-u8 buffer 0)))
           (atr-tc (unwrap (read-u8 buffer 0)))
           (atr-hist-bytes (unwrap (slice buffer 0 1)))
           (atr-tck (unwrap (read-u8 buffer 0)))
           (p1 (unwrap (read-u8 buffer 0)))
           (p2 (unwrap (read-u8 buffer 0)))
           (lc (unwrap (read-u8 buffer 0)))
           (body (unwrap (slice buffer 0 1)))
           (sw2 (unwrap (read-u8 buffer 0)))
           (atr-ta (unwrap (read-u8 buffer 2)))
           )

      (ok (list
        (cons 'atr-ta1-fi (list (cons 'raw atr-ta1-fi) (cons 'formatted (number->string atr-ta1-fi))))
        (cons 'atr-ta1-di (list (cons 'raw atr-ta1-di) (cons 'formatted (number->string atr-ta1-di))))
        (cons 'atr-t0 (list (cons 'raw atr-t0) (cons 'formatted (fmt-hex atr-t0))))
        (cons 'atr-td (list (cons 'raw atr-td) (cons 'formatted (fmt-hex atr-td))))
        (cons 'atr-next-ta-present (list (cons 'raw atr-next-ta-present) (cons 'formatted (number->string atr-next-ta-present))))
        (cons 'atr-next-tb-present (list (cons 'raw atr-next-tb-present) (cons 'formatted (number->string atr-next-tb-present))))
        (cons 'atr-next-tc-present (list (cons 'raw atr-next-tc-present) (cons 'formatted (number->string atr-next-tc-present))))
        (cons 'atr-next-td-present (list (cons 'raw atr-next-td-present) (cons 'formatted (number->string atr-next-td-present))))
        (cons 'atr-k (list (cons 'raw atr-k) (cons 'formatted (number->string atr-k))))
        (cons 'atr-t (list (cons 'raw atr-t) (cons 'formatted (fmt-hex atr-t))))
        (cons 'atr-tb (list (cons 'raw atr-tb) (cons 'formatted (fmt-hex atr-tb))))
        (cons 'atr-tc (list (cons 'raw atr-tc) (cons 'formatted (fmt-hex atr-tc))))
        (cons 'atr-hist-bytes (list (cons 'raw atr-hist-bytes) (cons 'formatted (fmt-bytes atr-hist-bytes))))
        (cons 'atr-tck (list (cons 'raw atr-tck) (cons 'formatted (fmt-hex atr-tck))))
        (cons 'p1 (list (cons 'raw p1) (cons 'formatted (fmt-hex p1))))
        (cons 'p2 (list (cons 'raw p2) (cons 'formatted (fmt-hex p2))))
        (cons 'lc (list (cons 'raw lc) (cons 'formatted (fmt-hex lc))))
        (cons 'body (list (cons 'raw body) (cons 'formatted (fmt-bytes body))))
        (cons 'sw2 (list (cons 'raw sw2) (cons 'formatted (fmt-hex sw2))))
        (cons 'atr-ta (list (cons 'raw atr-ta) (cons 'formatted (fmt-hex atr-ta))))
        )))

    (catch (e)
      (err (str "ISO7816 parse error: " e)))))

;; dissect-iso7816: parse ISO7816 from bytevector
;; Returns (ok fields-alist) or (err message)