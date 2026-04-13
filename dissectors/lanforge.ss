;; packet-lanforge.c
;; Routines for "LANforge traffic generator IP protocol" dissection
;; Copyright 2008
;; Ben Greear <greearb@candelatech.com>
;;
;; Based on pktgen dissectory by:
;; Francesco Fondelli <francesco dot fondelli, gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lanforge.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lanforge.c

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
(def (dissect-lanforge buffer)
  "LANforge Traffic Generator"
  (try
    (let* (
           (crc (unwrap (read-u32be buffer 0)))
           (magic (unwrap (read-u32be buffer 4)))
           (src-session (unwrap (read-u16be buffer 8)))
           (dst-session (unwrap (read-u16be buffer 10)))
           (pld-len-l (unwrap (read-u16be buffer 12)))
           (pld-len-h (unwrap (read-u8 buffer 14)))
           (pld-len (unwrap (read-u32be buffer 15)))
           (pld-pattern (unwrap (read-u16be buffer 15)))
           (seq (unwrap (read-u32be buffer 16)))
           (tx-time-s (unwrap (read-u32be buffer 20)))
           (tx-time-ns (unwrap (read-u32be buffer 24)))
           )

      (ok (list
        (cons 'crc (list (cons 'raw crc) (cons 'formatted (fmt-hex crc))))
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        (cons 'src-session (list (cons 'raw src-session) (cons 'formatted (number->string src-session))))
        (cons 'dst-session (list (cons 'raw dst-session) (cons 'formatted (number->string dst-session))))
        (cons 'pld-len-l (list (cons 'raw pld-len-l) (cons 'formatted (number->string pld-len-l))))
        (cons 'pld-len-h (list (cons 'raw pld-len-h) (cons 'formatted (number->string pld-len-h))))
        (cons 'pld-len (list (cons 'raw pld-len) (cons 'formatted (number->string pld-len))))
        (cons 'pld-pattern (list (cons 'raw pld-pattern) (cons 'formatted (number->string pld-pattern))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'tx-time-s (list (cons 'raw tx-time-s) (cons 'formatted (number->string tx-time-s))))
        (cons 'tx-time-ns (list (cons 'raw tx-time-ns) (cons 'formatted (number->string tx-time-ns))))
        )))

    (catch (e)
      (err (str "LANFORGE parse error: " e)))))

;; dissect-lanforge: parse LANFORGE from bytevector
;; Returns (ok fields-alist) or (err message)