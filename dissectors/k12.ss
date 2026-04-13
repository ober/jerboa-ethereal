;; packet-k12.c
;; Helper-dissector for Tektronix k12xx-k15xx .rf5 file type
;;
;; Luis E. Garcia Ontanon <luis@ontanon.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/k12.ss
;; Auto-generated from wireshark/epan/dissectors/packet-k12.c

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
(def (dissect-k12 buffer)
  "K12xx"
  (try
    (let* (
           (atm-cid (unwrap (read-u16be buffer 0)))
           (atm-vc (unwrap (read-u16be buffer 0)))
           (atm-vp (unwrap (read-u16be buffer 0)))
           (ts (unwrap (read-u32be buffer 0)))
           (stack-file (unwrap (slice buffer 0 1)))
           (port-name (unwrap (slice buffer 0 1)))
           (port-id (unwrap (read-u32be buffer 0)))
           )

      (ok (list
        (cons 'atm-cid (list (cons 'raw atm-cid) (cons 'formatted (number->string atm-cid))))
        (cons 'atm-vc (list (cons 'raw atm-vc) (cons 'formatted (number->string atm-vc))))
        (cons 'atm-vp (list (cons 'raw atm-vp) (cons 'formatted (number->string atm-vp))))
        (cons 'ts (list (cons 'raw ts) (cons 'formatted (fmt-hex ts))))
        (cons 'stack-file (list (cons 'raw stack-file) (cons 'formatted (utf8->string stack-file))))
        (cons 'port-name (list (cons 'raw port-name) (cons 'formatted (utf8->string port-name))))
        (cons 'port-id (list (cons 'raw port-id) (cons 'formatted (fmt-hex port-id))))
        )))

    (catch (e)
      (err (str "K12 parse error: " e)))))

;; dissect-k12: parse K12 from bytevector
;; Returns (ok fields-alist) or (err message)