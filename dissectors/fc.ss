;; packet-fc.c
;; Routines for Fibre Channel Decoding (FC Header, Link Ctl & Basic Link Svc)
;; Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
;; Copyright 2003  Ronnie Sahlberg, exchange first/last matching and
;; tap listener and misc updates
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fc.c

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
(def (dissect-fc buffer)
  "Fibre Channel"
  (try
    (let* (
           (exchange-last-frame (unwrap (read-u32be buffer 0)))
           (exchange-first-frame (unwrap (read-u32be buffer 0)))
           (rctl (unwrap (read-u8 buffer 8)))
           (csctl (unwrap (read-u8 buffer 8)))
           (seqid (unwrap (read-u8 buffer 8)))
           (dfctl (unwrap (read-u8 buffer 8)))
           (seqcnt (unwrap (read-u16be buffer 8)))
           (oxid (unwrap (read-u16be buffer 8)))
           (rxid (unwrap (read-u16be buffer 8)))
           (param (unwrap (read-u32be buffer 8)))
           (relative-offset (unwrap (read-u32be buffer 8)))
           (reassembled (unwrap (read-u8 buffer 24)))
           )

      (ok (list
        (cons 'exchange-last-frame (list (cons 'raw exchange-last-frame) (cons 'formatted (number->string exchange-last-frame))))
        (cons 'exchange-first-frame (list (cons 'raw exchange-first-frame) (cons 'formatted (number->string exchange-first-frame))))
        (cons 'rctl (list (cons 'raw rctl) (cons 'formatted (fmt-hex rctl))))
        (cons 'csctl (list (cons 'raw csctl) (cons 'formatted (fmt-hex csctl))))
        (cons 'seqid (list (cons 'raw seqid) (cons 'formatted (fmt-hex seqid))))
        (cons 'dfctl (list (cons 'raw dfctl) (cons 'formatted (fmt-hex dfctl))))
        (cons 'seqcnt (list (cons 'raw seqcnt) (cons 'formatted (number->string seqcnt))))
        (cons 'oxid (list (cons 'raw oxid) (cons 'formatted (fmt-hex oxid))))
        (cons 'rxid (list (cons 'raw rxid) (cons 'formatted (fmt-hex rxid))))
        (cons 'param (list (cons 'raw param) (cons 'formatted (fmt-hex param))))
        (cons 'relative-offset (list (cons 'raw relative-offset) (cons 'formatted (number->string relative-offset))))
        (cons 'reassembled (list (cons 'raw reassembled) (cons 'formatted (number->string reassembled))))
        )))

    (catch (e)
      (err (str "FC parse error: " e)))))

;; dissect-fc: parse FC from bytevector
;; Returns (ok fields-alist) or (err message)