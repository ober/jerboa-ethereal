;; packet-lapsat.c
;;
;; Routines for GMR-1 LAPSat dissection in wireshark.
;;
;; Link Access Procedures (LAP) for the Satellite Channel (LAPSat).
;; LAPSat is the protocol for signalling transfer between an Access
;; Terminal (MES) and a Gateway Station (GS) in the GeoMobile (GMR-1) network.
;;
;; Copyright (c) 2011 Sylvain Munaut <tnt@246tNt.com>
;; Inspired on LAPDm code by Duncan Salerno <duncan.salerno@googlemail.com>
;;
;; References:
;; [1] ETSI TS 101 376-4-6 V1.2.1 - GMR-1 04.006
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lapsat.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lapsat.c

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
(def (dissect-lapsat buffer)
  "Link Access Procedure, Satellite channel (LAPSat)"
  (try
    (let* (
           (addr-cr (unwrap (read-u8 buffer 0)))
           (addr (unwrap (read-u8 buffer 0)))
           (ctl-p (unwrap (read-u8 buffer 1)))
           (ctl-n-s (unwrap (read-u16be buffer 1)))
           (ctl-mii (unwrap (read-u8 buffer 1)))
           (ctl-n-r (unwrap (read-u16be buffer 1)))
           (ctl (unwrap (read-u16be buffer 1)))
           (payload-last-nibble (unwrap (read-u8 buffer 2)))
           (len (unwrap (read-u8 buffer 3)))
           )

      (ok (list
        (cons 'addr-cr (list (cons 'raw addr-cr) (cons 'formatted (number->string addr-cr))))
        (cons 'addr (list (cons 'raw addr) (cons 'formatted (fmt-hex addr))))
        (cons 'ctl-p (list (cons 'raw ctl-p) (cons 'formatted (number->string ctl-p))))
        (cons 'ctl-n-s (list (cons 'raw ctl-n-s) (cons 'formatted (number->string ctl-n-s))))
        (cons 'ctl-mii (list (cons 'raw ctl-mii) (cons 'formatted (number->string ctl-mii))))
        (cons 'ctl-n-r (list (cons 'raw ctl-n-r) (cons 'formatted (number->string ctl-n-r))))
        (cons 'ctl (list (cons 'raw ctl) (cons 'formatted (fmt-hex ctl))))
        (cons 'payload-last-nibble (list (cons 'raw payload-last-nibble) (cons 'formatted (fmt-hex payload-last-nibble))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        )))

    (catch (e)
      (err (str "LAPSAT parse error: " e)))))

;; dissect-lapsat: parse LAPSAT from bytevector
;; Returns (ok fields-alist) or (err message)