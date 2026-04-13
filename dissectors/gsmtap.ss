;; packet-gsmtap.c
;; Routines for GSMTAP captures
;;
;; (C) 2008-2013 by Harald Welte <laforge@gnumonks.org>
;; (C) 2011 by Holger Hans Peter Freyther
;; (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
;; (C) 2024 by Tamas Regos <tamas.regos@infostam.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsmtap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsmtap.c

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
(def (dissect-gsmtap buffer)
  "GSM Radiotap"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (ta-idx (unwrap (read-u8 buffer 0)))
           (l1h-sro-srr (unwrap (read-u8 buffer 0)))
           (l1h-fpc (unwrap (read-u8 buffer 0)))
           (l1h-power-lev (unwrap (read-u8 buffer 0)))
           (spare (unwrap (read-u8 buffer 0)))
           (ta-val (unwrap (read-u8 buffer 0)))
           (timeslot (unwrap (read-u8 buffer 0)))
           (arfcn (unwrap (read-u16be buffer 0)))
           (uplink (unwrap (read-u16be buffer 0)))
           (pcs (unwrap (read-u16be buffer 0)))
           (frame-nr (unwrap (read-u32be buffer 0)))
           (antenna (unwrap (read-u8 buffer 0)))
           (subslot (unwrap (read-u8 buffer 0)))
           (res (unwrap (read-u8 buffer 0)))
           (l1h-ta (unwrap (read-u8 buffer 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'ta-idx (list (cons 'raw ta-idx) (cons 'formatted (number->string ta-idx))))
        (cons 'l1h-sro-srr (list (cons 'raw l1h-sro-srr) (cons 'formatted (if (= l1h-sro-srr 0) "False" "True"))))
        (cons 'l1h-fpc (list (cons 'raw l1h-fpc) (cons 'formatted (if (= l1h-fpc 0) "False" "True"))))
        (cons 'l1h-power-lev (list (cons 'raw l1h-power-lev) (cons 'formatted (number->string l1h-power-lev))))
        (cons 'spare (list (cons 'raw spare) (cons 'formatted (number->string spare))))
        (cons 'ta-val (list (cons 'raw ta-val) (cons 'formatted (number->string ta-val))))
        (cons 'timeslot (list (cons 'raw timeslot) (cons 'formatted (number->string timeslot))))
        (cons 'arfcn (list (cons 'raw arfcn) (cons 'formatted (number->string arfcn))))
        (cons 'uplink (list (cons 'raw uplink) (cons 'formatted (number->string uplink))))
        (cons 'pcs (list (cons 'raw pcs) (cons 'formatted (number->string pcs))))
        (cons 'frame-nr (list (cons 'raw frame-nr) (cons 'formatted (number->string frame-nr))))
        (cons 'antenna (list (cons 'raw antenna) (cons 'formatted (number->string antenna))))
        (cons 'subslot (list (cons 'raw subslot) (cons 'formatted (number->string subslot))))
        (cons 'res (list (cons 'raw res) (cons 'formatted (number->string res))))
        (cons 'l1h-ta (list (cons 'raw l1h-ta) (cons 'formatted (number->string l1h-ta))))
        )))

    (catch (e)
      (err (str "GSMTAP parse error: " e)))))

;; dissect-gsmtap: parse GSMTAP from bytevector
;; Returns (ok fields-alist) or (err message)