;; packet-osmo_trx.c
;; Dissector for OsmoTRX Protocol (GSM Transceiver control and data).
;;
;; (C) 2018 by Harald Welte <laforge@gnumonks.org>
;; (C) 2019 by Vadim Yanitskiy <axilirator@gmail.com>
;; (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/osmo-trx.ss
;; Auto-generated from wireshark/epan/dissectors/packet-osmo_trx.c

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
(def (dissect-osmo-trx buffer)
  "OsmoTRX Data Protocol"
  (try
    (let* (
           (pdu-ver (unwrap (read-u8 buffer 0)))
           (type (unwrap (slice buffer 0 3)))
           (verb (unwrap (slice buffer 4 1)))
           (nope-ind (unwrap (read-u8 buffer 5)))
           (nope-ind-pad (unwrap (read-u8 buffer 5)))
           (tsc (unwrap (read-u8 buffer 5)))
           (status (unwrap (slice buffer 6 1)))
           (params (unwrap (slice buffer 6 1)))
           (chdr-reserved (unwrap (read-u8 buffer 9)))
           (tdma-tn (unwrap (read-u8 buffer 9)))
           (batch-ind (unwrap (read-u8 buffer 10)))
           (shadow-ind (unwrap (read-u8 buffer 10)))
           (trx-num (unwrap (read-u8 buffer 10)))
           (tdma-fn (unwrap (read-u32be buffer 15)))
           )

      (ok (list
        (cons 'pdu-ver (list (cons 'raw pdu-ver) (cons 'formatted (number->string pdu-ver))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (utf8->string type))))
        (cons 'verb (list (cons 'raw verb) (cons 'formatted (utf8->string verb))))
        (cons 'nope-ind (list (cons 'raw nope-ind) (cons 'formatted (if (= nope-ind 0) "False" "True"))))
        (cons 'nope-ind-pad (list (cons 'raw nope-ind-pad) (cons 'formatted (number->string nope-ind-pad))))
        (cons 'tsc (list (cons 'raw tsc) (cons 'formatted (number->string tsc))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (utf8->string status))))
        (cons 'params (list (cons 'raw params) (cons 'formatted (utf8->string params))))
        (cons 'chdr-reserved (list (cons 'raw chdr-reserved) (cons 'formatted (number->string chdr-reserved))))
        (cons 'tdma-tn (list (cons 'raw tdma-tn) (cons 'formatted (number->string tdma-tn))))
        (cons 'batch-ind (list (cons 'raw batch-ind) (cons 'formatted (if (= batch-ind 0) "False" "True"))))
        (cons 'shadow-ind (list (cons 'raw shadow-ind) (cons 'formatted (if (= shadow-ind 0) "False" "True"))))
        (cons 'trx-num (list (cons 'raw trx-num) (cons 'formatted (number->string trx-num))))
        (cons 'tdma-fn (list (cons 'raw tdma-fn) (cons 'formatted (number->string tdma-fn))))
        )))

    (catch (e)
      (err (str "OSMO-TRX parse error: " e)))))

;; dissect-osmo-trx: parse OSMO-TRX from bytevector
;; Returns (ok fields-alist) or (err message)