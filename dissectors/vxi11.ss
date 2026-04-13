;; packet-vxi11.c
;; Routines for VXI-11 (TCP/IP Instrument Protocol) dissection.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; VXI-11 protocol dissector
;; By Jens Kilian <jens.kilian@verigy.com>
;; Copyright 2009 Verigy Deutschland GmbH
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vxi11.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vxi11.c

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
(def (dissect-vxi11 buffer)
  "VXI-11 Core Protocol"
  (try
    (let* (
           (core-flags (unwrap (read-u32be buffer 0)))
           (core-flag-wait-lock (unwrap (read-u8 buffer 0)))
           (core-flag-end (unwrap (read-u8 buffer 0)))
           (core-flag-term-chr-set (unwrap (read-u8 buffer 0)))
           (core-reason (unwrap (read-u32be buffer 0)))
           (core-reason-req-cnt (unwrap (read-u8 buffer 0)))
           (core-reason-chr (unwrap (read-u8 buffer 0)))
           (core-reason-end (unwrap (read-u8 buffer 0)))
           )

      (ok (list
        (cons 'core-flags (list (cons 'raw core-flags) (cons 'formatted (fmt-hex core-flags))))
        (cons 'core-flag-wait-lock (list (cons 'raw core-flag-wait-lock) (cons 'formatted (number->string core-flag-wait-lock))))
        (cons 'core-flag-end (list (cons 'raw core-flag-end) (cons 'formatted (number->string core-flag-end))))
        (cons 'core-flag-term-chr-set (list (cons 'raw core-flag-term-chr-set) (cons 'formatted (number->string core-flag-term-chr-set))))
        (cons 'core-reason (list (cons 'raw core-reason) (cons 'formatted (fmt-hex core-reason))))
        (cons 'core-reason-req-cnt (list (cons 'raw core-reason-req-cnt) (cons 'formatted (number->string core-reason-req-cnt))))
        (cons 'core-reason-chr (list (cons 'raw core-reason-chr) (cons 'formatted (number->string core-reason-chr))))
        (cons 'core-reason-end (list (cons 'raw core-reason-end) (cons 'formatted (number->string core-reason-end))))
        )))

    (catch (e)
      (err (str "VXI11 parse error: " e)))))

;; dissect-vxi11: parse VXI11 from bytevector
;; Returns (ok fields-alist) or (err message)