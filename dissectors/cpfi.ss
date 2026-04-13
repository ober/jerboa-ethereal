;; packet-cpfi.c
;; Routines for CPFI Cross Point Frame Injector dissection
;; CPFI - Cross Point Frame Injector is a CNT proprietary
;; protocol used to carry Fibre Channel data over UDP
;;
;; Copyright 2003, Dave Sclarsky <dave_sclarsky[AT]cnt.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-m2tp.c
;; Thanks to Heinz Prantner for his motivation and assistance
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cpfi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cpfi.c

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
(def (dissect-cpfi buffer)
  "Cross Point Frame Injector"
  (try
    (let* (
           (CRC-32 (unwrap (read-u32be buffer 0)))
           (from-LCM (unwrap (read-u8 buffer 0)))
           (OPM-error (unwrap (read-u8 buffer 0)))
           (dest (unwrap (read-u32be buffer 0)))
           (source (unwrap (read-u32be buffer 0)))
           (frame-type (unwrap (read-u32be buffer 0)))
           (word-one (unwrap (read-u32be buffer 0)))
           (t-dst-port (unwrap (slice buffer 0 1)))
           (t-dst-board (unwrap (slice buffer 0 1)))
           (t-dst-instance (unwrap (slice buffer 0 1)))
           (t-src-port (unwrap (slice buffer 0 1)))
           (t-port (unwrap (slice buffer 0 1)))
           (t-src-board (unwrap (slice buffer 0 1)))
           (t-board (unwrap (slice buffer 0 1)))
           (t-src-instance (unwrap (slice buffer 0 1)))
           (t-instance (unwrap (slice buffer 0 1)))
           (word-two (unwrap (read-u32be buffer 4)))
           )

      (ok (list
        (cons 'CRC-32 (list (cons 'raw CRC-32) (cons 'formatted (fmt-hex CRC-32))))
        (cons 'from-LCM (list (cons 'raw from-LCM) (cons 'formatted (number->string from-LCM))))
        (cons 'OPM-error (list (cons 'raw OPM-error) (cons 'formatted (number->string OPM-error))))
        (cons 'dest (list (cons 'raw dest) (cons 'formatted (fmt-hex dest))))
        (cons 'source (list (cons 'raw source) (cons 'formatted (fmt-hex source))))
        (cons 'frame-type (list (cons 'raw frame-type) (cons 'formatted (fmt-hex frame-type))))
        (cons 'word-one (list (cons 'raw word-one) (cons 'formatted (fmt-hex word-one))))
        (cons 't-dst-port (list (cons 'raw t-dst-port) (cons 'formatted (fmt-bytes t-dst-port))))
        (cons 't-dst-board (list (cons 'raw t-dst-board) (cons 'formatted (fmt-bytes t-dst-board))))
        (cons 't-dst-instance (list (cons 'raw t-dst-instance) (cons 'formatted (fmt-bytes t-dst-instance))))
        (cons 't-src-port (list (cons 'raw t-src-port) (cons 'formatted (fmt-bytes t-src-port))))
        (cons 't-port (list (cons 'raw t-port) (cons 'formatted (fmt-bytes t-port))))
        (cons 't-src-board (list (cons 'raw t-src-board) (cons 'formatted (fmt-bytes t-src-board))))
        (cons 't-board (list (cons 'raw t-board) (cons 'formatted (fmt-bytes t-board))))
        (cons 't-src-instance (list (cons 'raw t-src-instance) (cons 'formatted (fmt-bytes t-src-instance))))
        (cons 't-instance (list (cons 'raw t-instance) (cons 'formatted (fmt-bytes t-instance))))
        (cons 'word-two (list (cons 'raw word-two) (cons 'formatted (fmt-hex word-two))))
        )))

    (catch (e)
      (err (str "CPFI parse error: " e)))))

;; dissect-cpfi: parse CPFI from bytevector
;; Returns (ok fields-alist) or (err message)