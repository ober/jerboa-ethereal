;; packet-uhd.c
;; Routines for UHD captures
;;
;; (C) 2013 by Klyuchnikov Ivan <kluchnikovi@gmail.com>, Dario Lombardo <lomato@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/uhd.ss
;; Auto-generated from wireshark/epan/dissectors/packet-uhd.c

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
(def (dissect-uhd buffer)
  "UHD"
  (try
    (let* (
           (version (unwrap (read-u32be buffer 0)))
           (seq (unwrap (read-u32be buffer 8)))
           (echo-len (unwrap (read-u32be buffer 12)))
           (reg-addr (unwrap (read-u32be buffer 12)))
           (i2c-addr (unwrap (read-u8 buffer 12)))
           (spi-dev (unwrap (read-u32be buffer 12)))
           (ip-addr (unwrap (read-u32be buffer 12)))
           (i2c-bytes (unwrap (read-u8 buffer 13)))
           (reg-data (unwrap (read-u32be buffer 16)))
           (spi-data (unwrap (read-u32be buffer 16)))
           (spi-miso-edge (unwrap (read-u8 buffer 20)))
           (spi-mosi-edge (unwrap (read-u8 buffer 21)))
           (spi-num-bits (unwrap (read-u8 buffer 22)))
           (spi-readback (unwrap (read-u8 buffer 23)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'echo-len (list (cons 'raw echo-len) (cons 'formatted (number->string echo-len))))
        (cons 'reg-addr (list (cons 'raw reg-addr) (cons 'formatted (fmt-hex reg-addr))))
        (cons 'i2c-addr (list (cons 'raw i2c-addr) (cons 'formatted (fmt-hex i2c-addr))))
        (cons 'spi-dev (list (cons 'raw spi-dev) (cons 'formatted (fmt-hex spi-dev))))
        (cons 'ip-addr (list (cons 'raw ip-addr) (cons 'formatted (fmt-ipv4 ip-addr))))
        (cons 'i2c-bytes (list (cons 'raw i2c-bytes) (cons 'formatted (number->string i2c-bytes))))
        (cons 'reg-data (list (cons 'raw reg-data) (cons 'formatted (fmt-hex reg-data))))
        (cons 'spi-data (list (cons 'raw spi-data) (cons 'formatted (fmt-hex spi-data))))
        (cons 'spi-miso-edge (list (cons 'raw spi-miso-edge) (cons 'formatted (fmt-hex spi-miso-edge))))
        (cons 'spi-mosi-edge (list (cons 'raw spi-mosi-edge) (cons 'formatted (fmt-hex spi-mosi-edge))))
        (cons 'spi-num-bits (list (cons 'raw spi-num-bits) (cons 'formatted (number->string spi-num-bits))))
        (cons 'spi-readback (list (cons 'raw spi-readback) (cons 'formatted (fmt-hex spi-readback))))
        )))

    (catch (e)
      (err (str "UHD parse error: " e)))))

;; dissect-uhd: parse UHD from bytevector
;; Returns (ok fields-alist) or (err message)