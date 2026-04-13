;; packet-ftdi-mpsse.c
;; Routines for FTDI Multi-Protocol Synchronous Serial Engine dissection
;;
;; Copyright 2020 Tomasz Mon
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ftdi-mpsse.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ftdi_mpsse.c

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
(def (dissect-ftdi-mpsse buffer)
  "FTDI Multi-Protocol Synchronous Serial Engine"
  (try
    (let* (
           (bytes-out (unwrap (slice buffer 2 1)))
           (bits-out (unwrap (read-u8 buffer 3)))
           (direction (unwrap (read-u8 buffer 4)))
           (cpumode-address-short (unwrap (read-u8 buffer 4)))
           (cpumode-address-extended (unwrap (read-u16be buffer 5)))
           (clk-divisor (unwrap (read-u16be buffer 8)))
           (length-uint8 (unwrap (read-u8 buffer 10)))
           (length-uint16 (unwrap (read-u16be buffer 10)))
           (open-drain-enable-low (unwrap (read-u8 buffer 10)))
           (open-drain-enable-high (unwrap (read-u8 buffer 10)))
           (command (unwrap (read-u8 buffer 10)))
           (command-with-parameters (unwrap (slice buffer 10 1)))
           (value (unwrap (read-u8 buffer 11)))
           (cpumode-data (unwrap (read-u8 buffer 11)))
           (bytes-in (unwrap (slice buffer 11 1)))
           (bits-in (unwrap (read-u8 buffer 11)))
           (bad-command-error (unwrap (read-u8 buffer 11)))
           (bad-command-code (unwrap (read-u8 buffer 11)))
           (response (unwrap (slice buffer 11 1)))
           )

      (ok (list
        (cons 'bytes-out (list (cons 'raw bytes-out) (cons 'formatted (fmt-bytes bytes-out))))
        (cons 'bits-out (list (cons 'raw bits-out) (cons 'formatted (fmt-hex bits-out))))
        (cons 'direction (list (cons 'raw direction) (cons 'formatted (fmt-hex direction))))
        (cons 'cpumode-address-short (list (cons 'raw cpumode-address-short) (cons 'formatted (fmt-hex cpumode-address-short))))
        (cons 'cpumode-address-extended (list (cons 'raw cpumode-address-extended) (cons 'formatted (fmt-hex cpumode-address-extended))))
        (cons 'clk-divisor (list (cons 'raw clk-divisor) (cons 'formatted (fmt-hex clk-divisor))))
        (cons 'length-uint8 (list (cons 'raw length-uint8) (cons 'formatted (number->string length-uint8))))
        (cons 'length-uint16 (list (cons 'raw length-uint16) (cons 'formatted (number->string length-uint16))))
        (cons 'open-drain-enable-low (list (cons 'raw open-drain-enable-low) (cons 'formatted (fmt-hex open-drain-enable-low))))
        (cons 'open-drain-enable-high (list (cons 'raw open-drain-enable-high) (cons 'formatted (fmt-hex open-drain-enable-high))))
        (cons 'command (list (cons 'raw command) (cons 'formatted (fmt-hex command))))
        (cons 'command-with-parameters (list (cons 'raw command-with-parameters) (cons 'formatted (fmt-bytes command-with-parameters))))
        (cons 'value (list (cons 'raw value) (cons 'formatted (fmt-hex value))))
        (cons 'cpumode-data (list (cons 'raw cpumode-data) (cons 'formatted (fmt-hex cpumode-data))))
        (cons 'bytes-in (list (cons 'raw bytes-in) (cons 'formatted (fmt-bytes bytes-in))))
        (cons 'bits-in (list (cons 'raw bits-in) (cons 'formatted (fmt-hex bits-in))))
        (cons 'bad-command-error (list (cons 'raw bad-command-error) (cons 'formatted (fmt-hex bad-command-error))))
        (cons 'bad-command-code (list (cons 'raw bad-command-code) (cons 'formatted (fmt-hex bad-command-code))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (fmt-bytes response))))
        )))

    (catch (e)
      (err (str "FTDI-MPSSE parse error: " e)))))

;; dissect-ftdi-mpsse: parse FTDI-MPSSE from bytevector
;; Returns (ok fields-alist) or (err message)