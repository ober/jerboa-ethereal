;; packet-ftdi-ft.c
;; Routines for FTDI FTxxxx USB converters dissection
;;
;; Copyright 2019 Tomasz Mon
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ftdi-ft.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ftdi_ft.c

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
(def (dissect-ftdi-ft buffer)
  "FTDI FT USB"
  (try
    (let* (
           (lvalue-xon-char (unwrap (read-u8 buffer 0)))
           (hvalue-xoff-char (unwrap (read-u8 buffer 0)))
           (lvalue-baud-low (unwrap (read-u8 buffer 0)))
           (hvalue-baud-mid (unwrap (read-u8 buffer 0)))
           (lvalue-event-char (unwrap (read-u8 buffer 2)))
           (lvalue-error-char (unwrap (read-u8 buffer 2)))
           (lvalue-latency-time (unwrap (read-u8 buffer 2)))
           (lat-timer (unwrap (read-u8 buffer 2)))
           (lvalue-bitmask (unwrap (read-u8 buffer 2)))
           (eeprom-word (unwrap (read-u16be buffer 2)))
           (value-eeprom-word (unwrap (read-u16be buffer 4)))
           (wlength (unwrap (read-u16be buffer 4)))
           (lindex-eeprom-addr (unwrap (read-u8 buffer 6)))
           (hindex (unwrap (read-u8 buffer 6)))
           (lvalue (unwrap (read-u8 buffer 6)))
           (hvalue (unwrap (read-u8 buffer 6)))
           (lindex (unwrap (read-u8 buffer 6)))
           (status (unwrap (read-u8 buffer 6)))
           )

      (ok (list
        (cons 'lvalue-xon-char (list (cons 'raw lvalue-xon-char) (cons 'formatted (fmt-hex lvalue-xon-char))))
        (cons 'hvalue-xoff-char (list (cons 'raw hvalue-xoff-char) (cons 'formatted (fmt-hex hvalue-xoff-char))))
        (cons 'lvalue-baud-low (list (cons 'raw lvalue-baud-low) (cons 'formatted (fmt-hex lvalue-baud-low))))
        (cons 'hvalue-baud-mid (list (cons 'raw hvalue-baud-mid) (cons 'formatted (fmt-hex hvalue-baud-mid))))
        (cons 'lvalue-event-char (list (cons 'raw lvalue-event-char) (cons 'formatted (fmt-hex lvalue-event-char))))
        (cons 'lvalue-error-char (list (cons 'raw lvalue-error-char) (cons 'formatted (fmt-hex lvalue-error-char))))
        (cons 'lvalue-latency-time (list (cons 'raw lvalue-latency-time) (cons 'formatted (number->string lvalue-latency-time))))
        (cons 'lat-timer (list (cons 'raw lat-timer) (cons 'formatted (number->string lat-timer))))
        (cons 'lvalue-bitmask (list (cons 'raw lvalue-bitmask) (cons 'formatted (fmt-hex lvalue-bitmask))))
        (cons 'eeprom-word (list (cons 'raw eeprom-word) (cons 'formatted (fmt-hex eeprom-word))))
        (cons 'value-eeprom-word (list (cons 'raw value-eeprom-word) (cons 'formatted (fmt-hex value-eeprom-word))))
        (cons 'wlength (list (cons 'raw wlength) (cons 'formatted (number->string wlength))))
        (cons 'lindex-eeprom-addr (list (cons 'raw lindex-eeprom-addr) (cons 'formatted (fmt-hex lindex-eeprom-addr))))
        (cons 'hindex (list (cons 'raw hindex) (cons 'formatted (fmt-hex hindex))))
        (cons 'lvalue (list (cons 'raw lvalue) (cons 'formatted (fmt-hex lvalue))))
        (cons 'hvalue (list (cons 'raw hvalue) (cons 'formatted (fmt-hex hvalue))))
        (cons 'lindex (list (cons 'raw lindex) (cons 'formatted (fmt-hex lindex))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (fmt-hex status))))
        )))

    (catch (e)
      (err (str "FTDI-FT parse error: " e)))))

;; dissect-ftdi-ft: parse FTDI-FT from bytevector
;; Returns (ok fields-alist) or (err message)