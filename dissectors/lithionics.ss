;; packet-lithionics.c
;; Routines for Lithionics NeverDie Battery Management System (BMS)
;; By Michael Mann <Michael.Mann@jbtc.com>
;; Copyright 2018 Michael Mann
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; From https://lithionicsbattery.com/wp-content/uploads/2018/06/NeverDie-BMS-Advanced-RS232-UART-serial-protocol-Rev7.15.pdf
;;

;; jerboa-ethereal/dissectors/lithionics.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lithionics.c

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
(def (dissect-lithionics buffer)
  "Lithionics Battery Management System"
  (try
    (let* (
           (amp-hours-remain (unwrap (read-u32be buffer 2)))
           (volts (unwrap (read-u32be buffer 8)))
           (amps (unwrap (read-u32be buffer 23)))
           (system-status (unwrap (read-u24be buffer 40)))
           (temination (unwrap (slice buffer 47 2)))
           (battery-address (unwrap (read-u16be buffer 49)))
           )

      (ok (list
        (cons 'amp-hours-remain (list (cons 'raw amp-hours-remain) (cons 'formatted (number->string amp-hours-remain))))
        (cons 'volts (list (cons 'raw volts) (cons 'formatted (number->string volts))))
        (cons 'amps (list (cons 'raw amps) (cons 'formatted (number->string amps))))
        (cons 'system-status (list (cons 'raw system-status) (cons 'formatted (fmt-hex system-status))))
        (cons 'temination (list (cons 'raw temination) (cons 'formatted (fmt-bytes temination))))
        (cons 'battery-address (list (cons 'raw battery-address) (cons 'formatted (number->string battery-address))))
        )))

    (catch (e)
      (err (str "LITHIONICS parse error: " e)))))

;; dissect-lithionics: parse LITHIONICS from bytevector
;; Returns (ok fields-alist) or (err message)