;; packet-5co-legacy.c
;; Routines for FiveCo's Legacy Register Access Protocol dissector
;; Copyright 2021, Antoine Gardiol <antoine.gardiol@fiveco.ch>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/5co-legacy.ss
;; Auto-generated from wireshark/epan/dissectors/packet-5co_legacy.c

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
(def (dissect-5co-legacy buffer)
  "FiveCo's Legacy Register Access Protocol"
  (try
    (let* (
           (id (unwrap (read-u16be buffer 2)))
           (length (unwrap (read-u16be buffer 4)))
           (reg-comm-option (unwrap (read-u32be buffer 8)))
           (i2c2read (unwrap (read-u8 buffer 8)))
           (i2cadd (unwrap (read-u8 buffer 9)))
           (i2c2write (unwrap (read-u8 buffer 10)))
           (i2cwrite (unwrap (slice buffer 11 1)))
           (i2c2scan (unwrap (slice buffer 11 1)))
           (i2cscaned (unwrap (slice buffer 11 1)))
           (i2cerror (unwrap (read-u8 buffer 11)))
           (EasyIPMAC (unwrap (slice buffer 11 6)))
           (reg-mac-address (unwrap (slice buffer 12 6)))
           (EasyIPIP (unwrap (read-u32be buffer 17)))
           (reg-ip-address (unwrap (read-u32be buffer 18)))
           (EasyIPSM (unwrap (read-u32be buffer 21)))
           (reg-ip-subnet-mask (unwrap (read-u32be buffer 22)))
           (i2canswer (unwrap (slice buffer 26 1)))
           (flash-offset (unwrap (read-u24be buffer 26)))
           (reg-name (unwrap (slice buffer 27 16)))
           (flash-size (unwrap (read-u24be buffer 29)))
           (flash-answer (unwrap (slice buffer 32 1)))
           )

      (ok (list
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'reg-comm-option (list (cons 'raw reg-comm-option) (cons 'formatted (fmt-hex reg-comm-option))))
        (cons 'i2c2read (list (cons 'raw i2c2read) (cons 'formatted (number->string i2c2read))))
        (cons 'i2cadd (list (cons 'raw i2cadd) (cons 'formatted (number->string i2cadd))))
        (cons 'i2c2write (list (cons 'raw i2c2write) (cons 'formatted (number->string i2c2write))))
        (cons 'i2cwrite (list (cons 'raw i2cwrite) (cons 'formatted (fmt-bytes i2cwrite))))
        (cons 'i2c2scan (list (cons 'raw i2c2scan) (cons 'formatted (fmt-bytes i2c2scan))))
        (cons 'i2cscaned (list (cons 'raw i2cscaned) (cons 'formatted (fmt-bytes i2cscaned))))
        (cons 'i2cerror (list (cons 'raw i2cerror) (cons 'formatted (fmt-hex i2cerror))))
        (cons 'EasyIPMAC (list (cons 'raw EasyIPMAC) (cons 'formatted (fmt-mac EasyIPMAC))))
        (cons 'reg-mac-address (list (cons 'raw reg-mac-address) (cons 'formatted (fmt-mac reg-mac-address))))
        (cons 'EasyIPIP (list (cons 'raw EasyIPIP) (cons 'formatted (fmt-ipv4 EasyIPIP))))
        (cons 'reg-ip-address (list (cons 'raw reg-ip-address) (cons 'formatted (fmt-ipv4 reg-ip-address))))
        (cons 'EasyIPSM (list (cons 'raw EasyIPSM) (cons 'formatted (fmt-ipv4 EasyIPSM))))
        (cons 'reg-ip-subnet-mask (list (cons 'raw reg-ip-subnet-mask) (cons 'formatted (fmt-ipv4 reg-ip-subnet-mask))))
        (cons 'i2canswer (list (cons 'raw i2canswer) (cons 'formatted (fmt-bytes i2canswer))))
        (cons 'flash-offset (list (cons 'raw flash-offset) (cons 'formatted (fmt-hex flash-offset))))
        (cons 'reg-name (list (cons 'raw reg-name) (cons 'formatted (utf8->string reg-name))))
        (cons 'flash-size (list (cons 'raw flash-size) (cons 'formatted (number->string flash-size))))
        (cons 'flash-answer (list (cons 'raw flash-answer) (cons 'formatted (utf8->string flash-answer))))
        )))

    (catch (e)
      (err (str "5CO-LEGACY parse error: " e)))))

;; dissect-5co-legacy: parse 5CO-LEGACY from bytevector
;; Returns (ok fields-alist) or (err message)