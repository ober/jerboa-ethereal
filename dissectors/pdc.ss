;; packet-pdc.c
;; Routines for PDC dissection
;; Copyright 2014, Antony Bridle <antony.bridle@nats.co.uk>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pdc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pdc.c

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
(def (dissect-pdc buffer)
  "PDC Protocol"
  (try
    (let* (
           (simpdu-var-len (unwrap (read-u8 buffer 0)))
           (admpdu-size (unwrap (read-u16be buffer 4)))
           (admpdu-admpdunr (unwrap (read-u32be buffer 6)))
           (dtmpdu-user-size (unwrap (read-u16be buffer 6)))
           (akmpdu-mns (unwrap (read-u16be buffer 6)))
           (akmpdu-cdt (unwrap (read-u16be buffer 6)))
           (yr-admu-nr (unwrap (read-u32be buffer 6)))
           (credit (unwrap (read-u8 buffer 10)))
           )

      (ok (list
        (cons 'simpdu-var-len (list (cons 'raw simpdu-var-len) (cons 'formatted (number->string simpdu-var-len))))
        (cons 'admpdu-size (list (cons 'raw admpdu-size) (cons 'formatted (number->string admpdu-size))))
        (cons 'admpdu-admpdunr (list (cons 'raw admpdu-admpdunr) (cons 'formatted (number->string admpdu-admpdunr))))
        (cons 'dtmpdu-user-size (list (cons 'raw dtmpdu-user-size) (cons 'formatted (number->string dtmpdu-user-size))))
        (cons 'akmpdu-mns (list (cons 'raw akmpdu-mns) (cons 'formatted (number->string akmpdu-mns))))
        (cons 'akmpdu-cdt (list (cons 'raw akmpdu-cdt) (cons 'formatted (number->string akmpdu-cdt))))
        (cons 'yr-admu-nr (list (cons 'raw yr-admu-nr) (cons 'formatted (number->string yr-admu-nr))))
        (cons 'credit (list (cons 'raw credit) (cons 'formatted (number->string credit))))
        )))

    (catch (e)
      (err (str "PDC parse error: " e)))))

;; dissect-pdc: parse PDC from bytevector
;; Returns (ok fields-alist) or (err message)