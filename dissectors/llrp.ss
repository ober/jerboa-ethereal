;; packet-llrp.c
;; Routines for Low Level Reader Protocol dissection
;; Copyright 2012, Evan Huus <eapache@gmail.com>
;; Copyright 2012, Martin Kupec <martin.kupec@kupson.cz>
;; Copyright 2014, Petr Stetiar <petr.stetiar@gaben.cz>
;;
;; http://www.gs1.org/gsmp/kc/epcglobal/llrp
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/llrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-llrp.c

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
(def (dissect-llrp buffer)
  "Low Level Reader Protocol"
  (try
    (let* (
           (length-bits (unwrap (read-u16be buffer 0)))
           (length-words (unwrap (read-u16be buffer 0)))
           (length (unwrap (read-u32be buffer 2)))
           (id (unwrap (read-u32be buffer 6)))
           (tlv-len (unwrap (read-u16be buffer 183)))
           (rfu (unwrap (slice buffer 595 4)))
           (save-config (unwrap (read-u8 buffer 599)))
           (rest-fact (unwrap (read-u8 buffer 614)))
           )

      (ok (list
        (cons 'length-bits (list (cons 'raw length-bits) (cons 'formatted (number->string length-bits))))
        (cons 'length-words (list (cons 'raw length-words) (cons 'formatted (number->string length-words))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'tlv-len (list (cons 'raw tlv-len) (cons 'formatted (number->string tlv-len))))
        (cons 'rfu (list (cons 'raw rfu) (cons 'formatted (fmt-bytes rfu))))
        (cons 'save-config (list (cons 'raw save-config) (cons 'formatted (if (= save-config 0) "False" "True"))))
        (cons 'rest-fact (list (cons 'raw rest-fact) (cons 'formatted (if (= rest-fact 0) "False" "True"))))
        )))

    (catch (e)
      (err (str "LLRP parse error: " e)))))

;; dissect-llrp: parse LLRP from bytevector
;; Returns (ok fields-alist) or (err message)