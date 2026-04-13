;;
;; packet-rftap.c
;; Decode packets with a RFtap header
;; Copyright 2016, Jonathan Brucker <jonathan.brucke@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rftap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rftap.c

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
(def (dissect-rftap buffer)
  "RFtap Protocol"
  (try
    (let* (
           (magic (unwrap (read-u32be buffer 0)))
           (len (unwrap (read-u32be buffer 4)))
           (dlt (unwrap (read-u32be buffer 8)))
           (signal-power (unwrap (read-u32be buffer 36)))
           (noise-power (unwrap (read-u32be buffer 40)))
           (snr (unwrap (read-u32be buffer 44)))
           (signal-quality (unwrap (read-u32be buffer 48)))
           (time-int (unwrap (read-u64be buffer 52)))
           (time-frac (unwrap (read-u64be buffer 52)))
           (time (unwrap (read-u64be buffer 52)))
           (subdissector-name (unwrap (slice buffer 100 1)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'dlt (list (cons 'raw dlt) (cons 'formatted (number->string dlt))))
        (cons 'signal-power (list (cons 'raw signal-power) (cons 'formatted (number->string signal-power))))
        (cons 'noise-power (list (cons 'raw noise-power) (cons 'formatted (number->string noise-power))))
        (cons 'snr (list (cons 'raw snr) (cons 'formatted (number->string snr))))
        (cons 'signal-quality (list (cons 'raw signal-quality) (cons 'formatted (number->string signal-quality))))
        (cons 'time-int (list (cons 'raw time-int) (cons 'formatted (number->string time-int))))
        (cons 'time-frac (list (cons 'raw time-frac) (cons 'formatted (number->string time-frac))))
        (cons 'time (list (cons 'raw time) (cons 'formatted (number->string time))))
        (cons 'subdissector-name (list (cons 'raw subdissector-name) (cons 'formatted (utf8->string subdissector-name))))
        )))

    (catch (e)
      (err (str "RFTAP parse error: " e)))))

;; dissect-rftap: parse RFTAP from bytevector
;; Returns (ok fields-alist) or (err message)