;; packet-sbas_l5.c
;; SBAS L5 protocol dissection.
;;
;; By Timo Warns <timo.warns@gmail.com>
;; Copyright 2025 Timo Warns
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@unicom.net>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sbas-l5.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sbas_l5.c

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
(def (dissect-sbas-l5 buffer)
  "SBAS L5 Navigation Message"
  (try
    (let* (
           (l5-mt63-reserved-1 (unwrap (read-u8 buffer 0)))
           (l5-mt31-gps-mask (unwrap (read-u64be buffer 0)))
           (l5-mt0-reserved-1 (unwrap (read-u8 buffer 0)))
           (l5-mt (unwrap (read-u16be buffer 0)))
           (l5-preamble (unwrap (read-u8 buffer 0)))
           (l5-mt31-glonass-mask (unwrap (read-u64be buffer 4)))
           (l5-mt31-galileo-mask (unwrap (read-u64be buffer 9)))
           (l5-mt31-spare-112-119 (unwrap (read-u16be buffer 14)))
           (l5-mt31-sbas-mask (unwrap (read-u64be buffer 15)))
           (l5-mt31-bds-mask (unwrap (read-u64be buffer 20)))
           (l5-mt31-reserved (unwrap (read-u32be buffer 24)))
           (l5-mt31-spare-208-214 (unwrap (read-u8 buffer 26)))
           (l5-mt63-reserved-3 (unwrap (read-u8 buffer 27)))
           (l5-mt31-iodm (unwrap (read-u8 buffer 27)))
           (l5-mt0-reserved-3 (unwrap (read-u8 buffer 27)))
           )

      (ok (list
        (cons 'l5-mt63-reserved-1 (list (cons 'raw l5-mt63-reserved-1) (cons 'formatted (fmt-hex l5-mt63-reserved-1))))
        (cons 'l5-mt31-gps-mask (list (cons 'raw l5-mt31-gps-mask) (cons 'formatted (fmt-hex l5-mt31-gps-mask))))
        (cons 'l5-mt0-reserved-1 (list (cons 'raw l5-mt0-reserved-1) (cons 'formatted (fmt-hex l5-mt0-reserved-1))))
        (cons 'l5-mt (list (cons 'raw l5-mt) (cons 'formatted (number->string l5-mt))))
        (cons 'l5-preamble (list (cons 'raw l5-preamble) (cons 'formatted (fmt-hex l5-preamble))))
        (cons 'l5-mt31-glonass-mask (list (cons 'raw l5-mt31-glonass-mask) (cons 'formatted (fmt-hex l5-mt31-glonass-mask))))
        (cons 'l5-mt31-galileo-mask (list (cons 'raw l5-mt31-galileo-mask) (cons 'formatted (fmt-hex l5-mt31-galileo-mask))))
        (cons 'l5-mt31-spare-112-119 (list (cons 'raw l5-mt31-spare-112-119) (cons 'formatted (fmt-hex l5-mt31-spare-112-119))))
        (cons 'l5-mt31-sbas-mask (list (cons 'raw l5-mt31-sbas-mask) (cons 'formatted (fmt-hex l5-mt31-sbas-mask))))
        (cons 'l5-mt31-bds-mask (list (cons 'raw l5-mt31-bds-mask) (cons 'formatted (fmt-hex l5-mt31-bds-mask))))
        (cons 'l5-mt31-reserved (list (cons 'raw l5-mt31-reserved) (cons 'formatted (fmt-hex l5-mt31-reserved))))
        (cons 'l5-mt31-spare-208-214 (list (cons 'raw l5-mt31-spare-208-214) (cons 'formatted (fmt-hex l5-mt31-spare-208-214))))
        (cons 'l5-mt63-reserved-3 (list (cons 'raw l5-mt63-reserved-3) (cons 'formatted (fmt-hex l5-mt63-reserved-3))))
        (cons 'l5-mt31-iodm (list (cons 'raw l5-mt31-iodm) (cons 'formatted (number->string l5-mt31-iodm))))
        (cons 'l5-mt0-reserved-3 (list (cons 'raw l5-mt0-reserved-3) (cons 'formatted (fmt-hex l5-mt0-reserved-3))))
        )))

    (catch (e)
      (err (str "SBAS-L5 parse error: " e)))))

;; dissect-sbas-l5: parse SBAS-L5 from bytevector
;; Returns (ok fields-alist) or (err message)