;; packet-ehs.c
;; Routines for "Enhanced HOSC System" (EHS) dissection
;; Copyright 2000, Scott Hovis scott.hovis@ums.msfc.nasa.gov
;; Enhanced 2008, Matt Dunkle Matthew.L.Dunkle@nasa.gov
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.com>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ehs.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ehs.c

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
(def (dissect-ehs buffer)
  "EHS"
  (try
    (let* (
           (ph-version (unwrap (read-u8 buffer 0)))
           (ph-mission (unwrap (read-u8 buffer 0)))
           (ph-year (unwrap (read-u8 buffer 0)))
           (ph-jday (unwrap (read-u16be buffer 0)))
           (ph-hour (unwrap (read-u8 buffer 2)))
           (ph-minute (unwrap (read-u8 buffer 2)))
           (ph-second (unwrap (read-u8 buffer 2)))
           (ph-tenths (unwrap (read-u8 buffer 2)))
           (ph-new-data-flag (unwrap (read-u8 buffer 2)))
           (ph-pad1 (unwrap (read-u8 buffer 2)))
           (ph-hold-flag (unwrap (read-u8 buffer 2)))
           (ph-sign-flag (unwrap (read-u8 buffer 2)))
           (ph-pad2 (unwrap (read-u8 buffer 2)))
           (ph-pad3 (unwrap (read-u8 buffer 2)))
           (ph-pad4 (unwrap (read-u8 buffer 2)))
           (ph-hosc-packet-size (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'ph-version (list (cons 'raw ph-version) (cons 'formatted (number->string ph-version))))
        (cons 'ph-mission (list (cons 'raw ph-mission) (cons 'formatted (number->string ph-mission))))
        (cons 'ph-year (list (cons 'raw ph-year) (cons 'formatted (number->string ph-year))))
        (cons 'ph-jday (list (cons 'raw ph-jday) (cons 'formatted (number->string ph-jday))))
        (cons 'ph-hour (list (cons 'raw ph-hour) (cons 'formatted (number->string ph-hour))))
        (cons 'ph-minute (list (cons 'raw ph-minute) (cons 'formatted (number->string ph-minute))))
        (cons 'ph-second (list (cons 'raw ph-second) (cons 'formatted (number->string ph-second))))
        (cons 'ph-tenths (list (cons 'raw ph-tenths) (cons 'formatted (number->string ph-tenths))))
        (cons 'ph-new-data-flag (list (cons 'raw ph-new-data-flag) (cons 'formatted (number->string ph-new-data-flag))))
        (cons 'ph-pad1 (list (cons 'raw ph-pad1) (cons 'formatted (number->string ph-pad1))))
        (cons 'ph-hold-flag (list (cons 'raw ph-hold-flag) (cons 'formatted (number->string ph-hold-flag))))
        (cons 'ph-sign-flag (list (cons 'raw ph-sign-flag) (cons 'formatted (number->string ph-sign-flag))))
        (cons 'ph-pad2 (list (cons 'raw ph-pad2) (cons 'formatted (number->string ph-pad2))))
        (cons 'ph-pad3 (list (cons 'raw ph-pad3) (cons 'formatted (number->string ph-pad3))))
        (cons 'ph-pad4 (list (cons 'raw ph-pad4) (cons 'formatted (number->string ph-pad4))))
        (cons 'ph-hosc-packet-size (list (cons 'raw ph-hosc-packet-size) (cons 'formatted (number->string ph-hosc-packet-size))))
        )))

    (catch (e)
      (err (str "EHS parse error: " e)))))

;; dissect-ehs: parse EHS from bytevector
;; Returns (ok fields-alist) or (err message)