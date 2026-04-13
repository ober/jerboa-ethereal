;; packet-ppi-gps.c
;; Routines for PPI-GEOLOCATION-GPS  dissection
;; Copyright 2010, Harris Corp, jellch@harris.com
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-radiotap.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ppi-gps.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ppi_gps.c

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
(def (dissect-ppi-gps buffer)
  "PPI Geotagging GPS tag decoder"
  (try
    (let* (
           (gps-pad (unwrap (read-u8 buffer 0)))
           (gps-length (unwrap (read-u16be buffer 0)))
           (gps-gpsflags-flags (unwrap (read-u32le buffer 0)))
           (gps-lat (unwrap (read-u64be buffer 4)))
           (gps-lon (unwrap (read-u64be buffer 8)))
           (gps-alt (unwrap (read-u64be buffer 12)))
           (gps-alt-gnd (unwrap (read-u64be buffer 16)))
           (gps-fractime (unwrap (read-u32be buffer 20)))
           (gps-eph (unwrap (read-u64be buffer 24)))
           (gps-epv (unwrap (read-u64be buffer 28)))
           (gps-ept (unwrap (read-u64be buffer 32)))
           (gps-descstr (unwrap (slice buffer 36 32)))
           (gps-appspecific-num (unwrap (read-u32be buffer 68)))
           (gps-appspecific-data (unwrap (slice buffer 72 60)))
           (gps-version (unwrap (read-u8 buffer 132)))
           )

      (ok (list
        (cons 'gps-pad (list (cons 'raw gps-pad) (cons 'formatted (number->string gps-pad))))
        (cons 'gps-length (list (cons 'raw gps-length) (cons 'formatted (number->string gps-length))))
        (cons 'gps-gpsflags-flags (list (cons 'raw gps-gpsflags-flags) (cons 'formatted (fmt-hex gps-gpsflags-flags))))
        (cons 'gps-lat (list (cons 'raw gps-lat) (cons 'formatted (number->string gps-lat))))
        (cons 'gps-lon (list (cons 'raw gps-lon) (cons 'formatted (number->string gps-lon))))
        (cons 'gps-alt (list (cons 'raw gps-alt) (cons 'formatted (number->string gps-alt))))
        (cons 'gps-alt-gnd (list (cons 'raw gps-alt-gnd) (cons 'formatted (number->string gps-alt-gnd))))
        (cons 'gps-fractime (list (cons 'raw gps-fractime) (cons 'formatted (number->string gps-fractime))))
        (cons 'gps-eph (list (cons 'raw gps-eph) (cons 'formatted (number->string gps-eph))))
        (cons 'gps-epv (list (cons 'raw gps-epv) (cons 'formatted (number->string gps-epv))))
        (cons 'gps-ept (list (cons 'raw gps-ept) (cons 'formatted (number->string gps-ept))))
        (cons 'gps-descstr (list (cons 'raw gps-descstr) (cons 'formatted (utf8->string gps-descstr))))
        (cons 'gps-appspecific-num (list (cons 'raw gps-appspecific-num) (cons 'formatted (fmt-hex gps-appspecific-num))))
        (cons 'gps-appspecific-data (list (cons 'raw gps-appspecific-data) (cons 'formatted (fmt-bytes gps-appspecific-data))))
        (cons 'gps-version (list (cons 'raw gps-version) (cons 'formatted (number->string gps-version))))
        )))

    (catch (e)
      (err (str "PPI-GPS parse error: " e)))))

;; dissect-ppi-gps: parse PPI-GPS from bytevector
;; Returns (ok fields-alist) or (err message)