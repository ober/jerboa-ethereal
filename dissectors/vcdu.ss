;; packet-vcdu.c
;; Routines for VCDU dissection
;; Copyright 2000, Scott Hovis scott.hovis@ums.msfc.nasa.gov
;; Enhanced 2008, Matt Dunkle Matthew.L.Dunkle@nasa.gov
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.com>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vcdu.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vcdu.c

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
(def (dissect-vcdu buffer)
  "VCDU"
  (try
    (let* (
           (ccsds-continuation-packet (unwrap (slice buffer 0 1)))
           (ccsds-all-fill (unwrap (slice buffer 0 1)))
           (bitream-all-fill (unwrap (slice buffer 0 1)))
           (bitream-all-data-anomaly (unwrap (slice buffer 0 1)))
           (bitream-all-data (unwrap (slice buffer 0 1)))
           (gsc (unwrap (read-u64be buffer 0)))
           (unused (unwrap (read-u16be buffer 8)))
           (framelen (unwrap (read-u16be buffer 10)))
           (rs-enable (unwrap (read-u8 buffer 12)))
           (rs-error (unwrap (read-u8 buffer 12)))
           (crc-enable (unwrap (read-u8 buffer 12)))
           (crc-error (unwrap (read-u8 buffer 12)))
           (mcs-enable (unwrap (read-u8 buffer 12)))
           (mcs-num-error (unwrap (read-u8 buffer 12)))
           (pb5 (unwrap (read-u16be buffer 14)))
           (jday (unwrap (read-u16be buffer 14)))
           (seconds (unwrap (read-u24be buffer 15)))
           (msec (unwrap (read-u16be buffer 18)))
           (spare (unwrap (read-u16be buffer 18)))
           (ground-receipt-time (unwrap (slice buffer 20 6)))
           (version (unwrap (read-u16be buffer 20)))
           (sp-id (unwrap (read-u16be buffer 20)))
           (vc-id (unwrap (read-u16be buffer 20)))
           (seq (unwrap (read-u24be buffer 22)))
           (replay (unwrap (read-u8 buffer 25)))
           (lbp (unwrap (read-u16be buffer 26)))
           (fhp (unwrap (read-u16be buffer 26)))
           (data (unwrap (slice buffer 28 1)))
           )

      (ok (list
        (cons 'ccsds-continuation-packet (list (cons 'raw ccsds-continuation-packet) (cons 'formatted (fmt-bytes ccsds-continuation-packet))))
        (cons 'ccsds-all-fill (list (cons 'raw ccsds-all-fill) (cons 'formatted (fmt-bytes ccsds-all-fill))))
        (cons 'bitream-all-fill (list (cons 'raw bitream-all-fill) (cons 'formatted (fmt-bytes bitream-all-fill))))
        (cons 'bitream-all-data-anomaly (list (cons 'raw bitream-all-data-anomaly) (cons 'formatted (fmt-bytes bitream-all-data-anomaly))))
        (cons 'bitream-all-data (list (cons 'raw bitream-all-data) (cons 'formatted (fmt-bytes bitream-all-data))))
        (cons 'gsc (list (cons 'raw gsc) (cons 'formatted (number->string gsc))))
        (cons 'unused (list (cons 'raw unused) (cons 'formatted (number->string unused))))
        (cons 'framelen (list (cons 'raw framelen) (cons 'formatted (number->string framelen))))
        (cons 'rs-enable (list (cons 'raw rs-enable) (cons 'formatted (number->string rs-enable))))
        (cons 'rs-error (list (cons 'raw rs-error) (cons 'formatted (number->string rs-error))))
        (cons 'crc-enable (list (cons 'raw crc-enable) (cons 'formatted (number->string crc-enable))))
        (cons 'crc-error (list (cons 'raw crc-error) (cons 'formatted (number->string crc-error))))
        (cons 'mcs-enable (list (cons 'raw mcs-enable) (cons 'formatted (number->string mcs-enable))))
        (cons 'mcs-num-error (list (cons 'raw mcs-num-error) (cons 'formatted (number->string mcs-num-error))))
        (cons 'pb5 (list (cons 'raw pb5) (cons 'formatted (number->string pb5))))
        (cons 'jday (list (cons 'raw jday) (cons 'formatted (number->string jday))))
        (cons 'seconds (list (cons 'raw seconds) (cons 'formatted (number->string seconds))))
        (cons 'msec (list (cons 'raw msec) (cons 'formatted (number->string msec))))
        (cons 'spare (list (cons 'raw spare) (cons 'formatted (number->string spare))))
        (cons 'ground-receipt-time (list (cons 'raw ground-receipt-time) (cons 'formatted (utf8->string ground-receipt-time))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'sp-id (list (cons 'raw sp-id) (cons 'formatted (number->string sp-id))))
        (cons 'vc-id (list (cons 'raw vc-id) (cons 'formatted (number->string vc-id))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'replay (list (cons 'raw replay) (cons 'formatted (number->string replay))))
        (cons 'lbp (list (cons 'raw lbp) (cons 'formatted (number->string lbp))))
        (cons 'fhp (list (cons 'raw fhp) (cons 'formatted (number->string fhp))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        )))

    (catch (e)
      (err (str "VCDU parse error: " e)))))

;; dissect-vcdu: parse VCDU from bytevector
;; Returns (ok fields-alist) or (err message)