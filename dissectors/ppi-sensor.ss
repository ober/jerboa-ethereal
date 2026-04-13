;; packet-ppi-sensor.c
;; Routines for PPI-GEOLOCATION-SENSOR dissection
;; Copyright 2010, Harris Corp, jellch@harris.com
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-ppi-antenna.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ppi-sensor.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ppi_sensor.c

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
(def (dissect-ppi-sensor buffer)
  "PPI sensor decoder"
  (try
    (let* (
           (sensor-pad (unwrap (read-u8 buffer 0)))
           (sensor-length (unwrap (read-u16be buffer 0)))
           (sensor-present (unwrap (read-u32le buffer 0)))
           (sensor-present-sensortype (extract-bits sensor-present 0x0 0))
           (sensor-present-scalefactor (extract-bits sensor-present 0x0 0))
           (sensor-present-val-x (extract-bits sensor-present 0x0 0))
           (sensor-present-val-y (extract-bits sensor-present 0x0 0))
           (sensor-present-val-z (extract-bits sensor-present 0x0 0))
           (sensor-present-val-t (extract-bits sensor-present 0x0 0))
           (sensor-present-val-e (extract-bits sensor-present 0x0 0))
           (sensor-present-descstr (extract-bits sensor-present 0x0 0))
           (sensor-present-appspecific-num (extract-bits sensor-present 0x0 0))
           (sensor-present-appspecific-data (extract-bits sensor-present 0x0 0))
           (sensor-present-ext (extract-bits sensor-present 0x0 0))
           (sensor-sensortype (unwrap (read-u16be buffer 0)))
           (sensor-scalefactor (unwrap (read-u8 buffer 2)))
           (sensor-val-x (unwrap (read-u64be buffer 3)))
           (sensor-val-y (unwrap (read-u64be buffer 7)))
           (sensor-val-z (unwrap (read-u64be buffer 11)))
           (sensor-val-t (unwrap (read-u64be buffer 15)))
           (sensor-val-e (unwrap (read-u64be buffer 19)))
           (sensor-descstr (unwrap (slice buffer 23 32)))
           (sensor-appspecific-num (unwrap (read-u32be buffer 55)))
           (sensor-appspecific-data (unwrap (slice buffer 59 60)))
           (sensor-version (unwrap (read-u8 buffer 119)))
           )

      (ok (list
        (cons 'sensor-pad (list (cons 'raw sensor-pad) (cons 'formatted (number->string sensor-pad))))
        (cons 'sensor-length (list (cons 'raw sensor-length) (cons 'formatted (number->string sensor-length))))
        (cons 'sensor-present (list (cons 'raw sensor-present) (cons 'formatted (fmt-hex sensor-present))))
        (cons 'sensor-present-sensortype (list (cons 'raw sensor-present-sensortype) (cons 'formatted (if (= sensor-present-sensortype 0) "Not set" "Set"))))
        (cons 'sensor-present-scalefactor (list (cons 'raw sensor-present-scalefactor) (cons 'formatted (if (= sensor-present-scalefactor 0) "Not set" "Set"))))
        (cons 'sensor-present-val-x (list (cons 'raw sensor-present-val-x) (cons 'formatted (if (= sensor-present-val-x 0) "Not set" "Set"))))
        (cons 'sensor-present-val-y (list (cons 'raw sensor-present-val-y) (cons 'formatted (if (= sensor-present-val-y 0) "Not set" "Set"))))
        (cons 'sensor-present-val-z (list (cons 'raw sensor-present-val-z) (cons 'formatted (if (= sensor-present-val-z 0) "Not set" "Set"))))
        (cons 'sensor-present-val-t (list (cons 'raw sensor-present-val-t) (cons 'formatted (if (= sensor-present-val-t 0) "Not set" "Set"))))
        (cons 'sensor-present-val-e (list (cons 'raw sensor-present-val-e) (cons 'formatted (if (= sensor-present-val-e 0) "Not set" "Set"))))
        (cons 'sensor-present-descstr (list (cons 'raw sensor-present-descstr) (cons 'formatted (if (= sensor-present-descstr 0) "Not set" "Set"))))
        (cons 'sensor-present-appspecific-num (list (cons 'raw sensor-present-appspecific-num) (cons 'formatted (if (= sensor-present-appspecific-num 0) "Not set" "Set"))))
        (cons 'sensor-present-appspecific-data (list (cons 'raw sensor-present-appspecific-data) (cons 'formatted (if (= sensor-present-appspecific-data 0) "Not set" "Set"))))
        (cons 'sensor-present-ext (list (cons 'raw sensor-present-ext) (cons 'formatted (if (= sensor-present-ext 0) "Not set" "Set"))))
        (cons 'sensor-sensortype (list (cons 'raw sensor-sensortype) (cons 'formatted (number->string sensor-sensortype))))
        (cons 'sensor-scalefactor (list (cons 'raw sensor-scalefactor) (cons 'formatted (number->string sensor-scalefactor))))
        (cons 'sensor-val-x (list (cons 'raw sensor-val-x) (cons 'formatted (number->string sensor-val-x))))
        (cons 'sensor-val-y (list (cons 'raw sensor-val-y) (cons 'formatted (number->string sensor-val-y))))
        (cons 'sensor-val-z (list (cons 'raw sensor-val-z) (cons 'formatted (number->string sensor-val-z))))
        (cons 'sensor-val-t (list (cons 'raw sensor-val-t) (cons 'formatted (number->string sensor-val-t))))
        (cons 'sensor-val-e (list (cons 'raw sensor-val-e) (cons 'formatted (number->string sensor-val-e))))
        (cons 'sensor-descstr (list (cons 'raw sensor-descstr) (cons 'formatted (utf8->string sensor-descstr))))
        (cons 'sensor-appspecific-num (list (cons 'raw sensor-appspecific-num) (cons 'formatted (fmt-hex sensor-appspecific-num))))
        (cons 'sensor-appspecific-data (list (cons 'raw sensor-appspecific-data) (cons 'formatted (fmt-bytes sensor-appspecific-data))))
        (cons 'sensor-version (list (cons 'raw sensor-version) (cons 'formatted (number->string sensor-version))))
        )))

    (catch (e)
      (err (str "PPI-SENSOR parse error: " e)))))

;; dissect-ppi-sensor: parse PPI-SENSOR from bytevector
;; Returns (ok fields-alist) or (err message)