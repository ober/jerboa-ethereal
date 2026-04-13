;; packet-ppi-vector.c
;; Routines for PPI-GEOLOCATION-VECTOR  dissection
;; Copyright 2010, Harris Corp, jellch@harris.com
;;
;; See
;;
;; http://new.11mercenary.net/~johnycsh/ppi_geolocation_spec/
;;
;; for specifications.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-radiotap.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ppi-vector.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ppi_vector.c

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
(def (dissect-ppi-vector buffer)
  "PPI vector decoder"
  (try
    (let* (
           (vector-vflags-rots-absolute (unwrap (read-u8 buffer 0)))
           (vector-vflags-offsets-from-gps (unwrap (read-u8 buffer 0)))
           (vector-version (unwrap (read-u8 buffer 0)))
           (vector-pad (unwrap (read-u8 buffer 0)))
           (vector-length (unwrap (read-u16be buffer 0)))
           (vector-unknown-data (unwrap (slice buffer 0 1)))
           (vector-off-r (unwrap (read-u64be buffer 20)))
           (vector-off-f (unwrap (read-u64be buffer 24)))
           (vector-off-u (unwrap (read-u64be buffer 28)))
           (vector-present (unwrap (read-u32le buffer 176)))
           (vector-present-vflags (extract-bits vector-present 0x0 0))
           (vector-present-vchars (extract-bits vector-present 0x0 0))
           (vector-present-val-x (extract-bits vector-present 0x0 0))
           (vector-present-val-y (extract-bits vector-present 0x0 0))
           (vector-present-val-z (extract-bits vector-present 0x0 0))
           (vector-present-off-x (extract-bits vector-present 0x0 0))
           (vector-present-off-y (extract-bits vector-present 0x0 0))
           (vector-present-off-z (extract-bits vector-present 0x0 0))
           (vector-present-err-rot (extract-bits vector-present 0x0 0))
           (vector-present-err-off (extract-bits vector-present 0x0 0))
           (vector-present-descstr (extract-bits vector-present 0x0 0))
           (vector-presenappsecific-num (extract-bits vector-present 0x0 0))
           (vector-present-appspecific-data (extract-bits vector-present 0x0 0))
           (vector-present-ext (extract-bits vector-present 0x0 0))
           (vector-vflags (unwrap (read-u32be buffer 176)))
           (vector-vflags-defines-forward (unwrap (read-u8 buffer 176)))
           (vector-vchars (unwrap (read-u32be buffer 180)))
           (vector-vchars-antenna (unwrap (read-u8 buffer 180)))
           (vector-vchars-dir-of-travel (unwrap (read-u8 buffer 180)))
           (vector-vchars-front-of-veh (unwrap (read-u8 buffer 180)))
           (vector-vchars-angle-of-arrival (unwrap (read-u8 buffer 180)))
           (vector-vchars-transmitter-pos (unwrap (read-u8 buffer 180)))
           (vector-vchars-gps-derived (unwrap (read-u8 buffer 180)))
           (vector-vchars-ins-derived (unwrap (read-u8 buffer 180)))
           (vector-vchars-compass-derived (unwrap (read-u8 buffer 180)))
           (vector-vchars-accelerometer-derived (unwrap (read-u8 buffer 180)))
           (vector-vchars-human-derived (unwrap (read-u8 buffer 180)))
           (vector-rot-x (unwrap (read-u64be buffer 184)))
           (vector-rot-y (unwrap (read-u64be buffer 188)))
           (vector-rot-z (unwrap (read-u64be buffer 192)))
           (vector-off-x (unwrap (read-u64be buffer 196)))
           (vector-off-y (unwrap (read-u64be buffer 200)))
           (vector-off-z (unwrap (read-u64be buffer 204)))
           (vector-descstr (unwrap (slice buffer 216 32)))
           (vector-appspecific-num (unwrap (read-u32be buffer 248)))
           (vector-appspecific-data (unwrap (slice buffer 252 60)))
           )

      (ok (list
        (cons 'vector-vflags-rots-absolute (list (cons 'raw vector-vflags-rots-absolute) (cons 'formatted (number->string vector-vflags-rots-absolute))))
        (cons 'vector-vflags-offsets-from-gps (list (cons 'raw vector-vflags-offsets-from-gps) (cons 'formatted (number->string vector-vflags-offsets-from-gps))))
        (cons 'vector-version (list (cons 'raw vector-version) (cons 'formatted (number->string vector-version))))
        (cons 'vector-pad (list (cons 'raw vector-pad) (cons 'formatted (number->string vector-pad))))
        (cons 'vector-length (list (cons 'raw vector-length) (cons 'formatted (number->string vector-length))))
        (cons 'vector-unknown-data (list (cons 'raw vector-unknown-data) (cons 'formatted (fmt-bytes vector-unknown-data))))
        (cons 'vector-off-r (list (cons 'raw vector-off-r) (cons 'formatted (number->string vector-off-r))))
        (cons 'vector-off-f (list (cons 'raw vector-off-f) (cons 'formatted (number->string vector-off-f))))
        (cons 'vector-off-u (list (cons 'raw vector-off-u) (cons 'formatted (number->string vector-off-u))))
        (cons 'vector-present (list (cons 'raw vector-present) (cons 'formatted (fmt-hex vector-present))))
        (cons 'vector-present-vflags (list (cons 'raw vector-present-vflags) (cons 'formatted (if (= vector-present-vflags 0) "Not set" "Set"))))
        (cons 'vector-present-vchars (list (cons 'raw vector-present-vchars) (cons 'formatted (if (= vector-present-vchars 0) "Not set" "Set"))))
        (cons 'vector-present-val-x (list (cons 'raw vector-present-val-x) (cons 'formatted (if (= vector-present-val-x 0) "Not set" "Set"))))
        (cons 'vector-present-val-y (list (cons 'raw vector-present-val-y) (cons 'formatted (if (= vector-present-val-y 0) "Not set" "Set"))))
        (cons 'vector-present-val-z (list (cons 'raw vector-present-val-z) (cons 'formatted (if (= vector-present-val-z 0) "Not set" "Set"))))
        (cons 'vector-present-off-x (list (cons 'raw vector-present-off-x) (cons 'formatted (if (= vector-present-off-x 0) "Not set" "Set"))))
        (cons 'vector-present-off-y (list (cons 'raw vector-present-off-y) (cons 'formatted (if (= vector-present-off-y 0) "Not set" "Set"))))
        (cons 'vector-present-off-z (list (cons 'raw vector-present-off-z) (cons 'formatted (if (= vector-present-off-z 0) "Not set" "Set"))))
        (cons 'vector-present-err-rot (list (cons 'raw vector-present-err-rot) (cons 'formatted (if (= vector-present-err-rot 0) "Not set" "Set"))))
        (cons 'vector-present-err-off (list (cons 'raw vector-present-err-off) (cons 'formatted (if (= vector-present-err-off 0) "Not set" "Set"))))
        (cons 'vector-present-descstr (list (cons 'raw vector-present-descstr) (cons 'formatted (if (= vector-present-descstr 0) "Not set" "Set"))))
        (cons 'vector-presenappsecific-num (list (cons 'raw vector-presenappsecific-num) (cons 'formatted (if (= vector-presenappsecific-num 0) "Not set" "Set"))))
        (cons 'vector-present-appspecific-data (list (cons 'raw vector-present-appspecific-data) (cons 'formatted (if (= vector-present-appspecific-data 0) "Not set" "Set"))))
        (cons 'vector-present-ext (list (cons 'raw vector-present-ext) (cons 'formatted (if (= vector-present-ext 0) "Not set" "Set"))))
        (cons 'vector-vflags (list (cons 'raw vector-vflags) (cons 'formatted (fmt-hex vector-vflags))))
        (cons 'vector-vflags-defines-forward (list (cons 'raw vector-vflags-defines-forward) (cons 'formatted (number->string vector-vflags-defines-forward))))
        (cons 'vector-vchars (list (cons 'raw vector-vchars) (cons 'formatted (fmt-hex vector-vchars))))
        (cons 'vector-vchars-antenna (list (cons 'raw vector-vchars-antenna) (cons 'formatted (number->string vector-vchars-antenna))))
        (cons 'vector-vchars-dir-of-travel (list (cons 'raw vector-vchars-dir-of-travel) (cons 'formatted (number->string vector-vchars-dir-of-travel))))
        (cons 'vector-vchars-front-of-veh (list (cons 'raw vector-vchars-front-of-veh) (cons 'formatted (number->string vector-vchars-front-of-veh))))
        (cons 'vector-vchars-angle-of-arrival (list (cons 'raw vector-vchars-angle-of-arrival) (cons 'formatted (number->string vector-vchars-angle-of-arrival))))
        (cons 'vector-vchars-transmitter-pos (list (cons 'raw vector-vchars-transmitter-pos) (cons 'formatted (number->string vector-vchars-transmitter-pos))))
        (cons 'vector-vchars-gps-derived (list (cons 'raw vector-vchars-gps-derived) (cons 'formatted (number->string vector-vchars-gps-derived))))
        (cons 'vector-vchars-ins-derived (list (cons 'raw vector-vchars-ins-derived) (cons 'formatted (number->string vector-vchars-ins-derived))))
        (cons 'vector-vchars-compass-derived (list (cons 'raw vector-vchars-compass-derived) (cons 'formatted (number->string vector-vchars-compass-derived))))
        (cons 'vector-vchars-accelerometer-derived (list (cons 'raw vector-vchars-accelerometer-derived) (cons 'formatted (number->string vector-vchars-accelerometer-derived))))
        (cons 'vector-vchars-human-derived (list (cons 'raw vector-vchars-human-derived) (cons 'formatted (number->string vector-vchars-human-derived))))
        (cons 'vector-rot-x (list (cons 'raw vector-rot-x) (cons 'formatted (number->string vector-rot-x))))
        (cons 'vector-rot-y (list (cons 'raw vector-rot-y) (cons 'formatted (number->string vector-rot-y))))
        (cons 'vector-rot-z (list (cons 'raw vector-rot-z) (cons 'formatted (number->string vector-rot-z))))
        (cons 'vector-off-x (list (cons 'raw vector-off-x) (cons 'formatted (number->string vector-off-x))))
        (cons 'vector-off-y (list (cons 'raw vector-off-y) (cons 'formatted (number->string vector-off-y))))
        (cons 'vector-off-z (list (cons 'raw vector-off-z) (cons 'formatted (number->string vector-off-z))))
        (cons 'vector-descstr (list (cons 'raw vector-descstr) (cons 'formatted (utf8->string vector-descstr))))
        (cons 'vector-appspecific-num (list (cons 'raw vector-appspecific-num) (cons 'formatted (fmt-hex vector-appspecific-num))))
        (cons 'vector-appspecific-data (list (cons 'raw vector-appspecific-data) (cons 'formatted (fmt-bytes vector-appspecific-data))))
        )))

    (catch (e)
      (err (str "PPI-VECTOR parse error: " e)))))

;; dissect-ppi-vector: parse PPI-VECTOR from bytevector
;; Returns (ok fields-alist) or (err message)