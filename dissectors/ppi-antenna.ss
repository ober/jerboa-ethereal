;; packet-ppi-antenna.c
;; Routines for PPI-GEOLOCATION-ANTENNA  dissection
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

;; jerboa-ethereal/dissectors/ppi-antenna.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ppi_antenna.c

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
(def (dissect-ppi-antenna buffer)
  "PPI antenna decoder"
  (try
    (let* (
           (antenna-pad (unwrap (read-u8 buffer 0)))
           (antenna-length (unwrap (read-u16be buffer 0)))
           (antenna-present (unwrap (read-u32le buffer 0)))
           (antenna-present-flags (extract-bits antenna-present 0x0 0))
           (antenna-present-gaindb (extract-bits antenna-present 0x0 0))
           (antenna-present-horizbw (extract-bits antenna-present 0x0 0))
           (antenna-present-vertbw (extract-bits antenna-present 0x0 0))
           (antenna-present-pgain (extract-bits antenna-present 0x0 0))
           (antenna-present-beamid (extract-bits antenna-present 0x0 0))
           (antenna-present-serialnum (extract-bits antenna-present 0x0 0))
           (antenna-present-modelname (extract-bits antenna-present 0x0 0))
           (antenna-present-descstr (extract-bits antenna-present 0x0 0))
           (antenna-present-appspecific-num (extract-bits antenna-present 0x0 0))
           (antenna-present-appspecific-data (extract-bits antenna-present 0x0 0))
           (antenna-present-ext (extract-bits antenna-present 0x0 0))
           (antenna-flags (unwrap (read-u32le buffer 0)))
           (antennaflags-mimo (extract-bits antenna-flags 0x0 0))
           (antennaflags-horizpol (extract-bits antenna-flags 0x0 0))
           (antennaflags-vertpol (extract-bits antenna-flags 0x0 0))
           (antennaflags-circpol-l (extract-bits antenna-flags 0x0 0))
           (antennaflags-circpol-r (extract-bits antenna-flags 0x0 0))
           (antennaflags-steer-elec (extract-bits antenna-flags 0x0 0))
           (antennaflags-steer-mech (extract-bits antenna-flags 0x0 0))
           (antenna-gaindb (unwrap (read-u8 buffer 4)))
           (antenna-horizbw (unwrap (read-u64be buffer 5)))
           (antenna-vertbw (unwrap (read-u64be buffer 9)))
           (antenna-pgain (unwrap (read-u64be buffer 13)))
           (antenna-beamid (unwrap (read-u16be buffer 17)))
           (antenna-serialnum (unwrap (slice buffer 19 32)))
           (antenna-modelname (unwrap (slice buffer 51 32)))
           (antenna-descstr (unwrap (slice buffer 83 32)))
           (antenna-appspecific-num (unwrap (read-u32be buffer 115)))
           (antenna-appspecific-data (unwrap (slice buffer 119 60)))
           (antenna-version (unwrap (read-u8 buffer 179)))
           )

      (ok (list
        (cons 'antenna-pad (list (cons 'raw antenna-pad) (cons 'formatted (number->string antenna-pad))))
        (cons 'antenna-length (list (cons 'raw antenna-length) (cons 'formatted (number->string antenna-length))))
        (cons 'antenna-present (list (cons 'raw antenna-present) (cons 'formatted (fmt-hex antenna-present))))
        (cons 'antenna-present-flags (list (cons 'raw antenna-present-flags) (cons 'formatted (if (= antenna-present-flags 0) "Not set" "Set"))))
        (cons 'antenna-present-gaindb (list (cons 'raw antenna-present-gaindb) (cons 'formatted (if (= antenna-present-gaindb 0) "Not set" "Set"))))
        (cons 'antenna-present-horizbw (list (cons 'raw antenna-present-horizbw) (cons 'formatted (if (= antenna-present-horizbw 0) "Not set" "Set"))))
        (cons 'antenna-present-vertbw (list (cons 'raw antenna-present-vertbw) (cons 'formatted (if (= antenna-present-vertbw 0) "Not set" "Set"))))
        (cons 'antenna-present-pgain (list (cons 'raw antenna-present-pgain) (cons 'formatted (if (= antenna-present-pgain 0) "Not set" "Set"))))
        (cons 'antenna-present-beamid (list (cons 'raw antenna-present-beamid) (cons 'formatted (if (= antenna-present-beamid 0) "Not set" "Set"))))
        (cons 'antenna-present-serialnum (list (cons 'raw antenna-present-serialnum) (cons 'formatted (if (= antenna-present-serialnum 0) "Not set" "Set"))))
        (cons 'antenna-present-modelname (list (cons 'raw antenna-present-modelname) (cons 'formatted (if (= antenna-present-modelname 0) "Not set" "Set"))))
        (cons 'antenna-present-descstr (list (cons 'raw antenna-present-descstr) (cons 'formatted (if (= antenna-present-descstr 0) "Not set" "Set"))))
        (cons 'antenna-present-appspecific-num (list (cons 'raw antenna-present-appspecific-num) (cons 'formatted (if (= antenna-present-appspecific-num 0) "Not set" "Set"))))
        (cons 'antenna-present-appspecific-data (list (cons 'raw antenna-present-appspecific-data) (cons 'formatted (if (= antenna-present-appspecific-data 0) "Not set" "Set"))))
        (cons 'antenna-present-ext (list (cons 'raw antenna-present-ext) (cons 'formatted (if (= antenna-present-ext 0) "Not set" "Set"))))
        (cons 'antenna-flags (list (cons 'raw antenna-flags) (cons 'formatted (fmt-hex antenna-flags))))
        (cons 'antennaflags-mimo (list (cons 'raw antennaflags-mimo) (cons 'formatted (if (= antennaflags-mimo 0) "Not set" "Set"))))
        (cons 'antennaflags-horizpol (list (cons 'raw antennaflags-horizpol) (cons 'formatted (if (= antennaflags-horizpol 0) "Not set" "Set"))))
        (cons 'antennaflags-vertpol (list (cons 'raw antennaflags-vertpol) (cons 'formatted (if (= antennaflags-vertpol 0) "Not set" "Set"))))
        (cons 'antennaflags-circpol-l (list (cons 'raw antennaflags-circpol-l) (cons 'formatted (if (= antennaflags-circpol-l 0) "Not set" "Set"))))
        (cons 'antennaflags-circpol-r (list (cons 'raw antennaflags-circpol-r) (cons 'formatted (if (= antennaflags-circpol-r 0) "Not set" "Set"))))
        (cons 'antennaflags-steer-elec (list (cons 'raw antennaflags-steer-elec) (cons 'formatted (if (= antennaflags-steer-elec 0) "Not set" "Set"))))
        (cons 'antennaflags-steer-mech (list (cons 'raw antennaflags-steer-mech) (cons 'formatted (if (= antennaflags-steer-mech 0) "Not set" "Set"))))
        (cons 'antenna-gaindb (list (cons 'raw antenna-gaindb) (cons 'formatted (number->string antenna-gaindb))))
        (cons 'antenna-horizbw (list (cons 'raw antenna-horizbw) (cons 'formatted (number->string antenna-horizbw))))
        (cons 'antenna-vertbw (list (cons 'raw antenna-vertbw) (cons 'formatted (number->string antenna-vertbw))))
        (cons 'antenna-pgain (list (cons 'raw antenna-pgain) (cons 'formatted (number->string antenna-pgain))))
        (cons 'antenna-beamid (list (cons 'raw antenna-beamid) (cons 'formatted (fmt-hex antenna-beamid))))
        (cons 'antenna-serialnum (list (cons 'raw antenna-serialnum) (cons 'formatted (utf8->string antenna-serialnum))))
        (cons 'antenna-modelname (list (cons 'raw antenna-modelname) (cons 'formatted (utf8->string antenna-modelname))))
        (cons 'antenna-descstr (list (cons 'raw antenna-descstr) (cons 'formatted (utf8->string antenna-descstr))))
        (cons 'antenna-appspecific-num (list (cons 'raw antenna-appspecific-num) (cons 'formatted (fmt-hex antenna-appspecific-num))))
        (cons 'antenna-appspecific-data (list (cons 'raw antenna-appspecific-data) (cons 'formatted (fmt-bytes antenna-appspecific-data))))
        (cons 'antenna-version (list (cons 'raw antenna-version) (cons 'formatted (number->string antenna-version))))
        )))

    (catch (e)
      (err (str "PPI-ANTENNA parse error: " e)))))

;; dissect-ppi-antenna: parse PPI-ANTENNA from bytevector
;; Returns (ok fields-alist) or (err message)