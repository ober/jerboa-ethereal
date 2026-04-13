;; packet-gsm_a_common.c
;; Common routines for GSM A Interface dissection
;;
;; Copyright 2003, Michael Lum <mlum [AT] telostech.com>
;; In association with Telos Technology Inc.
;;
;; Split from packet-gsm_a.c by Neil Piercy <Neil [AT] littlebriars.co.uk>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-a-common.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_a_common.c

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
(def (dissect-gsm-a-common buffer)
  "GSM A-I/F COMMON"
  (try
    (let* (
           (a-geo-loc-no-of-points (unwrap (read-u8 buffer 0)))
           (a-geo-loc-deg-of-lat (unwrap (read-u24be buffer 0)))
           (a-geo-loc-uncertainty-code (unwrap (read-u8 buffer 0)))
           (a-geo-loc-uncertainty-semi-major (unwrap (read-u8 buffer 0)))
           (a-geo-loc-uncertainty-semi-minor (unwrap (read-u8 buffer 0)))
           (a-geo-loc-altitude (unwrap (read-u16be buffer 0)))
           (a-geo-loc-uncertainty-altitude (unwrap (read-u8 buffer 0)))
           (a-geo-loc-inner-radius (unwrap (read-u16be buffer 0)))
           (a-geo-loc-uncertainty-radius (unwrap (read-u8 buffer 0)))
           (a-geo-loc-offset-angle (unwrap (read-u8 buffer 0)))
           (a-geo-loc-included-angle (unwrap (read-u8 buffer 0)))
           (a-geo-loc-confidence (unwrap (read-u8 buffer 8)))
           (a-geo-loc-high-acc-deg-of-lat (unwrap (read-u32be buffer 8)))
           (a-geo-loc-high-acc-deg-of-long (unwrap (read-u32be buffer 12)))
           (a-geo-loc-high-acc-uncertainty-semi-major (unwrap (read-u8 buffer 19)))
           (a-geo-loc-high-acc-uncertainty-semi-minor (unwrap (read-u8 buffer 19)))
           (a-geo-loc-orientation-of-major-axis (unwrap (read-u8 buffer 19)))
           (a-geo-loc-horizontal-confidence (unwrap (read-u8 buffer 19)))
           (a-geo-loc-high-acc-uncertainty-alt (unwrap (read-u8 buffer 19)))
           (a-geo-loc-vertical-confidence (unwrap (read-u8 buffer 19)))
           )

      (ok (list
        (cons 'a-geo-loc-no-of-points (list (cons 'raw a-geo-loc-no-of-points) (cons 'formatted (number->string a-geo-loc-no-of-points))))
        (cons 'a-geo-loc-deg-of-lat (list (cons 'raw a-geo-loc-deg-of-lat) (cons 'formatted (number->string a-geo-loc-deg-of-lat))))
        (cons 'a-geo-loc-uncertainty-code (list (cons 'raw a-geo-loc-uncertainty-code) (cons 'formatted (number->string a-geo-loc-uncertainty-code))))
        (cons 'a-geo-loc-uncertainty-semi-major (list (cons 'raw a-geo-loc-uncertainty-semi-major) (cons 'formatted (number->string a-geo-loc-uncertainty-semi-major))))
        (cons 'a-geo-loc-uncertainty-semi-minor (list (cons 'raw a-geo-loc-uncertainty-semi-minor) (cons 'formatted (number->string a-geo-loc-uncertainty-semi-minor))))
        (cons 'a-geo-loc-altitude (list (cons 'raw a-geo-loc-altitude) (cons 'formatted (number->string a-geo-loc-altitude))))
        (cons 'a-geo-loc-uncertainty-altitude (list (cons 'raw a-geo-loc-uncertainty-altitude) (cons 'formatted (number->string a-geo-loc-uncertainty-altitude))))
        (cons 'a-geo-loc-inner-radius (list (cons 'raw a-geo-loc-inner-radius) (cons 'formatted (number->string a-geo-loc-inner-radius))))
        (cons 'a-geo-loc-uncertainty-radius (list (cons 'raw a-geo-loc-uncertainty-radius) (cons 'formatted (number->string a-geo-loc-uncertainty-radius))))
        (cons 'a-geo-loc-offset-angle (list (cons 'raw a-geo-loc-offset-angle) (cons 'formatted (number->string a-geo-loc-offset-angle))))
        (cons 'a-geo-loc-included-angle (list (cons 'raw a-geo-loc-included-angle) (cons 'formatted (number->string a-geo-loc-included-angle))))
        (cons 'a-geo-loc-confidence (list (cons 'raw a-geo-loc-confidence) (cons 'formatted (number->string a-geo-loc-confidence))))
        (cons 'a-geo-loc-high-acc-deg-of-lat (list (cons 'raw a-geo-loc-high-acc-deg-of-lat) (cons 'formatted (number->string a-geo-loc-high-acc-deg-of-lat))))
        (cons 'a-geo-loc-high-acc-deg-of-long (list (cons 'raw a-geo-loc-high-acc-deg-of-long) (cons 'formatted (number->string a-geo-loc-high-acc-deg-of-long))))
        (cons 'a-geo-loc-high-acc-uncertainty-semi-major (list (cons 'raw a-geo-loc-high-acc-uncertainty-semi-major) (cons 'formatted (number->string a-geo-loc-high-acc-uncertainty-semi-major))))
        (cons 'a-geo-loc-high-acc-uncertainty-semi-minor (list (cons 'raw a-geo-loc-high-acc-uncertainty-semi-minor) (cons 'formatted (number->string a-geo-loc-high-acc-uncertainty-semi-minor))))
        (cons 'a-geo-loc-orientation-of-major-axis (list (cons 'raw a-geo-loc-orientation-of-major-axis) (cons 'formatted (number->string a-geo-loc-orientation-of-major-axis))))
        (cons 'a-geo-loc-horizontal-confidence (list (cons 'raw a-geo-loc-horizontal-confidence) (cons 'formatted (number->string a-geo-loc-horizontal-confidence))))
        (cons 'a-geo-loc-high-acc-uncertainty-alt (list (cons 'raw a-geo-loc-high-acc-uncertainty-alt) (cons 'formatted (number->string a-geo-loc-high-acc-uncertainty-alt))))
        (cons 'a-geo-loc-vertical-confidence (list (cons 'raw a-geo-loc-vertical-confidence) (cons 'formatted (number->string a-geo-loc-vertical-confidence))))
        )))

    (catch (e)
      (err (str "GSM-A-COMMON parse error: " e)))))

;; dissect-gsm-a-common: parse GSM-A-COMMON from bytevector
;; Returns (ok fields-alist) or (err message)