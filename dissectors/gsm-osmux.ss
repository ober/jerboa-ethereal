;; packet-gsm_osmux.c
;; Routines for packet dissection of Osmux voice/signalling multiplex protocol
;; Copyright 2016-2024 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
;; Written by Daniel Willmann <dwillmann@sysmocom.de>,
;; Pau Espin Pedrol <pespin@sysmocom.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-osmux.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_osmux.c

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
(def (dissect-gsm-osmux buffer)
  "GSM multiplexing for AMR"
  (try
    (let* (
           (stream-id (unwrap (read-u32be buffer 0)))
           (ft-ctr (unwrap (read-u8 buffer 0)))
           (rtp-m (extract-bits ft-ctr 0x80 7))
           (ctr (extract-bits ft-ctr 0x1C 2))
           (amr-f (extract-bits ft-ctr 0x1 0))
           (amr-q (extract-bits ft-ctr 0x2 1))
           (circuit-id (unwrap (read-u8 buffer 0)))
           (seq (unwrap (read-u8 buffer 0)))
           (amr-data (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'stream-id (list (cons 'raw stream-id) (cons 'formatted (number->string stream-id))))
        (cons 'ft-ctr (list (cons 'raw ft-ctr) (cons 'formatted (number->string ft-ctr))))
        (cons 'rtp-m (list (cons 'raw rtp-m) (cons 'formatted (if (= rtp-m 0) "Not set" "Set"))))
        (cons 'ctr (list (cons 'raw ctr) (cons 'formatted (if (= ctr 0) "Not set" "Set"))))
        (cons 'amr-f (list (cons 'raw amr-f) (cons 'formatted (if (= amr-f 0) "Not set" "Set"))))
        (cons 'amr-q (list (cons 'raw amr-q) (cons 'formatted (if (= amr-q 0) "Not set" "Set"))))
        (cons 'circuit-id (list (cons 'raw circuit-id) (cons 'formatted (fmt-hex circuit-id))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (fmt-hex seq))))
        (cons 'amr-data (list (cons 'raw amr-data) (cons 'formatted (fmt-bytes amr-data))))
        )))

    (catch (e)
      (err (str "GSM-OSMUX parse error: " e)))))

;; dissect-gsm-osmux: parse GSM-OSMUX from bytevector
;; Returns (ok fields-alist) or (err message)