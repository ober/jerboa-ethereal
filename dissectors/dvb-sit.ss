;; packet-dvb-sit.c
;; Routines for DVB (ETSI EN 300 468) Selection Information Table (SIT) dissection
;; Copyright 2021, Roman Volkov <volkoff_roman@ukr.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dvb-sit.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dvb_sit.c

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
(def (dissect-dvb-sit buffer)
  "DVB Selection Information Table"
  (try
    (let* (
           (sit-reserved-future-use1 (unwrap (read-u16be buffer 0)))
           (sit-reserved (unwrap (read-u8 buffer 2)))
           (sit-version-number (unwrap (read-u8 buffer 2)))
           (sit-current-next-indicator (unwrap (read-u8 buffer 2)))
           (sit-section-number (unwrap (read-u8 buffer 3)))
           (sit-last-section-number (unwrap (read-u8 buffer 4)))
           (sit-reserved-future-use2 (unwrap (read-u16be buffer 5)))
           (sit-transmission-info-len (unwrap (read-u16be buffer 5)))
           (sit-service-id (unwrap (read-u16be buffer 7)))
           (sit-reserved-future-use3 (unwrap (read-u16be buffer 9)))
           (sit-service-descriptors-length (unwrap (read-u16be buffer 9)))
           )

      (ok (list
        (cons 'sit-reserved-future-use1 (list (cons 'raw sit-reserved-future-use1) (cons 'formatted (fmt-hex sit-reserved-future-use1))))
        (cons 'sit-reserved (list (cons 'raw sit-reserved) (cons 'formatted (fmt-hex sit-reserved))))
        (cons 'sit-version-number (list (cons 'raw sit-version-number) (cons 'formatted (fmt-hex sit-version-number))))
        (cons 'sit-current-next-indicator (list (cons 'raw sit-current-next-indicator) (cons 'formatted (if (= sit-current-next-indicator 0) "False" "True"))))
        (cons 'sit-section-number (list (cons 'raw sit-section-number) (cons 'formatted (number->string sit-section-number))))
        (cons 'sit-last-section-number (list (cons 'raw sit-last-section-number) (cons 'formatted (number->string sit-last-section-number))))
        (cons 'sit-reserved-future-use2 (list (cons 'raw sit-reserved-future-use2) (cons 'formatted (fmt-hex sit-reserved-future-use2))))
        (cons 'sit-transmission-info-len (list (cons 'raw sit-transmission-info-len) (cons 'formatted (number->string sit-transmission-info-len))))
        (cons 'sit-service-id (list (cons 'raw sit-service-id) (cons 'formatted (fmt-hex sit-service-id))))
        (cons 'sit-reserved-future-use3 (list (cons 'raw sit-reserved-future-use3) (cons 'formatted (fmt-hex sit-reserved-future-use3))))
        (cons 'sit-service-descriptors-length (list (cons 'raw sit-service-descriptors-length) (cons 'formatted (number->string sit-service-descriptors-length))))
        )))

    (catch (e)
      (err (str "DVB-SIT parse error: " e)))))

;; dissect-dvb-sit: parse DVB-SIT from bytevector
;; Returns (ok fields-alist) or (err message)