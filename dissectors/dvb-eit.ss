;; packet-dvb-eit.c
;; Routines for DVB (ETSI EN 300 468) Event Information Table (EIT) dissection
;; Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dvb-eit.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dvb_eit.c

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
(def (dissect-dvb-eit buffer)
  "DVB Event Information Table"
  (try
    (let* (
           (eit-service-id (unwrap (read-u16be buffer 0)))
           (eit-reserved (unwrap (read-u8 buffer 2)))
           (eit-version-number (unwrap (read-u8 buffer 2)))
           (eit-current-next-indicator (unwrap (read-u8 buffer 2)))
           (eit-section-number (unwrap (read-u8 buffer 3)))
           (eit-last-section-number (unwrap (read-u8 buffer 4)))
           (eit-transport-stream-id (unwrap (read-u16be buffer 5)))
           (eit-original-network-id (unwrap (read-u16be buffer 7)))
           (eit-segment-last-section-number (unwrap (read-u8 buffer 9)))
           (eit-last-table-id (unwrap (read-u8 buffer 10)))
           (eit-event-id (unwrap (read-u16be buffer 11)))
           (eit-duration (unwrap (read-u24be buffer 18)))
           (eit-descriptors-loop-length (unwrap (read-u16be buffer 21)))
           )

      (ok (list
        (cons 'eit-service-id (list (cons 'raw eit-service-id) (cons 'formatted (fmt-hex eit-service-id))))
        (cons 'eit-reserved (list (cons 'raw eit-reserved) (cons 'formatted (fmt-hex eit-reserved))))
        (cons 'eit-version-number (list (cons 'raw eit-version-number) (cons 'formatted (fmt-hex eit-version-number))))
        (cons 'eit-current-next-indicator (list (cons 'raw eit-current-next-indicator) (cons 'formatted (if (= eit-current-next-indicator 0) "False" "True"))))
        (cons 'eit-section-number (list (cons 'raw eit-section-number) (cons 'formatted (number->string eit-section-number))))
        (cons 'eit-last-section-number (list (cons 'raw eit-last-section-number) (cons 'formatted (number->string eit-last-section-number))))
        (cons 'eit-transport-stream-id (list (cons 'raw eit-transport-stream-id) (cons 'formatted (fmt-hex eit-transport-stream-id))))
        (cons 'eit-original-network-id (list (cons 'raw eit-original-network-id) (cons 'formatted (fmt-hex eit-original-network-id))))
        (cons 'eit-segment-last-section-number (list (cons 'raw eit-segment-last-section-number) (cons 'formatted (number->string eit-segment-last-section-number))))
        (cons 'eit-last-table-id (list (cons 'raw eit-last-table-id) (cons 'formatted (fmt-hex eit-last-table-id))))
        (cons 'eit-event-id (list (cons 'raw eit-event-id) (cons 'formatted (fmt-hex eit-event-id))))
        (cons 'eit-duration (list (cons 'raw eit-duration) (cons 'formatted (fmt-hex eit-duration))))
        (cons 'eit-descriptors-loop-length (list (cons 'raw eit-descriptors-loop-length) (cons 'formatted (number->string eit-descriptors-loop-length))))
        )))

    (catch (e)
      (err (str "DVB-EIT parse error: " e)))))

;; dissect-dvb-eit: parse DVB-EIT from bytevector
;; Returns (ok fields-alist) or (err message)