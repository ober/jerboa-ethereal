;; packet-dvb-sdt.c
;; Routines for DVB (ETSI EN 300 468) Servide Description Table (SDT) dissection
;; Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dvb-sdt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dvb_sdt.c

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
(def (dissect-dvb-sdt buffer)
  "DVB Service Description Table"
  (try
    (let* (
           (sdt-reserved1 (unwrap (read-u8 buffer 2)))
           (sdt-version-number (unwrap (read-u8 buffer 2)))
           (sdt-current-next-indicator (unwrap (read-u8 buffer 2)))
           (sdt-section-number (unwrap (read-u8 buffer 3)))
           (sdt-last-section-number (unwrap (read-u8 buffer 4)))
           (sdt-original-network-id (unwrap (read-u16be buffer 5)))
           (sdt-reserved2 (unwrap (read-u8 buffer 7)))
           (sdt-service-id (unwrap (read-u16be buffer 8)))
           (sdt-reserved3 (unwrap (read-u8 buffer 10)))
           (sdt-eit-schedule-flag (unwrap (read-u8 buffer 10)))
           (sdt-eit-present-following-flag (unwrap (read-u8 buffer 10)))
           (sdt-descriptors-loop-length (unwrap (read-u16be buffer 11)))
           (sdt-transport-stream-id (unwrap (read-u16be buffer 13)))
           )

      (ok (list
        (cons 'sdt-reserved1 (list (cons 'raw sdt-reserved1) (cons 'formatted (fmt-hex sdt-reserved1))))
        (cons 'sdt-version-number (list (cons 'raw sdt-version-number) (cons 'formatted (fmt-hex sdt-version-number))))
        (cons 'sdt-current-next-indicator (list (cons 'raw sdt-current-next-indicator) (cons 'formatted (if (= sdt-current-next-indicator 0) "False" "True"))))
        (cons 'sdt-section-number (list (cons 'raw sdt-section-number) (cons 'formatted (number->string sdt-section-number))))
        (cons 'sdt-last-section-number (list (cons 'raw sdt-last-section-number) (cons 'formatted (number->string sdt-last-section-number))))
        (cons 'sdt-original-network-id (list (cons 'raw sdt-original-network-id) (cons 'formatted (fmt-hex sdt-original-network-id))))
        (cons 'sdt-reserved2 (list (cons 'raw sdt-reserved2) (cons 'formatted (fmt-hex sdt-reserved2))))
        (cons 'sdt-service-id (list (cons 'raw sdt-service-id) (cons 'formatted (fmt-hex sdt-service-id))))
        (cons 'sdt-reserved3 (list (cons 'raw sdt-reserved3) (cons 'formatted (fmt-hex sdt-reserved3))))
        (cons 'sdt-eit-schedule-flag (list (cons 'raw sdt-eit-schedule-flag) (cons 'formatted (number->string sdt-eit-schedule-flag))))
        (cons 'sdt-eit-present-following-flag (list (cons 'raw sdt-eit-present-following-flag) (cons 'formatted (number->string sdt-eit-present-following-flag))))
        (cons 'sdt-descriptors-loop-length (list (cons 'raw sdt-descriptors-loop-length) (cons 'formatted (number->string sdt-descriptors-loop-length))))
        (cons 'sdt-transport-stream-id (list (cons 'raw sdt-transport-stream-id) (cons 'formatted (fmt-hex sdt-transport-stream-id))))
        )))

    (catch (e)
      (err (str "DVB-SDT parse error: " e)))))

;; dissect-dvb-sdt: parse DVB-SDT from bytevector
;; Returns (ok fields-alist) or (err message)