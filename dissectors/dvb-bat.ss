;; packet-dvb-bat.c
;; Routines for DVB (ETSI EN 300 468) Bouquet Association Table (BAT) dissection
;; Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dvb-bat.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dvb_bat.c

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
(def (dissect-dvb-bat buffer)
  "DVB Bouquet Association Table"
  (try
    (let* (
           (bat-bouquet-id (unwrap (read-u16be buffer 0)))
           (bat-reserved1 (unwrap (read-u8 buffer 2)))
           (bat-version-number (unwrap (read-u8 buffer 2)))
           (bat-current-next-indicator (unwrap (read-u8 buffer 2)))
           (bat-section-number (unwrap (read-u8 buffer 3)))
           (bat-last-section-number (unwrap (read-u8 buffer 4)))
           (bat-reserved2 (unwrap (read-u16be buffer 5)))
           (bat-bouquet-descriptors-length (unwrap (read-u16be buffer 5)))
           (bat-reserved3 (unwrap (read-u16be buffer 7)))
           (bat-transport-stream-loop-length (unwrap (read-u16be buffer 7)))
           (bat-transport-stream-id (unwrap (read-u16be buffer 9)))
           (bat-original-network-id (unwrap (read-u16be buffer 11)))
           (bat-reserved4 (unwrap (read-u16be buffer 13)))
           (bat-transport-descriptors-length (unwrap (read-u16be buffer 13)))
           )

      (ok (list
        (cons 'bat-bouquet-id (list (cons 'raw bat-bouquet-id) (cons 'formatted (fmt-hex bat-bouquet-id))))
        (cons 'bat-reserved1 (list (cons 'raw bat-reserved1) (cons 'formatted (fmt-hex bat-reserved1))))
        (cons 'bat-version-number (list (cons 'raw bat-version-number) (cons 'formatted (fmt-hex bat-version-number))))
        (cons 'bat-current-next-indicator (list (cons 'raw bat-current-next-indicator) (cons 'formatted (if (= bat-current-next-indicator 0) "False" "True"))))
        (cons 'bat-section-number (list (cons 'raw bat-section-number) (cons 'formatted (number->string bat-section-number))))
        (cons 'bat-last-section-number (list (cons 'raw bat-last-section-number) (cons 'formatted (number->string bat-last-section-number))))
        (cons 'bat-reserved2 (list (cons 'raw bat-reserved2) (cons 'formatted (fmt-hex bat-reserved2))))
        (cons 'bat-bouquet-descriptors-length (list (cons 'raw bat-bouquet-descriptors-length) (cons 'formatted (number->string bat-bouquet-descriptors-length))))
        (cons 'bat-reserved3 (list (cons 'raw bat-reserved3) (cons 'formatted (fmt-hex bat-reserved3))))
        (cons 'bat-transport-stream-loop-length (list (cons 'raw bat-transport-stream-loop-length) (cons 'formatted (number->string bat-transport-stream-loop-length))))
        (cons 'bat-transport-stream-id (list (cons 'raw bat-transport-stream-id) (cons 'formatted (fmt-hex bat-transport-stream-id))))
        (cons 'bat-original-network-id (list (cons 'raw bat-original-network-id) (cons 'formatted (fmt-hex bat-original-network-id))))
        (cons 'bat-reserved4 (list (cons 'raw bat-reserved4) (cons 'formatted (fmt-hex bat-reserved4))))
        (cons 'bat-transport-descriptors-length (list (cons 'raw bat-transport-descriptors-length) (cons 'formatted (number->string bat-transport-descriptors-length))))
        )))

    (catch (e)
      (err (str "DVB-BAT parse error: " e)))))

;; dissect-dvb-bat: parse DVB-BAT from bytevector
;; Returns (ok fields-alist) or (err message)