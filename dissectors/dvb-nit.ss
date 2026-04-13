;; packet-dvb-nit.c
;; Routines for DVB (ETSI EN 300 468) Network Information Table (NIT) dissection
;; Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dvb-nit.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dvb_nit.c

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
(def (dissect-dvb-nit buffer)
  "DVB Network Information Table"
  (try
    (let* (
           (nit-network-id (unwrap (read-u16be buffer 0)))
           (nit-reserved1 (unwrap (read-u8 buffer 2)))
           (nit-version-number (unwrap (read-u8 buffer 2)))
           (nit-current-next-indicator (unwrap (read-u8 buffer 2)))
           (nit-section-number (unwrap (read-u8 buffer 3)))
           (nit-last-section-number (unwrap (read-u8 buffer 4)))
           (nit-reserved2 (unwrap (read-u16be buffer 5)))
           (nit-network-descriptors-length (unwrap (read-u16be buffer 5)))
           (nit-reserved3 (unwrap (read-u16be buffer 7)))
           (nit-transport-stream-loop-length (unwrap (read-u16be buffer 7)))
           (nit-transport-stream-id (unwrap (read-u16be buffer 9)))
           (nit-original-network-id (unwrap (read-u16be buffer 11)))
           (nit-reserved4 (unwrap (read-u16be buffer 13)))
           (nit-transport-descriptors-length (unwrap (read-u16be buffer 13)))
           )

      (ok (list
        (cons 'nit-network-id (list (cons 'raw nit-network-id) (cons 'formatted (fmt-hex nit-network-id))))
        (cons 'nit-reserved1 (list (cons 'raw nit-reserved1) (cons 'formatted (fmt-hex nit-reserved1))))
        (cons 'nit-version-number (list (cons 'raw nit-version-number) (cons 'formatted (fmt-hex nit-version-number))))
        (cons 'nit-current-next-indicator (list (cons 'raw nit-current-next-indicator) (cons 'formatted (if (= nit-current-next-indicator 0) "False" "True"))))
        (cons 'nit-section-number (list (cons 'raw nit-section-number) (cons 'formatted (number->string nit-section-number))))
        (cons 'nit-last-section-number (list (cons 'raw nit-last-section-number) (cons 'formatted (number->string nit-last-section-number))))
        (cons 'nit-reserved2 (list (cons 'raw nit-reserved2) (cons 'formatted (fmt-hex nit-reserved2))))
        (cons 'nit-network-descriptors-length (list (cons 'raw nit-network-descriptors-length) (cons 'formatted (number->string nit-network-descriptors-length))))
        (cons 'nit-reserved3 (list (cons 'raw nit-reserved3) (cons 'formatted (fmt-hex nit-reserved3))))
        (cons 'nit-transport-stream-loop-length (list (cons 'raw nit-transport-stream-loop-length) (cons 'formatted (number->string nit-transport-stream-loop-length))))
        (cons 'nit-transport-stream-id (list (cons 'raw nit-transport-stream-id) (cons 'formatted (fmt-hex nit-transport-stream-id))))
        (cons 'nit-original-network-id (list (cons 'raw nit-original-network-id) (cons 'formatted (fmt-hex nit-original-network-id))))
        (cons 'nit-reserved4 (list (cons 'raw nit-reserved4) (cons 'formatted (fmt-hex nit-reserved4))))
        (cons 'nit-transport-descriptors-length (list (cons 'raw nit-transport-descriptors-length) (cons 'formatted (number->string nit-transport-descriptors-length))))
        )))

    (catch (e)
      (err (str "DVB-NIT parse error: " e)))))

;; dissect-dvb-nit: parse DVB-NIT from bytevector
;; Returns (ok fields-alist) or (err message)