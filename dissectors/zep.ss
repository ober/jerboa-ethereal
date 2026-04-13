;; packet-zep.c
;; Dissector  routines for the ZigBee Encapsulation Protocol
;; By Owen Kirby <osk@exegin.com>
;; Copyright 2009 Exegin Technologies Limited
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; ------------------------------------------------------------
;;
;; ZEP Packets must be received in the following format:
;; |UDP Header|  ZEP Header |IEEE 802.15.4 Packet|
;; | 8 bytes  | 16/32 bytes |    <= 127 bytes    |
;; ------------------------------------------------------------
;;
;; ZEP v1 Header will have the following format:
;; |Preamble|Version|Channel ID|Device ID|CRC/LQI Mode|LQI Val|Reserved|Length|
;; |2 bytes |1 byte |  1 byte  | 2 bytes |   1 byte   |1 byte |7 bytes |1 byte|
;;
;; ZEP v2 Header will have the following format (if type=1/Data):
;; |Preamble|Version| Type |Channel ID|Device ID|CRC/LQI Mode|LQI Val|NTP Timestamp|Sequence#|Reserved|Length|
;; |2 bytes |1 byte |1 byte|  1 byte  | 2 bytes |   1 byte   |1 byte |   8 bytes   | 4 bytes |10 bytes|1 byte|
;;
;; ZEP v2 Header will have the following format (if type=2/Ack):
;; |Preamble|Version| Type |Sequence#|
;; |2 bytes |1 byte |1 byte| 4 bytes |
;; ------------------------------------------------------------
;;

;; jerboa-ethereal/dissectors/zep.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zep.c

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
(def (dissect-zep buffer)
  "ZigBee Encapsulation Protocol"
  (try
    (let* (
           (protocol-id (unwrap (slice buffer 0 2)))
           (version (unwrap (read-u8 buffer 2)))
           (channel-id (unwrap (read-u8 buffer 3)))
           (seqno (unwrap (read-u32be buffer 4)))
           (device-id (unwrap (read-u16be buffer 4)))
           (lqi-mode (unwrap (read-u8 buffer 6)))
           (reserved-field (unwrap (slice buffer 7 9)))
           (lqi (unwrap (read-u8 buffer 7)))
           )

      (ok (list
        (cons 'protocol-id (list (cons 'raw protocol-id) (cons 'formatted (utf8->string protocol-id))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'channel-id (list (cons 'raw channel-id) (cons 'formatted (number->string channel-id))))
        (cons 'seqno (list (cons 'raw seqno) (cons 'formatted (number->string seqno))))
        (cons 'device-id (list (cons 'raw device-id) (cons 'formatted (number->string device-id))))
        (cons 'lqi-mode (list (cons 'raw lqi-mode) (cons 'formatted (if (= lqi-mode 0) "LQI" "CRC"))))
        (cons 'reserved-field (list (cons 'raw reserved-field) (cons 'formatted (fmt-bytes reserved-field))))
        (cons 'lqi (list (cons 'raw lqi) (cons 'formatted (number->string lqi))))
        )))

    (catch (e)
      (err (str "ZEP parse error: " e)))))

;; dissect-zep: parse ZEP from bytevector
;; Returns (ok fields-alist) or (err message)