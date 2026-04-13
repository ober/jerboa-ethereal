;; packet-lwapp.c
;;
;; Routines for LWAPP encapsulated packet disassembly
;; RFC 5412
;;
;; Copyright (c) 2003 by David Frascone <dave@frascone.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lwapp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lwapp.c
;; RFC 5412

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
(def (dissect-lwapp buffer)
  "LWAPP Encapsulated Packet"
  (try
    (let* (
           (control-mac (unwrap (slice buffer 0 6)))
           (version (unwrap (read-u8 buffer 6)))
           (slotid (unwrap (read-u24be buffer 6)))
           (flags (unwrap (read-u8 buffer 6)))
           (flags-type (extract-bits flags 0x0 0))
           (flags-fragment (extract-bits flags 0x0 0))
           (flags-fragment-type (extract-bits flags 0x0 0))
           (fragment-id (unwrap (read-u8 buffer 6)))
           (length (unwrap (read-u16be buffer 6)))
           (rssi (unwrap (read-u8 buffer 8)))
           (snr (unwrap (read-u8 buffer 8)))
           )

      (ok (list
        (cons 'control-mac (list (cons 'raw control-mac) (cons 'formatted (fmt-mac control-mac))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'slotid (list (cons 'raw slotid) (cons 'formatted (number->string slotid))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-type (list (cons 'raw flags-type) (cons 'formatted (if (= flags-type 0) "Encapsulated 80211" "LWAPP Control Packet"))))
        (cons 'flags-fragment (list (cons 'raw flags-fragment) (cons 'formatted (if (= flags-fragment 0) "Not set" "Set"))))
        (cons 'flags-fragment-type (list (cons 'raw flags-fragment-type) (cons 'formatted (if (= flags-fragment-type 0) "Not set" "Set"))))
        (cons 'fragment-id (list (cons 'raw fragment-id) (cons 'formatted (fmt-hex fragment-id))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'rssi (list (cons 'raw rssi) (cons 'formatted (fmt-hex rssi))))
        (cons 'snr (list (cons 'raw snr) (cons 'formatted (fmt-hex snr))))
        )))

    (catch (e)
      (err (str "LWAPP parse error: " e)))))

;; dissect-lwapp: parse LWAPP from bytevector
;; Returns (ok fields-alist) or (err message)