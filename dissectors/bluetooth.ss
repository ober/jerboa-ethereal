;; packet-bluetooth.c
;; Routines for the Bluetooth
;;
;; Copyright 2014, Michal Labedzki for Tieto Corporation
;;
;; Dissector for Bluetooth High Speed over wireless
;; Copyright 2012 intel Corp.
;; Written by Andrei Emeltchenko at intel dot com
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bluetooth.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bluetooth.c

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
(def (dissect-bluetooth buffer)
  "Bluetooth"
  (try
    (let* (
           (dst (unwrap (slice buffer 0 6)))
           (dst-str (unwrap (slice buffer 0 1)))
           (src (unwrap (slice buffer 0 6)))
           (addr (unwrap (slice buffer 0 6)))
           (src-str (unwrap (slice buffer 0 1)))
           (addr-str (unwrap (slice buffer 0 1)))
           (apple-ibeacon-type (unwrap (read-u8 buffer 0)))
           (alt-beacon-code (unwrap (read-u16be buffer 0)))
           (gaen-rpi128 (unwrap (slice buffer 0 16)))
           (apple-ibeacon-length (unwrap (read-u8 buffer 1)))
           (apple-ibeacon-uuid128 (unwrap (slice buffer 2 16)))
           (alt-beacon-id (unwrap (slice buffer 2 20)))
           (gaen-aemd32 (unwrap (slice buffer 16 4)))
           (apple-ibeacon-major (unwrap (read-u16be buffer 18)))
           (apple-ibeacon-minor (unwrap (read-u16be buffer 20)))
           (matter-version (unwrap (read-u16be buffer 21)))
           (matter-discriminator (unwrap (read-u16be buffer 21)))
           (alt-beacon-reference-rssi (unwrap (read-u8 buffer 22)))
           (alt-beacon-manufacturer-data (unwrap (read-u8 buffer 23)))
           (matter-vendor-id (unwrap (read-u16be buffer 23)))
           (matter-product-id (unwrap (read-u16be buffer 25)))
           (matter-flags (unwrap (read-u8 buffer 27)))
           (matter-flags-additional-data (extract-bits matter-flags 0x1 0))
           (matter-flags-ext-announcement (extract-bits matter-flags 0x2 1))
           )

      (ok (list
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (fmt-mac dst))))
        (cons 'dst-str (list (cons 'raw dst-str) (cons 'formatted (utf8->string dst-str))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (fmt-mac src))))
        (cons 'addr (list (cons 'raw addr) (cons 'formatted (fmt-mac addr))))
        (cons 'src-str (list (cons 'raw src-str) (cons 'formatted (utf8->string src-str))))
        (cons 'addr-str (list (cons 'raw addr-str) (cons 'formatted (utf8->string addr-str))))
        (cons 'apple-ibeacon-type (list (cons 'raw apple-ibeacon-type) (cons 'formatted (number->string apple-ibeacon-type))))
        (cons 'alt-beacon-code (list (cons 'raw alt-beacon-code) (cons 'formatted (fmt-hex alt-beacon-code))))
        (cons 'gaen-rpi128 (list (cons 'raw gaen-rpi128) (cons 'formatted (fmt-bytes gaen-rpi128))))
        (cons 'apple-ibeacon-length (list (cons 'raw apple-ibeacon-length) (cons 'formatted (number->string apple-ibeacon-length))))
        (cons 'apple-ibeacon-uuid128 (list (cons 'raw apple-ibeacon-uuid128) (cons 'formatted (fmt-bytes apple-ibeacon-uuid128))))
        (cons 'alt-beacon-id (list (cons 'raw alt-beacon-id) (cons 'formatted (fmt-bytes alt-beacon-id))))
        (cons 'gaen-aemd32 (list (cons 'raw gaen-aemd32) (cons 'formatted (fmt-bytes gaen-aemd32))))
        (cons 'apple-ibeacon-major (list (cons 'raw apple-ibeacon-major) (cons 'formatted (number->string apple-ibeacon-major))))
        (cons 'apple-ibeacon-minor (list (cons 'raw apple-ibeacon-minor) (cons 'formatted (number->string apple-ibeacon-minor))))
        (cons 'matter-version (list (cons 'raw matter-version) (cons 'formatted (number->string matter-version))))
        (cons 'matter-discriminator (list (cons 'raw matter-discriminator) (cons 'formatted (fmt-hex matter-discriminator))))
        (cons 'alt-beacon-reference-rssi (list (cons 'raw alt-beacon-reference-rssi) (cons 'formatted (number->string alt-beacon-reference-rssi))))
        (cons 'alt-beacon-manufacturer-data (list (cons 'raw alt-beacon-manufacturer-data) (cons 'formatted (fmt-hex alt-beacon-manufacturer-data))))
        (cons 'matter-vendor-id (list (cons 'raw matter-vendor-id) (cons 'formatted (fmt-hex matter-vendor-id))))
        (cons 'matter-product-id (list (cons 'raw matter-product-id) (cons 'formatted (fmt-hex matter-product-id))))
        (cons 'matter-flags (list (cons 'raw matter-flags) (cons 'formatted (fmt-hex matter-flags))))
        (cons 'matter-flags-additional-data (list (cons 'raw matter-flags-additional-data) (cons 'formatted (if (= matter-flags-additional-data 0) "Not set" "Set"))))
        (cons 'matter-flags-ext-announcement (list (cons 'raw matter-flags-ext-announcement) (cons 'formatted (if (= matter-flags-ext-announcement 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "BLUETOOTH parse error: " e)))))

;; dissect-bluetooth: parse BLUETOOTH from bytevector
;; Returns (ok fields-alist) or (err message)