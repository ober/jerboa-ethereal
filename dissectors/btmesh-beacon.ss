;; packet-btmesh-beacon.c
;; Routines for Bluetooth mesh PB-ADV dissection
;;
;; Copyright 2019, Piotr Winiarczyk <wino45@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Ref: Mesh Profile v1.0
;; https://www.bluetooth.com/specifications/mesh-specifications
;;

;; jerboa-ethereal/dissectors/btmesh-beacon.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btmesh_beacon.c

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
(def (dissect-btmesh-beacon buffer)
  "Bluetooth Mesh Beacon"
  (try
    (let* (
           (beacon-uuid (unwrap (slice buffer 1 16)))
           (beacon-oob (unwrap (read-u16be buffer 17)))
           (beacon-oob-other (unwrap (read-u8 buffer 17)))
           (beacon-oob-electronic (unwrap (read-u8 buffer 17)))
           (beacon-oob-2d-code (unwrap (read-u8 buffer 17)))
           (beacon-oob-bar-code (unwrap (read-u8 buffer 17)))
           (beacon-oob-nfc (unwrap (read-u8 buffer 17)))
           (beacon-oob-number (unwrap (read-u8 buffer 17)))
           (beacon-oob-string (unwrap (read-u8 buffer 17)))
           (beacon-oob-rfu (unwrap (read-u16be buffer 17)))
           (beacon-oob-on-box (unwrap (read-u8 buffer 17)))
           (beacon-oob-inside-box (unwrap (read-u8 buffer 17)))
           (beacon-oob-on-paper (unwrap (read-u8 buffer 17)))
           (beacon-oob-inside-manual (unwrap (read-u8 buffer 17)))
           (beacon-oob-on-device (unwrap (read-u8 buffer 17)))
           (beacon-uri-hash (unwrap (slice buffer 19 4)))
           (beacon-flags (unwrap (read-u8 buffer 23)))
           (beacon-flags-key-refresh (unwrap (read-u8 buffer 23)))
           (beacon-flags-iv-update (unwrap (read-u8 buffer 23)))
           (beacon-flags-rfu (unwrap (read-u8 buffer 23)))
           (beacon-network-id (unwrap (slice buffer 24 8)))
           (beacon-ivindex (unwrap (read-u32be buffer 32)))
           (beacon-authentication-value (unwrap (slice buffer 36 8)))
           (beacon-unknown-data (unwrap (slice buffer 44 1)))
           )

      (ok (list
        (cons 'beacon-uuid (list (cons 'raw beacon-uuid) (cons 'formatted (fmt-bytes beacon-uuid))))
        (cons 'beacon-oob (list (cons 'raw beacon-oob) (cons 'formatted (fmt-hex beacon-oob))))
        (cons 'beacon-oob-other (list (cons 'raw beacon-oob-other) (cons 'formatted (if (= beacon-oob-other 0) "False" "True"))))
        (cons 'beacon-oob-electronic (list (cons 'raw beacon-oob-electronic) (cons 'formatted (if (= beacon-oob-electronic 0) "False" "True"))))
        (cons 'beacon-oob-2d-code (list (cons 'raw beacon-oob-2d-code) (cons 'formatted (if (= beacon-oob-2d-code 0) "False" "True"))))
        (cons 'beacon-oob-bar-code (list (cons 'raw beacon-oob-bar-code) (cons 'formatted (if (= beacon-oob-bar-code 0) "False" "True"))))
        (cons 'beacon-oob-nfc (list (cons 'raw beacon-oob-nfc) (cons 'formatted (if (= beacon-oob-nfc 0) "False" "True"))))
        (cons 'beacon-oob-number (list (cons 'raw beacon-oob-number) (cons 'formatted (if (= beacon-oob-number 0) "False" "True"))))
        (cons 'beacon-oob-string (list (cons 'raw beacon-oob-string) (cons 'formatted (if (= beacon-oob-string 0) "False" "True"))))
        (cons 'beacon-oob-rfu (list (cons 'raw beacon-oob-rfu) (cons 'formatted (number->string beacon-oob-rfu))))
        (cons 'beacon-oob-on-box (list (cons 'raw beacon-oob-on-box) (cons 'formatted (if (= beacon-oob-on-box 0) "False" "True"))))
        (cons 'beacon-oob-inside-box (list (cons 'raw beacon-oob-inside-box) (cons 'formatted (if (= beacon-oob-inside-box 0) "False" "True"))))
        (cons 'beacon-oob-on-paper (list (cons 'raw beacon-oob-on-paper) (cons 'formatted (if (= beacon-oob-on-paper 0) "False" "True"))))
        (cons 'beacon-oob-inside-manual (list (cons 'raw beacon-oob-inside-manual) (cons 'formatted (if (= beacon-oob-inside-manual 0) "False" "True"))))
        (cons 'beacon-oob-on-device (list (cons 'raw beacon-oob-on-device) (cons 'formatted (if (= beacon-oob-on-device 0) "False" "True"))))
        (cons 'beacon-uri-hash (list (cons 'raw beacon-uri-hash) (cons 'formatted (fmt-bytes beacon-uri-hash))))
        (cons 'beacon-flags (list (cons 'raw beacon-flags) (cons 'formatted (fmt-hex beacon-flags))))
        (cons 'beacon-flags-key-refresh (list (cons 'raw beacon-flags-key-refresh) (cons 'formatted (if (= beacon-flags-key-refresh 0) "Key Refresh not in progress" "Key Refresh in progress"))))
        (cons 'beacon-flags-iv-update (list (cons 'raw beacon-flags-iv-update) (cons 'formatted (if (= beacon-flags-iv-update 0) "Normal operation" "IV Update active"))))
        (cons 'beacon-flags-rfu (list (cons 'raw beacon-flags-rfu) (cons 'formatted (number->string beacon-flags-rfu))))
        (cons 'beacon-network-id (list (cons 'raw beacon-network-id) (cons 'formatted (fmt-bytes beacon-network-id))))
        (cons 'beacon-ivindex (list (cons 'raw beacon-ivindex) (cons 'formatted (number->string beacon-ivindex))))
        (cons 'beacon-authentication-value (list (cons 'raw beacon-authentication-value) (cons 'formatted (fmt-bytes beacon-authentication-value))))
        (cons 'beacon-unknown-data (list (cons 'raw beacon-unknown-data) (cons 'formatted (fmt-bytes beacon-unknown-data))))
        )))

    (catch (e)
      (err (str "BTMESH-BEACON parse error: " e)))))

;; dissect-btmesh-beacon: parse BTMESH-BEACON from bytevector
;; Returns (ok fields-alist) or (err message)