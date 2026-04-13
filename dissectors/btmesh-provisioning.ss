;; packet-btmesh-provisioning.c
;; Routines for Bluetooth mesh Provisioning PDU dissection
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

;; jerboa-ethereal/dissectors/btmesh-provisioning.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btmesh_provisioning.c

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
(def (dissect-btmesh-provisioning buffer)
  "Bluetooth Mesh Provisioning PDU"
  (try
    (let* (
           (provisioning-pdu-padding (unwrap (read-u8 buffer 0)))
           (provisioning-attention-duration (unwrap (read-u8 buffer 1)))
           (provisioning-number-of-elements (unwrap (read-u8 buffer 2)))
           (provisioning-algorithms (unwrap (read-u16be buffer 3)))
           (provisioning-algorithms-p256 (unwrap (read-u8 buffer 3)))
           (provisioning-algorithms-rfu (unwrap (read-u16be buffer 3)))
           (provisioning-public-key-type (unwrap (read-u8 buffer 5)))
           (provisioning-public-key-type-oob (unwrap (read-u8 buffer 5)))
           (provisioning-public-key-type-rfu (unwrap (read-u8 buffer 5)))
           (provisioning-static-oob-type (unwrap (read-u8 buffer 6)))
           (provisioning-static-oob-type-static-oob-available (unwrap (read-u8 buffer 6)))
           (provisioning-static-oob-type-rfu (unwrap (read-u8 buffer 6)))
           (provisioning-output-oob-action (unwrap (read-u16be buffer 8)))
           (provisioning-output-oob-action-blink (unwrap (read-u8 buffer 8)))
           (provisioning-output-oob-action-beep (unwrap (read-u8 buffer 8)))
           (provisioning-output-oob-action-vibrate (unwrap (read-u8 buffer 8)))
           (provisioning-output-oob-action-output-numeric (unwrap (read-u8 buffer 8)))
           (provisioning-output-oob-action-output-alphanumeric (unwrap (read-u8 buffer 8)))
           (provisioning-output-oob-action-output-rfu (unwrap (read-u16be buffer 8)))
           (provisioning-input-oob-action (unwrap (read-u16be buffer 11)))
           (provisioning-input-oob-action-push (unwrap (read-u8 buffer 11)))
           (provisioning-input-oob-action-twist (unwrap (read-u8 buffer 11)))
           (provisioning-input-oob-action-input-numeric (unwrap (read-u8 buffer 11)))
           (provisioning-input-oob-action-input-alphanumeric (unwrap (read-u8 buffer 11)))
           (provisioning-input-oob-action-rfu (unwrap (read-u16be buffer 11)))
           (provisioning-public-key-x (unwrap (slice buffer 24 32)))
           (provisioning-public-key-y (unwrap (slice buffer 56 32)))
           (provisioning-confirmation (unwrap (slice buffer 88 16)))
           (provisioning-random (unwrap (slice buffer 104 16)))
           (provisioning-encrypted-provisioning-data (unwrap (slice buffer 120 25)))
           (provisioning-decrypted-provisioning-data-mic (unwrap (slice buffer 145 8)))
           (provisioning-unknown-data (unwrap (slice buffer 154 1)))
           )

      (ok (list
        (cons 'provisioning-pdu-padding (list (cons 'raw provisioning-pdu-padding) (cons 'formatted (number->string provisioning-pdu-padding))))
        (cons 'provisioning-attention-duration (list (cons 'raw provisioning-attention-duration) (cons 'formatted (number->string provisioning-attention-duration))))
        (cons 'provisioning-number-of-elements (list (cons 'raw provisioning-number-of-elements) (cons 'formatted (number->string provisioning-number-of-elements))))
        (cons 'provisioning-algorithms (list (cons 'raw provisioning-algorithms) (cons 'formatted (fmt-hex provisioning-algorithms))))
        (cons 'provisioning-algorithms-p256 (list (cons 'raw provisioning-algorithms-p256) (cons 'formatted (if (= provisioning-algorithms-p256 0) "False" "True"))))
        (cons 'provisioning-algorithms-rfu (list (cons 'raw provisioning-algorithms-rfu) (cons 'formatted (number->string provisioning-algorithms-rfu))))
        (cons 'provisioning-public-key-type (list (cons 'raw provisioning-public-key-type) (cons 'formatted (fmt-hex provisioning-public-key-type))))
        (cons 'provisioning-public-key-type-oob (list (cons 'raw provisioning-public-key-type-oob) (cons 'formatted (if (= provisioning-public-key-type-oob 0) "False" "True"))))
        (cons 'provisioning-public-key-type-rfu (list (cons 'raw provisioning-public-key-type-rfu) (cons 'formatted (number->string provisioning-public-key-type-rfu))))
        (cons 'provisioning-static-oob-type (list (cons 'raw provisioning-static-oob-type) (cons 'formatted (fmt-hex provisioning-static-oob-type))))
        (cons 'provisioning-static-oob-type-static-oob-available (list (cons 'raw provisioning-static-oob-type-static-oob-available) (cons 'formatted (if (= provisioning-static-oob-type-static-oob-available 0) "False" "True"))))
        (cons 'provisioning-static-oob-type-rfu (list (cons 'raw provisioning-static-oob-type-rfu) (cons 'formatted (number->string provisioning-static-oob-type-rfu))))
        (cons 'provisioning-output-oob-action (list (cons 'raw provisioning-output-oob-action) (cons 'formatted (fmt-hex provisioning-output-oob-action))))
        (cons 'provisioning-output-oob-action-blink (list (cons 'raw provisioning-output-oob-action-blink) (cons 'formatted (if (= provisioning-output-oob-action-blink 0) "False" "True"))))
        (cons 'provisioning-output-oob-action-beep (list (cons 'raw provisioning-output-oob-action-beep) (cons 'formatted (if (= provisioning-output-oob-action-beep 0) "False" "True"))))
        (cons 'provisioning-output-oob-action-vibrate (list (cons 'raw provisioning-output-oob-action-vibrate) (cons 'formatted (if (= provisioning-output-oob-action-vibrate 0) "False" "True"))))
        (cons 'provisioning-output-oob-action-output-numeric (list (cons 'raw provisioning-output-oob-action-output-numeric) (cons 'formatted (if (= provisioning-output-oob-action-output-numeric 0) "False" "True"))))
        (cons 'provisioning-output-oob-action-output-alphanumeric (list (cons 'raw provisioning-output-oob-action-output-alphanumeric) (cons 'formatted (if (= provisioning-output-oob-action-output-alphanumeric 0) "False" "True"))))
        (cons 'provisioning-output-oob-action-output-rfu (list (cons 'raw provisioning-output-oob-action-output-rfu) (cons 'formatted (number->string provisioning-output-oob-action-output-rfu))))
        (cons 'provisioning-input-oob-action (list (cons 'raw provisioning-input-oob-action) (cons 'formatted (fmt-hex provisioning-input-oob-action))))
        (cons 'provisioning-input-oob-action-push (list (cons 'raw provisioning-input-oob-action-push) (cons 'formatted (if (= provisioning-input-oob-action-push 0) "False" "True"))))
        (cons 'provisioning-input-oob-action-twist (list (cons 'raw provisioning-input-oob-action-twist) (cons 'formatted (if (= provisioning-input-oob-action-twist 0) "False" "True"))))
        (cons 'provisioning-input-oob-action-input-numeric (list (cons 'raw provisioning-input-oob-action-input-numeric) (cons 'formatted (if (= provisioning-input-oob-action-input-numeric 0) "False" "True"))))
        (cons 'provisioning-input-oob-action-input-alphanumeric (list (cons 'raw provisioning-input-oob-action-input-alphanumeric) (cons 'formatted (if (= provisioning-input-oob-action-input-alphanumeric 0) "False" "True"))))
        (cons 'provisioning-input-oob-action-rfu (list (cons 'raw provisioning-input-oob-action-rfu) (cons 'formatted (number->string provisioning-input-oob-action-rfu))))
        (cons 'provisioning-public-key-x (list (cons 'raw provisioning-public-key-x) (cons 'formatted (fmt-bytes provisioning-public-key-x))))
        (cons 'provisioning-public-key-y (list (cons 'raw provisioning-public-key-y) (cons 'formatted (fmt-bytes provisioning-public-key-y))))
        (cons 'provisioning-confirmation (list (cons 'raw provisioning-confirmation) (cons 'formatted (fmt-bytes provisioning-confirmation))))
        (cons 'provisioning-random (list (cons 'raw provisioning-random) (cons 'formatted (fmt-bytes provisioning-random))))
        (cons 'provisioning-encrypted-provisioning-data (list (cons 'raw provisioning-encrypted-provisioning-data) (cons 'formatted (fmt-bytes provisioning-encrypted-provisioning-data))))
        (cons 'provisioning-decrypted-provisioning-data-mic (list (cons 'raw provisioning-decrypted-provisioning-data-mic) (cons 'formatted (fmt-bytes provisioning-decrypted-provisioning-data-mic))))
        (cons 'provisioning-unknown-data (list (cons 'raw provisioning-unknown-data) (cons 'formatted (fmt-bytes provisioning-unknown-data))))
        )))

    (catch (e)
      (err (str "BTMESH-PROVISIONING parse error: " e)))))

;; dissect-btmesh-provisioning: parse BTMESH-PROVISIONING from bytevector
;; Returns (ok fields-alist) or (err message)