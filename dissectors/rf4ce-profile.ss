;; packet-rf4ce-profile.c
;; Profile layer related functions and objects for RF4CE dissector
;; Copyright (C) Atmosic 2023
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rf4ce-profile.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rf4ce_profile.c

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
(def (dissect-rf4ce-profile buffer)
  "RF4CE Profile"
  (try
    (let* (
           (profile-fcf (unwrap (read-u8 buffer 1)))
           (profile-fcf-reserved (extract-bits profile-fcf 0x0 0))
           (profile-fcf-data-pending (extract-bits profile-fcf 0x0 0))
           (zrc10-fcf (unwrap (read-u8 buffer 2)))
           (zrc10-fcf-reserved (extract-bits zrc10-fcf 0x0 0))
           )

      (ok (list
        (cons 'profile-fcf (list (cons 'raw profile-fcf) (cons 'formatted (fmt-hex profile-fcf))))
        (cons 'profile-fcf-reserved (list (cons 'raw profile-fcf-reserved) (cons 'formatted (if (= profile-fcf-reserved 0) "Not set" "Set"))))
        (cons 'profile-fcf-data-pending (list (cons 'raw profile-fcf-data-pending) (cons 'formatted (if (= profile-fcf-data-pending 0) "Not set" "Set"))))
        (cons 'zrc10-fcf (list (cons 'raw zrc10-fcf) (cons 'formatted (fmt-hex zrc10-fcf))))
        (cons 'zrc10-fcf-reserved (list (cons 'raw zrc10-fcf-reserved) (cons 'formatted (if (= zrc10-fcf-reserved 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "RF4CE-PROFILE parse error: " e)))))

;; dissect-rf4ce-profile: parse RF4CE-PROFILE from bytevector
;; Returns (ok fields-alist) or (err message)