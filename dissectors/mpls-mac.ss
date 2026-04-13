;; packet-mpls-mac.c
;;
;; Routines for MPLS Media Access Control (MAC) Address Withdrawal over Static Pseudowire.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mpls-mac.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mpls_mac.c

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
(def (dissect-mpls-mac buffer)
  "Media Access Control (MAC) Address Withdrawal over Static Pseudowire"
  (try
    (let* (
           (mac-tlv-length-total (unwrap (read-u8 buffer 2)))
           (mac-flags (unwrap (read-u8 buffer 3)))
           (mac-flags-a (extract-bits mac-flags 0x80 7))
           (mac-flags-r (extract-bits mac-flags 0x40 6))
           (mac-flags-reserved (extract-bits mac-flags 0x3F 0))
           (mac-tlv-res (unwrap (read-u16be buffer 4)))
           (mac-tlv-type (unwrap (read-u16be buffer 4)))
           (mac-tlv-length (unwrap (read-u16be buffer 6)))
           (mac-tlv-value (unwrap (slice buffer 8 1)))
           (mac-tlv-sequence-number (unwrap (read-u32be buffer 8)))
           (mac-reserved (unwrap (slice buffer 12 2)))
           )

      (ok (list
        (cons 'mac-tlv-length-total (list (cons 'raw mac-tlv-length-total) (cons 'formatted (number->string mac-tlv-length-total))))
        (cons 'mac-flags (list (cons 'raw mac-flags) (cons 'formatted (fmt-hex mac-flags))))
        (cons 'mac-flags-a (list (cons 'raw mac-flags-a) (cons 'formatted (if (= mac-flags-a 0) "Not set" "Set"))))
        (cons 'mac-flags-r (list (cons 'raw mac-flags-r) (cons 'formatted (if (= mac-flags-r 0) "Not set" "Set"))))
        (cons 'mac-flags-reserved (list (cons 'raw mac-flags-reserved) (cons 'formatted (if (= mac-flags-reserved 0) "Not set" "Set"))))
        (cons 'mac-tlv-res (list (cons 'raw mac-tlv-res) (cons 'formatted (fmt-hex mac-tlv-res))))
        (cons 'mac-tlv-type (list (cons 'raw mac-tlv-type) (cons 'formatted (fmt-hex mac-tlv-type))))
        (cons 'mac-tlv-length (list (cons 'raw mac-tlv-length) (cons 'formatted (number->string mac-tlv-length))))
        (cons 'mac-tlv-value (list (cons 'raw mac-tlv-value) (cons 'formatted (fmt-bytes mac-tlv-value))))
        (cons 'mac-tlv-sequence-number (list (cons 'raw mac-tlv-sequence-number) (cons 'formatted (number->string mac-tlv-sequence-number))))
        (cons 'mac-reserved (list (cons 'raw mac-reserved) (cons 'formatted (fmt-bytes mac-reserved))))
        )))

    (catch (e)
      (err (str "MPLS-MAC parse error: " e)))))

;; dissect-mpls-mac: parse MPLS-MAC from bytevector
;; Returns (ok fields-alist) or (err message)