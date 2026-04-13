;; packet-vxlan.c
;;
;; Routines for Virtual eXtensible Local Area Network (VXLAN) packet dissection
;; RFC 7348 plus draft-smith-vxlan-group-policy-01
;;
;; (c) Copyright 2016, Sumit Kumar Jha <sjha3@ncsu.edu>
;; Support for VXLAN GPE (https://datatracker.ietf.org/doc/html/draft-ietf-nvo3-vxlan-gpe-02)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vxlan.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vxlan.c
;; RFC 7348

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
(def (dissect-vxlan buffer)
  "Virtual eXtensible Local Area Network"
  (try
    (let* (
           (gpe-flags (unwrap (read-u8 buffer 0)))
           (gpe-flag-ver (extract-bits gpe-flags 0x30 4))
           (gpe-flag-i (extract-bits gpe-flags 0x8 3))
           (gpe-flag-p (extract-bits gpe-flags 0x4 2))
           (gpe-flag-o (extract-bits gpe-flags 0x1 0))
           (gpe-flag-reserved (extract-bits gpe-flags 0xC2 1))
           (gpe-reserved-16 (unwrap (read-u16be buffer 1)))
           (flags (unwrap (read-u16be buffer 4)))
           (flag-g (extract-bits flags 0x8000 15))
           (flag-i (extract-bits flags 0x800 11))
           (flag-d (extract-bits flags 0x40 6))
           (flag-a (extract-bits flags 0x8 3))
           (flags-reserved (extract-bits flags 0x77B7 0))
           (gbp (unwrap (read-u16be buffer 6)))
           (vni (unwrap (read-u24be buffer 8)))
           (reserved-8 (unwrap (read-u8 buffer 11)))
           )

      (ok (list
        (cons 'gpe-flags (list (cons 'raw gpe-flags) (cons 'formatted (fmt-hex gpe-flags))))
        (cons 'gpe-flag-ver (list (cons 'raw gpe-flag-ver) (cons 'formatted (if (= gpe-flag-ver 0) "Not set" "Set"))))
        (cons 'gpe-flag-i (list (cons 'raw gpe-flag-i) (cons 'formatted (if (= gpe-flag-i 0) "Not set" "Set"))))
        (cons 'gpe-flag-p (list (cons 'raw gpe-flag-p) (cons 'formatted (if (= gpe-flag-p 0) "Not set" "Set"))))
        (cons 'gpe-flag-o (list (cons 'raw gpe-flag-o) (cons 'formatted (if (= gpe-flag-o 0) "Not set" "Set"))))
        (cons 'gpe-flag-reserved (list (cons 'raw gpe-flag-reserved) (cons 'formatted (if (= gpe-flag-reserved 0) "Not set" "Set"))))
        (cons 'gpe-reserved-16 (list (cons 'raw gpe-reserved-16) (cons 'formatted (number->string gpe-reserved-16))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flag-g (list (cons 'raw flag-g) (cons 'formatted (if (= flag-g 0) "Not set" "Set"))))
        (cons 'flag-i (list (cons 'raw flag-i) (cons 'formatted (if (= flag-i 0) "Not set" "Set"))))
        (cons 'flag-d (list (cons 'raw flag-d) (cons 'formatted (if (= flag-d 0) "Not set" "Set"))))
        (cons 'flag-a (list (cons 'raw flag-a) (cons 'formatted (if (= flag-a 0) "Not set" "Set"))))
        (cons 'flags-reserved (list (cons 'raw flags-reserved) (cons 'formatted (if (= flags-reserved 0) "Not set" "Set"))))
        (cons 'gbp (list (cons 'raw gbp) (cons 'formatted (number->string gbp))))
        (cons 'vni (list (cons 'raw vni) (cons 'formatted (number->string vni))))
        (cons 'reserved-8 (list (cons 'raw reserved-8) (cons 'formatted (number->string reserved-8))))
        )))

    (catch (e)
      (err (str "VXLAN parse error: " e)))))

;; dissect-vxlan: parse VXLAN from bytevector
;; Returns (ok fields-alist) or (err message)