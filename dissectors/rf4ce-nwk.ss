;; packet-rf4ce-nwk.c
;; Network layer related functions and objects for RF4CE dissector
;; Copyright (C) Atmosic 2023
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rf4ce-nwk.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rf4ce_nwk.c

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
(def (dissect-rf4ce-nwk buffer)
  "RF4CE Network Layer"
  (try
    (let* (
           (nwk-fcf (unwrap (read-u8 buffer 0)))
           (nwk-fcf-security-enabled (extract-bits nwk-fcf 0x0 0))
           (nwk-fcf-protocol-version (extract-bits nwk-fcf 0x0 0))
           (nwk-fcf-reserved (extract-bits nwk-fcf 0x0 0))
           (nwk-seq-num (unwrap (read-u32be buffer 1)))
           (nwk-vendor-id (unwrap (read-u16be buffer 6)))
           (nwk-mic (unwrap (read-u32be buffer 8)))
           )

      (ok (list
        (cons 'nwk-fcf (list (cons 'raw nwk-fcf) (cons 'formatted (fmt-hex nwk-fcf))))
        (cons 'nwk-fcf-security-enabled (list (cons 'raw nwk-fcf-security-enabled) (cons 'formatted (if (= nwk-fcf-security-enabled 0) "Not set" "Set"))))
        (cons 'nwk-fcf-protocol-version (list (cons 'raw nwk-fcf-protocol-version) (cons 'formatted (if (= nwk-fcf-protocol-version 0) "Not set" "Set"))))
        (cons 'nwk-fcf-reserved (list (cons 'raw nwk-fcf-reserved) (cons 'formatted (if (= nwk-fcf-reserved 0) "Not set" "Set"))))
        (cons 'nwk-seq-num (list (cons 'raw nwk-seq-num) (cons 'formatted (number->string nwk-seq-num))))
        (cons 'nwk-vendor-id (list (cons 'raw nwk-vendor-id) (cons 'formatted (fmt-hex nwk-vendor-id))))
        (cons 'nwk-mic (list (cons 'raw nwk-mic) (cons 'formatted (fmt-hex nwk-mic))))
        )))

    (catch (e)
      (err (str "RF4CE-NWK parse error: " e)))))

;; dissect-rf4ce-nwk: parse RF4CE-NWK from bytevector
;; Returns (ok fields-alist) or (err message)