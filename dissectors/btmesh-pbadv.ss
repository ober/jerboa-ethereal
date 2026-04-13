;; packet-btmesh-pbadv.c
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

;; jerboa-ethereal/dissectors/btmesh-pbadv.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btmesh_pbadv.c

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
(def (dissect-btmesh-pbadv buffer)
  "Bluetooth Mesh PB-ADV"
  (try
    (let* (
           (pbadv-linkid (unwrap (read-u32be buffer 0)))
           (pbadv-trnumber (unwrap (read-u8 buffer 4)))
           (gpcf-segn (unwrap (read-u8 buffer 5)))
           (gpcf-total-length (unwrap (read-u16be buffer 6)))
           (gpcf-fcs (unwrap (read-u8 buffer 8)))
           (gpp-payload (unwrap (slice buffer 9 1)))
           (gpcf-padding (unwrap (read-u8 buffer 9)))
           (gpcf-segment-index (unwrap (read-u8 buffer 9)))
           (gpp-payload-fragment (unwrap (slice buffer 10 1)))
           (gpcf-bearer-opcode-device-UUID (unwrap (slice buffer 11 16)))
           (gpcf-bearer-unknown-data (unwrap (slice buffer 28 1)))
           )

      (ok (list
        (cons 'pbadv-linkid (list (cons 'raw pbadv-linkid) (cons 'formatted (number->string pbadv-linkid))))
        (cons 'pbadv-trnumber (list (cons 'raw pbadv-trnumber) (cons 'formatted (number->string pbadv-trnumber))))
        (cons 'gpcf-segn (list (cons 'raw gpcf-segn) (cons 'formatted (number->string gpcf-segn))))
        (cons 'gpcf-total-length (list (cons 'raw gpcf-total-length) (cons 'formatted (number->string gpcf-total-length))))
        (cons 'gpcf-fcs (list (cons 'raw gpcf-fcs) (cons 'formatted (fmt-hex gpcf-fcs))))
        (cons 'gpp-payload (list (cons 'raw gpp-payload) (cons 'formatted (fmt-bytes gpp-payload))))
        (cons 'gpcf-padding (list (cons 'raw gpcf-padding) (cons 'formatted (number->string gpcf-padding))))
        (cons 'gpcf-segment-index (list (cons 'raw gpcf-segment-index) (cons 'formatted (number->string gpcf-segment-index))))
        (cons 'gpp-payload-fragment (list (cons 'raw gpp-payload-fragment) (cons 'formatted (fmt-bytes gpp-payload-fragment))))
        (cons 'gpcf-bearer-opcode-device-UUID (list (cons 'raw gpcf-bearer-opcode-device-UUID) (cons 'formatted (fmt-bytes gpcf-bearer-opcode-device-UUID))))
        (cons 'gpcf-bearer-unknown-data (list (cons 'raw gpcf-bearer-unknown-data) (cons 'formatted (fmt-bytes gpcf-bearer-unknown-data))))
        )))

    (catch (e)
      (err (str "BTMESH-PBADV parse error: " e)))))

;; dissect-btmesh-pbadv: parse BTMESH-PBADV from bytevector
;; Returns (ok fields-alist) or (err message)