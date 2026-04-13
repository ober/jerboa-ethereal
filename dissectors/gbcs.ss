;; packet-gbcs.c
;;
;; Dissector for Great Britain Companion Specification (GBCS) used in the Smart Metering Equipment Technical Specifications (SMETS)
;;
;; The Smart Metering Equipment Technical Specifications (SMETS) requires that Gas Smart Metering Equipment (GSME), and Electricity
;; Smart Metering Equipment (ESME) including variants, meet the requirements described in
;; the Great Britain Companion Specification (GBCS).
;;
;; GBCS messages are end-to-end and contains ZigBee, DLMS or ASN.1 formatted payloads. The GBCS messages are transported via IP
;; or via the ZigBee Tunneling cluster.
;;
;; https://smartenergycodecompany.co.uk/document-download-centre/download-info/gbcs-v2-1/
;;
;; Sample capture is attached in Bug 15381
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gbcs.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gbcs.c

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
(def (dissect-gbcs buffer)
  "GBCS GBZ"
  (try
    (let* (
           (tunnel-remaining (unwrap (read-u8 buffer 1)))
           (gbz-components (unwrap (read-u8 buffer 2)))
           (gbz-firmware-alert-start (unwrap (read-u16be buffer 9)))
           (gbz-firmware-hash (unwrap (slice buffer 11 32)))
           (gbz-future-alert-start (unwrap (read-u8 buffer 43)))
           (gbz-originator-counter (unwrap (read-u64be buffer 46)))
           (gbz-frame-control (unwrap (read-u8 buffer 56)))
           (gbz-command-id (unwrap (read-u8 buffer 57)))
           (gbz-profile-id (unwrap (read-u16be buffer 58)))
           )

      (ok (list
        (cons 'tunnel-remaining (list (cons 'raw tunnel-remaining) (cons 'formatted (number->string tunnel-remaining))))
        (cons 'gbz-components (list (cons 'raw gbz-components) (cons 'formatted (number->string gbz-components))))
        (cons 'gbz-firmware-alert-start (list (cons 'raw gbz-firmware-alert-start) (cons 'formatted (fmt-hex gbz-firmware-alert-start))))
        (cons 'gbz-firmware-hash (list (cons 'raw gbz-firmware-hash) (cons 'formatted (fmt-bytes gbz-firmware-hash))))
        (cons 'gbz-future-alert-start (list (cons 'raw gbz-future-alert-start) (cons 'formatted (fmt-hex gbz-future-alert-start))))
        (cons 'gbz-originator-counter (list (cons 'raw gbz-originator-counter) (cons 'formatted (number->string gbz-originator-counter))))
        (cons 'gbz-frame-control (list (cons 'raw gbz-frame-control) (cons 'formatted (fmt-hex gbz-frame-control))))
        (cons 'gbz-command-id (list (cons 'raw gbz-command-id) (cons 'formatted (fmt-hex gbz-command-id))))
        (cons 'gbz-profile-id (list (cons 'raw gbz-profile-id) (cons 'formatted (fmt-hex gbz-profile-id))))
        )))

    (catch (e)
      (err (str "GBCS parse error: " e)))))

;; dissect-gbcs: parse GBCS from bytevector
;; Returns (ok fields-alist) or (err message)