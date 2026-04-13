;; packet-lbmpdm.c
;; Routines for LBM PDM Packet dissection
;;
;; Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lbmpdm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lbmpdm.c

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
(def (dissect-lbmpdm buffer)
  "LBMPDM Protocol"
  (try
    (let* (
           (field-int-name (unwrap (read-u32be buffer 0)))
           (field-string-name (unwrap (slice buffer 0 1)))
           (field-id (unwrap (read-u32be buffer 0)))
           (field-value-boolean (unwrap (read-u8 buffer 0)))
           (field-value-int8 (unwrap (read-u8 buffer 0)))
           (field-value-uint8 (unwrap (read-u8 buffer 0)))
           (field-value-int16 (unwrap (read-u16be buffer 0)))
           (field-value-uint16 (unwrap (read-u16be buffer 0)))
           (field-value-int32 (unwrap (read-u32be buffer 0)))
           (field-value-uint32 (unwrap (read-u32be buffer 0)))
           (field-value-int64 (unwrap (read-u64be buffer 0)))
           (field-value-uint64 (unwrap (read-u64be buffer 0)))
           (field-value-float (unwrap (read-u32be buffer 0)))
           (field-value-double (unwrap (read-u64be buffer 0)))
           (field-value-fixed-string (unwrap (slice buffer 0 1)))
           (field-value-string (unwrap (slice buffer 0 1)))
           (field-value-fixed-unicode (unwrap (slice buffer 0 1)))
           (field-value-unicode (unwrap (slice buffer 0 1)))
           (field-value-blob (unwrap (slice buffer 0 1)))
           (field-value-message (unwrap (slice buffer 0 1)))
           (segment-flags (unwrap (read-u8 buffer 4)))
           (segment-res (unwrap (read-u16be buffer 4)))
           (segment-len (unwrap (read-u32be buffer 4)))
           (segment-data (unwrap (slice buffer 4 1)))
           (magic (unwrap (read-u32be buffer 4)))
           (encoding (unwrap (slice buffer 4 1)))
           (ver (unwrap (read-u8 buffer 4)))
           (type (unwrap (read-u8 buffer 4)))
           (def-major-ver (unwrap (read-u8 buffer 4)))
           (def-minor-ver (unwrap (read-u8 buffer 4)))
           (def-id (unwrap (read-u32be buffer 4)))
           (len (unwrap (read-u32be buffer 4)))
           )

      (ok (list
        (cons 'field-int-name (list (cons 'raw field-int-name) (cons 'formatted (number->string field-int-name))))
        (cons 'field-string-name (list (cons 'raw field-string-name) (cons 'formatted (utf8->string field-string-name))))
        (cons 'field-id (list (cons 'raw field-id) (cons 'formatted (number->string field-id))))
        (cons 'field-value-boolean (list (cons 'raw field-value-boolean) (cons 'formatted (number->string field-value-boolean))))
        (cons 'field-value-int8 (list (cons 'raw field-value-int8) (cons 'formatted (number->string field-value-int8))))
        (cons 'field-value-uint8 (list (cons 'raw field-value-uint8) (cons 'formatted (number->string field-value-uint8))))
        (cons 'field-value-int16 (list (cons 'raw field-value-int16) (cons 'formatted (number->string field-value-int16))))
        (cons 'field-value-uint16 (list (cons 'raw field-value-uint16) (cons 'formatted (number->string field-value-uint16))))
        (cons 'field-value-int32 (list (cons 'raw field-value-int32) (cons 'formatted (number->string field-value-int32))))
        (cons 'field-value-uint32 (list (cons 'raw field-value-uint32) (cons 'formatted (number->string field-value-uint32))))
        (cons 'field-value-int64 (list (cons 'raw field-value-int64) (cons 'formatted (number->string field-value-int64))))
        (cons 'field-value-uint64 (list (cons 'raw field-value-uint64) (cons 'formatted (number->string field-value-uint64))))
        (cons 'field-value-float (list (cons 'raw field-value-float) (cons 'formatted (number->string field-value-float))))
        (cons 'field-value-double (list (cons 'raw field-value-double) (cons 'formatted (number->string field-value-double))))
        (cons 'field-value-fixed-string (list (cons 'raw field-value-fixed-string) (cons 'formatted (utf8->string field-value-fixed-string))))
        (cons 'field-value-string (list (cons 'raw field-value-string) (cons 'formatted (utf8->string field-value-string))))
        (cons 'field-value-fixed-unicode (list (cons 'raw field-value-fixed-unicode) (cons 'formatted (fmt-bytes field-value-fixed-unicode))))
        (cons 'field-value-unicode (list (cons 'raw field-value-unicode) (cons 'formatted (fmt-bytes field-value-unicode))))
        (cons 'field-value-blob (list (cons 'raw field-value-blob) (cons 'formatted (fmt-bytes field-value-blob))))
        (cons 'field-value-message (list (cons 'raw field-value-message) (cons 'formatted (fmt-bytes field-value-message))))
        (cons 'segment-flags (list (cons 'raw segment-flags) (cons 'formatted (fmt-hex segment-flags))))
        (cons 'segment-res (list (cons 'raw segment-res) (cons 'formatted (fmt-hex segment-res))))
        (cons 'segment-len (list (cons 'raw segment-len) (cons 'formatted (number->string segment-len))))
        (cons 'segment-data (list (cons 'raw segment-data) (cons 'formatted (fmt-bytes segment-data))))
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        (cons 'encoding (list (cons 'raw encoding) (cons 'formatted (utf8->string encoding))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (number->string type))))
        (cons 'def-major-ver (list (cons 'raw def-major-ver) (cons 'formatted (number->string def-major-ver))))
        (cons 'def-minor-ver (list (cons 'raw def-minor-ver) (cons 'formatted (number->string def-minor-ver))))
        (cons 'def-id (list (cons 'raw def-id) (cons 'formatted (number->string def-id))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        )))

    (catch (e)
      (err (str "LBMPDM parse error: " e)))))

;; dissect-lbmpdm: parse LBMPDM from bytevector
;; Returns (ok fields-alist) or (err message)