;; packet-saphdb.c
;; Routines for SAP HDB (HANA SQL Command Network Protocol) dissection
;; Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
;; Code contributed by SecureAuth Corp.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/saphdb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-saphdb.c

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
(def (dissect-saphdb buffer)
  "SAP HANA SQL Command Network Protocol"
  (try
    (let* (
           (part-option-name (unwrap (read-u8 buffer 0)))
           (part-option-value-byte (unwrap (read-u8 buffer 0)))
           (part-option-value-short (unwrap (read-u16be buffer 0)))
           (part-option-value-int (unwrap (read-u32be buffer 0)))
           (part-option-value-bigint (unwrap (read-u64be buffer 0)))
           (part-option-value-double (unwrap (read-u64be buffer 0)))
           (part-option-value-bool (unwrap (read-u8 buffer 0)))
           (part-option-length (unwrap (read-u16be buffer 0)))
           (part-option-value-string (unwrap (slice buffer 0 1)))
           (part-option-argcount (unwrap (read-u16be buffer 0)))
           (part-authentication-field-count (unwrap (read-u16be buffer 6)))
           (part-authentication-field-length (unwrap (read-u16be buffer 11)))
           (part-command (unwrap (slice buffer 12 1)))
           (part-error-code (unwrap (read-u32be buffer 12)))
           (initialization-reply-product-version-major (unwrap (read-u8 buffer 14)))
           (initialization-reply-product-version-minor (unwrap (read-u16be buffer 15)))
           (part-error-position (unwrap (read-u32be buffer 16)))
           (initialization-reply-protocol-version-major (unwrap (read-u8 buffer 17)))
           (initialization-reply-protocol-version-minor (unwrap (read-u16be buffer 18)))
           (part-error-text-length (unwrap (read-u32be buffer 20)))
           (message-header-sessionid (unwrap (read-u64be buffer 20)))
           (part-error-sqlstate (unwrap (slice buffer 25 5)))
           (message-header-packetcount (unwrap (read-u32be buffer 28)))
           (part-error-text (unwrap (slice buffer 30 1)))
           (part-clientid (unwrap (slice buffer 30 1)))
           (part-partattributes (unwrap (read-u8 buffer 31)))
           (part-argumentcount (unwrap (read-u16be buffer 32)))
           (message-header-varpartlength (unwrap (read-u32be buffer 32)))
           (part-bigargumentcount (unwrap (read-u32be buffer 34)))
           (message-header-varpartsize (unwrap (read-u32be buffer 36)))
           (part-bufferlength (unwrap (read-u32be buffer 38)))
           (message-header-noofsegm (unwrap (read-u16be buffer 40)))
           (part-buffersize (unwrap (read-u32be buffer 42)))
           (message-header-compressionvarpartlength (unwrap (read-u32be buffer 44)))
           (segment-segmentlength (unwrap (read-u32be buffer 46)))
           (message-header-reserved (unwrap (slice buffer 48 4)))
           (segment-segmentofs (unwrap (read-u32be buffer 50)))
           (segment-noofparts (unwrap (read-u16be buffer 54)))
           (segment-segmentno (unwrap (read-u16be buffer 56)))
           (segment-commit (unwrap (read-u8 buffer 60)))
           (segment-commandoptions (unwrap (read-u8 buffer 61)))
           (segment-reserved (unwrap (slice buffer 73 8)))
           )

      (ok (list
        (cons 'part-option-name (list (cons 'raw part-option-name) (cons 'formatted (number->string part-option-name))))
        (cons 'part-option-value-byte (list (cons 'raw part-option-value-byte) (cons 'formatted (number->string part-option-value-byte))))
        (cons 'part-option-value-short (list (cons 'raw part-option-value-short) (cons 'formatted (number->string part-option-value-short))))
        (cons 'part-option-value-int (list (cons 'raw part-option-value-int) (cons 'formatted (number->string part-option-value-int))))
        (cons 'part-option-value-bigint (list (cons 'raw part-option-value-bigint) (cons 'formatted (number->string part-option-value-bigint))))
        (cons 'part-option-value-double (list (cons 'raw part-option-value-double) (cons 'formatted (number->string part-option-value-double))))
        (cons 'part-option-value-bool (list (cons 'raw part-option-value-bool) (cons 'formatted (number->string part-option-value-bool))))
        (cons 'part-option-length (list (cons 'raw part-option-length) (cons 'formatted (number->string part-option-length))))
        (cons 'part-option-value-string (list (cons 'raw part-option-value-string) (cons 'formatted (utf8->string part-option-value-string))))
        (cons 'part-option-argcount (list (cons 'raw part-option-argcount) (cons 'formatted (number->string part-option-argcount))))
        (cons 'part-authentication-field-count (list (cons 'raw part-authentication-field-count) (cons 'formatted (number->string part-authentication-field-count))))
        (cons 'part-authentication-field-length (list (cons 'raw part-authentication-field-length) (cons 'formatted (number->string part-authentication-field-length))))
        (cons 'part-command (list (cons 'raw part-command) (cons 'formatted (utf8->string part-command))))
        (cons 'part-error-code (list (cons 'raw part-error-code) (cons 'formatted (number->string part-error-code))))
        (cons 'initialization-reply-product-version-major (list (cons 'raw initialization-reply-product-version-major) (cons 'formatted (number->string initialization-reply-product-version-major))))
        (cons 'initialization-reply-product-version-minor (list (cons 'raw initialization-reply-product-version-minor) (cons 'formatted (number->string initialization-reply-product-version-minor))))
        (cons 'part-error-position (list (cons 'raw part-error-position) (cons 'formatted (number->string part-error-position))))
        (cons 'initialization-reply-protocol-version-major (list (cons 'raw initialization-reply-protocol-version-major) (cons 'formatted (number->string initialization-reply-protocol-version-major))))
        (cons 'initialization-reply-protocol-version-minor (list (cons 'raw initialization-reply-protocol-version-minor) (cons 'formatted (number->string initialization-reply-protocol-version-minor))))
        (cons 'part-error-text-length (list (cons 'raw part-error-text-length) (cons 'formatted (number->string part-error-text-length))))
        (cons 'message-header-sessionid (list (cons 'raw message-header-sessionid) (cons 'formatted (number->string message-header-sessionid))))
        (cons 'part-error-sqlstate (list (cons 'raw part-error-sqlstate) (cons 'formatted (utf8->string part-error-sqlstate))))
        (cons 'message-header-packetcount (list (cons 'raw message-header-packetcount) (cons 'formatted (number->string message-header-packetcount))))
        (cons 'part-error-text (list (cons 'raw part-error-text) (cons 'formatted (utf8->string part-error-text))))
        (cons 'part-clientid (list (cons 'raw part-clientid) (cons 'formatted (utf8->string part-clientid))))
        (cons 'part-partattributes (list (cons 'raw part-partattributes) (cons 'formatted (number->string part-partattributes))))
        (cons 'part-argumentcount (list (cons 'raw part-argumentcount) (cons 'formatted (number->string part-argumentcount))))
        (cons 'message-header-varpartlength (list (cons 'raw message-header-varpartlength) (cons 'formatted (number->string message-header-varpartlength))))
        (cons 'part-bigargumentcount (list (cons 'raw part-bigargumentcount) (cons 'formatted (number->string part-bigargumentcount))))
        (cons 'message-header-varpartsize (list (cons 'raw message-header-varpartsize) (cons 'formatted (number->string message-header-varpartsize))))
        (cons 'part-bufferlength (list (cons 'raw part-bufferlength) (cons 'formatted (number->string part-bufferlength))))
        (cons 'message-header-noofsegm (list (cons 'raw message-header-noofsegm) (cons 'formatted (number->string message-header-noofsegm))))
        (cons 'part-buffersize (list (cons 'raw part-buffersize) (cons 'formatted (number->string part-buffersize))))
        (cons 'message-header-compressionvarpartlength (list (cons 'raw message-header-compressionvarpartlength) (cons 'formatted (number->string message-header-compressionvarpartlength))))
        (cons 'segment-segmentlength (list (cons 'raw segment-segmentlength) (cons 'formatted (number->string segment-segmentlength))))
        (cons 'message-header-reserved (list (cons 'raw message-header-reserved) (cons 'formatted (fmt-bytes message-header-reserved))))
        (cons 'segment-segmentofs (list (cons 'raw segment-segmentofs) (cons 'formatted (number->string segment-segmentofs))))
        (cons 'segment-noofparts (list (cons 'raw segment-noofparts) (cons 'formatted (number->string segment-noofparts))))
        (cons 'segment-segmentno (list (cons 'raw segment-segmentno) (cons 'formatted (number->string segment-segmentno))))
        (cons 'segment-commit (list (cons 'raw segment-commit) (cons 'formatted (number->string segment-commit))))
        (cons 'segment-commandoptions (list (cons 'raw segment-commandoptions) (cons 'formatted (number->string segment-commandoptions))))
        (cons 'segment-reserved (list (cons 'raw segment-reserved) (cons 'formatted (fmt-bytes segment-reserved))))
        )))

    (catch (e)
      (err (str "SAPHDB parse error: " e)))))

;; dissect-saphdb: parse SAPHDB from bytevector
;; Returns (ok fields-alist) or (err message)