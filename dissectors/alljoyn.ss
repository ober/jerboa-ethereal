;; packet-alljoyn.c
;; Routines for AllJoyn (AllJoyn.org) packet dissection
;; Copyright (c) 2013-2014, The Linux Foundation.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/alljoyn.ss
;; Auto-generated from wireshark/epan/dissectors/packet-alljoyn.c

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
(def (dissect-alljoyn buffer)
  "AllJoyn Name Service Protocol"
  (try
    (let* (
           (connect-byte-value (unwrap (read-u8 buffer 0)))
           (ns-sender-version (unwrap (read-u8 buffer 0)))
           (ns-message-version (unwrap (read-u8 buffer 0)))
           (sasl-command (unwrap (slice buffer 1 1)))
           (sasl-parameter (unwrap (slice buffer 1 1)))
           (boolean (unwrap (read-u8 buffer 1)))
           (ns-questions (unwrap (read-u8 buffer 1)))
           (ns-answers (unwrap (read-u8 buffer 2)))
           (ns-timer (unwrap (read-u8 buffer 3)))
           (double (unwrap (read-u64be buffer 5)))
           (handle (unwrap (read-u32be buffer 14)))
           (int32 (unwrap (read-u32be buffer 18)))
           (int16 (unwrap (read-u16be buffer 22)))
           (uint16 (unwrap (read-u16be buffer 28)))
           (string-size-32bit (unwrap (read-u32be buffer 30)))
           (string-data (unwrap (slice buffer 34 1)))
           (uint64 (unwrap (read-u64be buffer 34)))
           (uint32 (unwrap (read-u32be buffer 42)))
           (mess-body-signature-length (unwrap (read-u8 buffer 46)))
           (mess-body-signature (unwrap (slice buffer 47 1)))
           (int64 (unwrap (read-u64be buffer 47)))
           (uint8 (unwrap (read-u8 buffer 55)))
           (mess-body-header-fieldcode (unwrap (read-u8 buffer 56)))
           (mess-header-fields (unwrap (slice buffer 60 1)))
           (mess-header (unwrap (slice buffer 60 1)))
           (mess-header-flags (unwrap (read-u8 buffer 60)))
           (mess-header-flags-encrypted (unwrap (read-u8 buffer 60)))
           (mess-header-flags-compressed (unwrap (read-u8 buffer 60)))
           (mess-header-flags-global-broadcast (unwrap (read-u8 buffer 60)))
           (mess-header-flags-sessionless (unwrap (read-u8 buffer 60)))
           (mess-header-flags-allow-remote-msg (unwrap (read-u8 buffer 60)))
           (mess-header-flags-no-auto-start (unwrap (read-u8 buffer 60)))
           (mess-header-flags-no-reply (unwrap (read-u8 buffer 60)))
           (mess-header-majorversion (unwrap (read-u8 buffer 60)))
           (mess-header-body-length (unwrap (read-u32be buffer 60)))
           (mess-header-serial (unwrap (read-u32be buffer 60)))
           (mess-header-header-length (unwrap (read-u32be buffer 60)))
           )

      (ok (list
        (cons 'connect-byte-value (list (cons 'raw connect-byte-value) (cons 'formatted (fmt-hex connect-byte-value))))
        (cons 'ns-sender-version (list (cons 'raw ns-sender-version) (cons 'formatted (number->string ns-sender-version))))
        (cons 'ns-message-version (list (cons 'raw ns-message-version) (cons 'formatted (number->string ns-message-version))))
        (cons 'sasl-command (list (cons 'raw sasl-command) (cons 'formatted (utf8->string sasl-command))))
        (cons 'sasl-parameter (list (cons 'raw sasl-parameter) (cons 'formatted (utf8->string sasl-parameter))))
        (cons 'boolean (list (cons 'raw boolean) (cons 'formatted (number->string boolean))))
        (cons 'ns-questions (list (cons 'raw ns-questions) (cons 'formatted (number->string ns-questions))))
        (cons 'ns-answers (list (cons 'raw ns-answers) (cons 'formatted (number->string ns-answers))))
        (cons 'ns-timer (list (cons 'raw ns-timer) (cons 'formatted (number->string ns-timer))))
        (cons 'double (list (cons 'raw double) (cons 'formatted (number->string double))))
        (cons 'handle (list (cons 'raw handle) (cons 'formatted (fmt-hex handle))))
        (cons 'int32 (list (cons 'raw int32) (cons 'formatted (number->string int32))))
        (cons 'int16 (list (cons 'raw int16) (cons 'formatted (number->string int16))))
        (cons 'uint16 (list (cons 'raw uint16) (cons 'formatted (number->string uint16))))
        (cons 'string-size-32bit (list (cons 'raw string-size-32bit) (cons 'formatted (number->string string-size-32bit))))
        (cons 'string-data (list (cons 'raw string-data) (cons 'formatted (utf8->string string-data))))
        (cons 'uint64 (list (cons 'raw uint64) (cons 'formatted (number->string uint64))))
        (cons 'uint32 (list (cons 'raw uint32) (cons 'formatted (number->string uint32))))
        (cons 'mess-body-signature-length (list (cons 'raw mess-body-signature-length) (cons 'formatted (number->string mess-body-signature-length))))
        (cons 'mess-body-signature (list (cons 'raw mess-body-signature) (cons 'formatted (utf8->string mess-body-signature))))
        (cons 'int64 (list (cons 'raw int64) (cons 'formatted (number->string int64))))
        (cons 'uint8 (list (cons 'raw uint8) (cons 'formatted (number->string uint8))))
        (cons 'mess-body-header-fieldcode (list (cons 'raw mess-body-header-fieldcode) (cons 'formatted (fmt-hex mess-body-header-fieldcode))))
        (cons 'mess-header-fields (list (cons 'raw mess-header-fields) (cons 'formatted (fmt-bytes mess-header-fields))))
        (cons 'mess-header (list (cons 'raw mess-header) (cons 'formatted (fmt-bytes mess-header))))
        (cons 'mess-header-flags (list (cons 'raw mess-header-flags) (cons 'formatted (fmt-hex mess-header-flags))))
        (cons 'mess-header-flags-encrypted (list (cons 'raw mess-header-flags-encrypted) (cons 'formatted (number->string mess-header-flags-encrypted))))
        (cons 'mess-header-flags-compressed (list (cons 'raw mess-header-flags-compressed) (cons 'formatted (number->string mess-header-flags-compressed))))
        (cons 'mess-header-flags-global-broadcast (list (cons 'raw mess-header-flags-global-broadcast) (cons 'formatted (number->string mess-header-flags-global-broadcast))))
        (cons 'mess-header-flags-sessionless (list (cons 'raw mess-header-flags-sessionless) (cons 'formatted (number->string mess-header-flags-sessionless))))
        (cons 'mess-header-flags-allow-remote-msg (list (cons 'raw mess-header-flags-allow-remote-msg) (cons 'formatted (number->string mess-header-flags-allow-remote-msg))))
        (cons 'mess-header-flags-no-auto-start (list (cons 'raw mess-header-flags-no-auto-start) (cons 'formatted (number->string mess-header-flags-no-auto-start))))
        (cons 'mess-header-flags-no-reply (list (cons 'raw mess-header-flags-no-reply) (cons 'formatted (number->string mess-header-flags-no-reply))))
        (cons 'mess-header-majorversion (list (cons 'raw mess-header-majorversion) (cons 'formatted (number->string mess-header-majorversion))))
        (cons 'mess-header-body-length (list (cons 'raw mess-header-body-length) (cons 'formatted (number->string mess-header-body-length))))
        (cons 'mess-header-serial (list (cons 'raw mess-header-serial) (cons 'formatted (number->string mess-header-serial))))
        (cons 'mess-header-header-length (list (cons 'raw mess-header-header-length) (cons 'formatted (number->string mess-header-header-length))))
        )))

    (catch (e)
      (err (str "ALLJOYN parse error: " e)))))

;; dissect-alljoyn: parse ALLJOYN from bytevector
;; Returns (ok fields-alist) or (err message)