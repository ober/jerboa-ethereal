;; packet-protobuf.c
;; Routines for Google Protocol Buffers dissection
;; Copyright 2017-2022, Huang Qiangxiong <qiangxiong.huang@qq.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/protobuf.ss
;; Auto-generated from wireshark/epan/dissectors/packet-protobuf.c

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
(def (dissect-protobuf buffer)
  "Protocol Buffers"
  (try
    (let* (
           (mapping-line (unwrap (slice buffer 0 1)))
           (value-double (unwrap (read-u64be buffer 0)))
           (value-float (unwrap (read-u32be buffer 0)))
           (value-int64 (unwrap (read-u64be buffer 0)))
           (value-uint64 (unwrap (read-u64be buffer 0)))
           (value-int32 (unwrap (read-u32be buffer 0)))
           (value-bool (unwrap (read-u8 buffer 0)))
           (value-string (unwrap (slice buffer 0 1)))
           (value-uint32 (unwrap (read-u32be buffer 0)))
           (field-name (unwrap (slice buffer 0 1)))
           (field-number (unwrap (read-u64be buffer 0)))
           (value-data (unwrap (slice buffer 0 1)))
           (message-name (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'mapping-line (list (cons 'raw mapping-line) (cons 'formatted (utf8->string mapping-line))))
        (cons 'value-double (list (cons 'raw value-double) (cons 'formatted (number->string value-double))))
        (cons 'value-float (list (cons 'raw value-float) (cons 'formatted (number->string value-float))))
        (cons 'value-int64 (list (cons 'raw value-int64) (cons 'formatted (number->string value-int64))))
        (cons 'value-uint64 (list (cons 'raw value-uint64) (cons 'formatted (number->string value-uint64))))
        (cons 'value-int32 (list (cons 'raw value-int32) (cons 'formatted (number->string value-int32))))
        (cons 'value-bool (list (cons 'raw value-bool) (cons 'formatted (number->string value-bool))))
        (cons 'value-string (list (cons 'raw value-string) (cons 'formatted (utf8->string value-string))))
        (cons 'value-uint32 (list (cons 'raw value-uint32) (cons 'formatted (number->string value-uint32))))
        (cons 'field-name (list (cons 'raw field-name) (cons 'formatted (utf8->string field-name))))
        (cons 'field-number (list (cons 'raw field-number) (cons 'formatted (number->string field-number))))
        (cons 'value-data (list (cons 'raw value-data) (cons 'formatted (fmt-bytes value-data))))
        (cons 'message-name (list (cons 'raw message-name) (cons 'formatted (utf8->string message-name))))
        )))

    (catch (e)
      (err (str "PROTOBUF parse error: " e)))))

;; dissect-protobuf: parse PROTOBUF from bytevector
;; Returns (ok fields-alist) or (err message)