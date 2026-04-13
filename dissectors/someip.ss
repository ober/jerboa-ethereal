;; packet-someip.c
;; SOME/IP dissector.
;; By Dr. Lars Voelker <lars.voelker@technica-engineering.de> / <lars.voelker@bmw.de>
;; Copyright 2012-2025 Dr. Lars Völker
;; Copyright 2019      Ana Pantar
;; Copyright 2019      Guenter Ebermann
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/someip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-someip.c

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
(def (dissect-someip buffer)
  "SOME/IP Protocol"
  (try
    (let* (
           (length-field-16bit (unwrap (read-u16be buffer 0)))
           (length-field-32bit (unwrap (read-u32be buffer 0)))
           (type-field-8bit (unwrap (read-u8 buffer 0)))
           (type-field-16bit (unwrap (read-u16be buffer 0)))
           (type-field-32bit (unwrap (read-u32be buffer 0)))
           (str-base (unwrap (slice buffer 0 1)))
           (str-struct (unwrap (slice buffer 0 1)))
           (str-array (unwrap (slice buffer 0 1)))
           (bitfield-item (unwrap (read-u8 buffer 0)))
           (unparsed (unwrap (slice buffer 0 1)))
           (messageid (unwrap (read-u32be buffer 0)))
           (serviceid (unwrap (read-u16be buffer 0)))
           (servicename (unwrap (slice buffer 0 2)))
           (methodid (unwrap (read-u16be buffer 2)))
           (methodname (unwrap (slice buffer 2 2)))
           (length (unwrap (read-u32be buffer 4)))
           (clientid (unwrap (read-u16be buffer 8)))
           (clientname (unwrap (slice buffer 8 2)))
           (sessionid (unwrap (read-u16be buffer 10)))
           (protover (unwrap (read-u8 buffer 12)))
           (interface-ver (unwrap (read-u8 buffer 13)))
           (messagetype (unwrap (read-u8 buffer 14)))
           (messagetype-ack-flag (unwrap (read-u8 buffer 14)))
           (messagetype-tp-flag (unwrap (read-u8 buffer 14)))
           (returncode (unwrap (read-u8 buffer 15)))
           (tp (unwrap (slice buffer 16 1)))
           (tp-offset-encoded (unwrap (read-u32be buffer 16)))
           (tp-reserved (unwrap (read-u32be buffer 16)))
           (tp-more-segments (unwrap (read-u8 buffer 16)))
           (tp-offset (unwrap (read-u32be buffer 16)))
           (payload (unwrap (slice buffer 20 1)))
           (length-field-8bit (unwrap (read-u8 buffer 21)))
           )

      (ok (list
        (cons 'length-field-16bit (list (cons 'raw length-field-16bit) (cons 'formatted (number->string length-field-16bit))))
        (cons 'length-field-32bit (list (cons 'raw length-field-32bit) (cons 'formatted (number->string length-field-32bit))))
        (cons 'type-field-8bit (list (cons 'raw type-field-8bit) (cons 'formatted (number->string type-field-8bit))))
        (cons 'type-field-16bit (list (cons 'raw type-field-16bit) (cons 'formatted (number->string type-field-16bit))))
        (cons 'type-field-32bit (list (cons 'raw type-field-32bit) (cons 'formatted (number->string type-field-32bit))))
        (cons 'str-base (list (cons 'raw str-base) (cons 'formatted (utf8->string str-base))))
        (cons 'str-struct (list (cons 'raw str-struct) (cons 'formatted (utf8->string str-struct))))
        (cons 'str-array (list (cons 'raw str-array) (cons 'formatted (utf8->string str-array))))
        (cons 'bitfield-item (list (cons 'raw bitfield-item) (cons 'formatted (number->string bitfield-item))))
        (cons 'unparsed (list (cons 'raw unparsed) (cons 'formatted (fmt-bytes unparsed))))
        (cons 'messageid (list (cons 'raw messageid) (cons 'formatted (fmt-hex messageid))))
        (cons 'serviceid (list (cons 'raw serviceid) (cons 'formatted (fmt-hex serviceid))))
        (cons 'servicename (list (cons 'raw servicename) (cons 'formatted (utf8->string servicename))))
        (cons 'methodid (list (cons 'raw methodid) (cons 'formatted (fmt-hex methodid))))
        (cons 'methodname (list (cons 'raw methodname) (cons 'formatted (utf8->string methodname))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'clientid (list (cons 'raw clientid) (cons 'formatted (fmt-hex clientid))))
        (cons 'clientname (list (cons 'raw clientname) (cons 'formatted (utf8->string clientname))))
        (cons 'sessionid (list (cons 'raw sessionid) (cons 'formatted (fmt-hex sessionid))))
        (cons 'protover (list (cons 'raw protover) (cons 'formatted (fmt-hex protover))))
        (cons 'interface-ver (list (cons 'raw interface-ver) (cons 'formatted (fmt-hex interface-ver))))
        (cons 'messagetype (list (cons 'raw messagetype) (cons 'formatted (fmt-hex messagetype))))
        (cons 'messagetype-ack-flag (list (cons 'raw messagetype-ack-flag) (cons 'formatted (number->string messagetype-ack-flag))))
        (cons 'messagetype-tp-flag (list (cons 'raw messagetype-tp-flag) (cons 'formatted (number->string messagetype-tp-flag))))
        (cons 'returncode (list (cons 'raw returncode) (cons 'formatted (fmt-hex returncode))))
        (cons 'tp (list (cons 'raw tp) (cons 'formatted (fmt-bytes tp))))
        (cons 'tp-offset-encoded (list (cons 'raw tp-offset-encoded) (cons 'formatted (fmt-hex tp-offset-encoded))))
        (cons 'tp-reserved (list (cons 'raw tp-reserved) (cons 'formatted (fmt-hex tp-reserved))))
        (cons 'tp-more-segments (list (cons 'raw tp-more-segments) (cons 'formatted (number->string tp-more-segments))))
        (cons 'tp-offset (list (cons 'raw tp-offset) (cons 'formatted (number->string tp-offset))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'length-field-8bit (list (cons 'raw length-field-8bit) (cons 'formatted (number->string length-field-8bit))))
        )))

    (catch (e)
      (err (str "SOMEIP parse error: " e)))))

;; dissect-someip: parse SOMEIP from bytevector
;; Returns (ok fields-alist) or (err message)