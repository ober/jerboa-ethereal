;; packet-hpsw.c
;; Routines for HP Switch Config protocol
;; Charlie Lenahan <clenahan@fortresstech.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hpsw.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hpsw.c

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
(def (dissect-hpsw buffer)
  "HP Switch Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (device-name (unwrap (slice buffer 0 1)))
           (device-version (unwrap (slice buffer 0 1)))
           (config-name (unwrap (slice buffer 0 1)))
           (root-mac-addr (unwrap (slice buffer 0 6)))
           (ip-addr (unwrap (read-u32be buffer 0)))
           (field-6 (unwrap (read-u16be buffer 0)))
           (domain (unwrap (slice buffer 0 1)))
           (field-8 (unwrap (read-u16be buffer 0)))
           (field-9 (unwrap (read-u16be buffer 0)))
           (field-10 (unwrap (read-u32be buffer 0)))
           (neighbor-mac-addr (unwrap (slice buffer 0 6)))
           (type (unwrap (read-u8 buffer 1)))
           (tlvlength (unwrap (read-u8 buffer 3)))
           (field-12 (unwrap (read-u8 buffer 6)))
           (device-id (unwrap (slice buffer 6 6)))
           (device-id-data (unwrap (slice buffer 6 1)))
           (own-mac-addr (unwrap (slice buffer 6 6)))
           (data (unwrap (slice buffer 6 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'device-name (list (cons 'raw device-name) (cons 'formatted (utf8->string device-name))))
        (cons 'device-version (list (cons 'raw device-version) (cons 'formatted (utf8->string device-version))))
        (cons 'config-name (list (cons 'raw config-name) (cons 'formatted (utf8->string config-name))))
        (cons 'root-mac-addr (list (cons 'raw root-mac-addr) (cons 'formatted (fmt-mac root-mac-addr))))
        (cons 'ip-addr (list (cons 'raw ip-addr) (cons 'formatted (fmt-ipv4 ip-addr))))
        (cons 'field-6 (list (cons 'raw field-6) (cons 'formatted (fmt-hex field-6))))
        (cons 'domain (list (cons 'raw domain) (cons 'formatted (utf8->string domain))))
        (cons 'field-8 (list (cons 'raw field-8) (cons 'formatted (fmt-hex field-8))))
        (cons 'field-9 (list (cons 'raw field-9) (cons 'formatted (fmt-hex field-9))))
        (cons 'field-10 (list (cons 'raw field-10) (cons 'formatted (fmt-hex field-10))))
        (cons 'neighbor-mac-addr (list (cons 'raw neighbor-mac-addr) (cons 'formatted (fmt-mac neighbor-mac-addr))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (fmt-hex type))))
        (cons 'tlvlength (list (cons 'raw tlvlength) (cons 'formatted (number->string tlvlength))))
        (cons 'field-12 (list (cons 'raw field-12) (cons 'formatted (fmt-hex field-12))))
        (cons 'device-id (list (cons 'raw device-id) (cons 'formatted (fmt-mac device-id))))
        (cons 'device-id-data (list (cons 'raw device-id-data) (cons 'formatted (fmt-bytes device-id-data))))
        (cons 'own-mac-addr (list (cons 'raw own-mac-addr) (cons 'formatted (fmt-mac own-mac-addr))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        )))

    (catch (e)
      (err (str "HPSW parse error: " e)))))

;; dissect-hpsw: parse HPSW from bytevector
;; Returns (ok fields-alist) or (err message)