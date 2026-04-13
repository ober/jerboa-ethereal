;; packet-classicstun.c
;; Routines for Simple Traversal of UDP Through NAT dissection
;; Copyright 2003, Shiang-Ming Huang <smhuang@pcs.csie.nctu.edu.tw>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Please refer to RFC 3489 for protocol detail.
;; (supports extra message attributes described in draft-ietf-behave-rfc3489bis-00)
;;

;; jerboa-ethereal/dissectors/classicstun.ss
;; Auto-generated from wireshark/epan/dissectors/packet-classicstun.c
;; RFC 3489

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
(def (dissect-classicstun buffer)
  "Simple Traversal of UDP Through NAT"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 2)))
           (att-length (unwrap (read-u16be buffer 2)))
           (id (unwrap (slice buffer 4 16)))
           (att-port (unwrap (read-u16be buffer 4)))
           (att-ipv4 (unwrap (read-u32be buffer 4)))
           (att-ipv6 (unwrap (slice buffer 4 16)))
           (att-change-ip (unwrap (read-u8 buffer 4)))
           (att-change-port (unwrap (read-u8 buffer 4)))
           (att-value (unwrap (slice buffer 4 1)))
           (att-error-class (unwrap (read-u8 buffer 4)))
           (att-error-number (unwrap (read-u8 buffer 4)))
           (att-lifetime (unwrap (read-u32be buffer 4)))
           (att-magic-cookie (unwrap (read-u32be buffer 4)))
           (att-bandwidth (unwrap (read-u32be buffer 4)))
           (att-data (unwrap (slice buffer 4 1)))
           (att-unknown (unwrap (read-u16be buffer 4)))
           (att-server-string (unwrap (slice buffer 4 1)))
           (att-xor-port (unwrap (read-u16be buffer 4)))
           (att-xor-ipv4 (unwrap (read-u32be buffer 4)))
           (att-xor-ipv6 (unwrap (slice buffer 4 16)))
           (att-connection-request-binding (unwrap (slice buffer 4 1)))
           (att-padding (unwrap (read-u16be buffer 4)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (fmt-hex length))))
        (cons 'att-length (list (cons 'raw att-length) (cons 'formatted (number->string att-length))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-bytes id))))
        (cons 'att-port (list (cons 'raw att-port) (cons 'formatted (number->string att-port))))
        (cons 'att-ipv4 (list (cons 'raw att-ipv4) (cons 'formatted (fmt-ipv4 att-ipv4))))
        (cons 'att-ipv6 (list (cons 'raw att-ipv6) (cons 'formatted (fmt-ipv6-address att-ipv6))))
        (cons 'att-change-ip (list (cons 'raw att-change-ip) (cons 'formatted (if (= att-change-ip 0) "False" "True"))))
        (cons 'att-change-port (list (cons 'raw att-change-port) (cons 'formatted (if (= att-change-port 0) "False" "True"))))
        (cons 'att-value (list (cons 'raw att-value) (cons 'formatted (fmt-bytes att-value))))
        (cons 'att-error-class (list (cons 'raw att-error-class) (cons 'formatted (number->string att-error-class))))
        (cons 'att-error-number (list (cons 'raw att-error-number) (cons 'formatted (number->string att-error-number))))
        (cons 'att-lifetime (list (cons 'raw att-lifetime) (cons 'formatted (number->string att-lifetime))))
        (cons 'att-magic-cookie (list (cons 'raw att-magic-cookie) (cons 'formatted (fmt-hex att-magic-cookie))))
        (cons 'att-bandwidth (list (cons 'raw att-bandwidth) (cons 'formatted (number->string att-bandwidth))))
        (cons 'att-data (list (cons 'raw att-data) (cons 'formatted (fmt-bytes att-data))))
        (cons 'att-unknown (list (cons 'raw att-unknown) (cons 'formatted (fmt-hex att-unknown))))
        (cons 'att-server-string (list (cons 'raw att-server-string) (cons 'formatted (utf8->string att-server-string))))
        (cons 'att-xor-port (list (cons 'raw att-xor-port) (cons 'formatted (number->string att-xor-port))))
        (cons 'att-xor-ipv4 (list (cons 'raw att-xor-ipv4) (cons 'formatted (fmt-ipv4 att-xor-ipv4))))
        (cons 'att-xor-ipv6 (list (cons 'raw att-xor-ipv6) (cons 'formatted (fmt-ipv6-address att-xor-ipv6))))
        (cons 'att-connection-request-binding (list (cons 'raw att-connection-request-binding) (cons 'formatted (utf8->string att-connection-request-binding))))
        (cons 'att-padding (list (cons 'raw att-padding) (cons 'formatted (number->string att-padding))))
        )))

    (catch (e)
      (err (str "CLASSICSTUN parse error: " e)))))

;; dissect-classicstun: parse CLASSICSTUN from bytevector
;; Returns (ok fields-alist) or (err message)