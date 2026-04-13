;; packet-lsdp.c
;; Dissector for Lenbrook Service Discovery Protocol
;;
;; Copyright (c) 2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lsdp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lsdp.c

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
(def (dissect-lsdp buffer)
  "Lenbrook Service Discovery Protocol"
  (try
    (let* (
           (header-length (unwrap (read-u8 buffer 0)))
           (node-id (unwrap (slice buffer 1 1)))
           (node-id-mac (unwrap (slice buffer 1 6)))
           (header-magic-word (unwrap (slice buffer 1 4)))
           (query-count (unwrap (read-u8 buffer 3)))
           (header-proto-version (unwrap (read-u8 buffer 5)))
           (announce-addr-length (unwrap (read-u8 buffer 8)))
           (announce-addr-ipv4 (unwrap (read-u32be buffer 9)))
           (announce-addr-ipv6 (unwrap (slice buffer 9 16)))
           (announce-count (unwrap (read-u8 buffer 9)))
           (announce-record-count (unwrap (read-u8 buffer 12)))
           (announce-record-txt-key-length (unwrap (read-u8 buffer 13)))
           (announce-record-txt-key (unwrap (slice buffer 14 1)))
           (announce-record-txt-value-length (unwrap (read-u8 buffer 14)))
           (announce-record-txt-value (unwrap (slice buffer 15 1)))
           (msg-length (unwrap (read-u8 buffer 15)))
           (delete-count (unwrap (read-u8 buffer 17)))
           (node-id-length (unwrap (read-u8 buffer 25)))
           )

      (ok (list
        (cons 'header-length (list (cons 'raw header-length) (cons 'formatted (number->string header-length))))
        (cons 'node-id (list (cons 'raw node-id) (cons 'formatted (fmt-bytes node-id))))
        (cons 'node-id-mac (list (cons 'raw node-id-mac) (cons 'formatted (fmt-mac node-id-mac))))
        (cons 'header-magic-word (list (cons 'raw header-magic-word) (cons 'formatted (utf8->string header-magic-word))))
        (cons 'query-count (list (cons 'raw query-count) (cons 'formatted (number->string query-count))))
        (cons 'header-proto-version (list (cons 'raw header-proto-version) (cons 'formatted (number->string header-proto-version))))
        (cons 'announce-addr-length (list (cons 'raw announce-addr-length) (cons 'formatted (number->string announce-addr-length))))
        (cons 'announce-addr-ipv4 (list (cons 'raw announce-addr-ipv4) (cons 'formatted (fmt-ipv4 announce-addr-ipv4))))
        (cons 'announce-addr-ipv6 (list (cons 'raw announce-addr-ipv6) (cons 'formatted (fmt-ipv6-address announce-addr-ipv6))))
        (cons 'announce-count (list (cons 'raw announce-count) (cons 'formatted (number->string announce-count))))
        (cons 'announce-record-count (list (cons 'raw announce-record-count) (cons 'formatted (number->string announce-record-count))))
        (cons 'announce-record-txt-key-length (list (cons 'raw announce-record-txt-key-length) (cons 'formatted (number->string announce-record-txt-key-length))))
        (cons 'announce-record-txt-key (list (cons 'raw announce-record-txt-key) (cons 'formatted (utf8->string announce-record-txt-key))))
        (cons 'announce-record-txt-value-length (list (cons 'raw announce-record-txt-value-length) (cons 'formatted (number->string announce-record-txt-value-length))))
        (cons 'announce-record-txt-value (list (cons 'raw announce-record-txt-value) (cons 'formatted (utf8->string announce-record-txt-value))))
        (cons 'msg-length (list (cons 'raw msg-length) (cons 'formatted (number->string msg-length))))
        (cons 'delete-count (list (cons 'raw delete-count) (cons 'formatted (number->string delete-count))))
        (cons 'node-id-length (list (cons 'raw node-id-length) (cons 'formatted (number->string node-id-length))))
        )))

    (catch (e)
      (err (str "LSDP parse error: " e)))))

;; dissect-lsdp: parse LSDP from bytevector
;; Returns (ok fields-alist) or (err message)