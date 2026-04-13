;; packet-h224.c
;; Routines for H.224 dissection
;; Copyright 2022, Anders Broman <anders.broman@ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/h224.ss
;; Auto-generated from wireshark/epan/dissectors/packet-h224.c
;; RFC 4573

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
(def (dissect-h224 buffer)
  "H.224"
  (try
    (let* (
           (extended-client-id-list (unwrap (read-u8 buffer 0)))
           (extended-client-id (unwrap (read-u8 buffer 0)))
           (non-standard-client (unwrap (read-u8 buffer 0)))
           (extension (unwrap (read-u8 buffer 1)))
           (q922-ctl (unwrap (read-u8 buffer 2)))
           (dta (unwrap (read-u16be buffer 3)))
           (client-id-manufacturer (unwrap (read-u8 buffer 4)))
           (standard-client-id (unwrap (read-u8 buffer 4)))
           (client-list-code (unwrap (read-u8 buffer 4)))
           (response-code (unwrap (read-u8 buffer 4)))
           (number-of-clients (unwrap (read-u8 buffer 4)))
           (ex-caps-bit (unwrap (read-u8 buffer 4)))
           (extra-caps-code (unwrap (read-u8 buffer 4)))
           (encoded-characters (unwrap (slice buffer 4 1)))
           (end-octet (unwrap (read-u8 buffer 4)))
           (message-reserved-b7b4 (unwrap (read-u8 buffer 4)))
           (message-timeout (unwrap (read-u8 buffer 4)))
           (other-client-data (unwrap (slice buffer 4 1)))
           (sta (unwrap (read-u16be buffer 5)))
           (reserved (unwrap (read-u8 buffer 7)))
           )

      (ok (list
        (cons 'extended-client-id-list (list (cons 'raw extended-client-id-list) (cons 'formatted (fmt-hex extended-client-id-list))))
        (cons 'extended-client-id (list (cons 'raw extended-client-id) (cons 'formatted (fmt-hex extended-client-id))))
        (cons 'non-standard-client (list (cons 'raw non-standard-client) (cons 'formatted (fmt-hex non-standard-client))))
        (cons 'extension (list (cons 'raw extension) (cons 'formatted (fmt-hex extension))))
        (cons 'q922-ctl (list (cons 'raw q922-ctl) (cons 'formatted (fmt-hex q922-ctl))))
        (cons 'dta (list (cons 'raw dta) (cons 'formatted (number->string dta))))
        (cons 'client-id-manufacturer (list (cons 'raw client-id-manufacturer) (cons 'formatted (fmt-hex client-id-manufacturer))))
        (cons 'standard-client-id (list (cons 'raw standard-client-id) (cons 'formatted (fmt-hex standard-client-id))))
        (cons 'client-list-code (list (cons 'raw client-list-code) (cons 'formatted (fmt-hex client-list-code))))
        (cons 'response-code (list (cons 'raw response-code) (cons 'formatted (fmt-hex response-code))))
        (cons 'number-of-clients (list (cons 'raw number-of-clients) (cons 'formatted (number->string number-of-clients))))
        (cons 'ex-caps-bit (list (cons 'raw ex-caps-bit) (cons 'formatted (number->string ex-caps-bit))))
        (cons 'extra-caps-code (list (cons 'raw extra-caps-code) (cons 'formatted (fmt-hex extra-caps-code))))
        (cons 'encoded-characters (list (cons 'raw encoded-characters) (cons 'formatted (utf8->string encoded-characters))))
        (cons 'end-octet (list (cons 'raw end-octet) (cons 'formatted (number->string end-octet))))
        (cons 'message-reserved-b7b4 (list (cons 'raw message-reserved-b7b4) (cons 'formatted (number->string message-reserved-b7b4))))
        (cons 'message-timeout (list (cons 'raw message-timeout) (cons 'formatted (number->string message-timeout))))
        (cons 'other-client-data (list (cons 'raw other-client-data) (cons 'formatted (fmt-bytes other-client-data))))
        (cons 'sta (list (cons 'raw sta) (cons 'formatted (number->string sta))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        )))

    (catch (e)
      (err (str "H224 parse error: " e)))))

;; dissect-h224: parse H224 from bytevector
;; Returns (ok fields-alist) or (err message)