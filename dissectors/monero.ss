;; packet-monero.c
;; Routines for Monero protocol dissection
;; Copyright 2023, snicket2100 <snicket2100@protonmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/monero.ss
;; Auto-generated from wireshark/epan/dissectors/packet-monero.c

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
(def (dissect-monero buffer)
  "Monero protocol"
  (try
    (let* (
           (signature (unwrap (read-u64be buffer 0)))
           (payload-magic (unwrap (slice buffer 0 9)))
           (payload-item (unwrap (slice buffer 0 1)))
           (payload-item-key (unwrap (slice buffer 1 1)))
           (payload-item-size (unwrap (read-u64be buffer 2)))
           (length (unwrap (read-u64be buffer 8)))
           (payload-item-value-int32 (unwrap (read-u32be buffer 10)))
           (payload-item-value-int16 (unwrap (read-u16be buffer 14)))
           (havetoreturn (unwrap (read-u8 buffer 16)))
           (payload-item-value-int8 (unwrap (read-u8 buffer 16)))
           (payload-item-value-uint64 (unwrap (read-u64be buffer 17)))
           (return-code (unwrap (read-u32be buffer 21)))
           (flags (unwrap (read-u32le buffer 25)))
           (flags-request (extract-bits flags 0x1 0))
           (flags-response (extract-bits flags 0x2 1))
           (flags-start-fragment (extract-bits flags 0x4 2))
           (flags-end-fragment (extract-bits flags 0x8 3))
           (flags-reserved (extract-bits flags 0xFFFFFFF0 4))
           (payload-item-value-uint32 (unwrap (read-u32be buffer 25)))
           (protocol (unwrap (read-u32be buffer 29)))
           (payload-item-value-uint16 (unwrap (read-u16be buffer 29)))
           (payload-item-value-uint8 (unwrap (read-u8 buffer 31)))
           (payload-item-value-float64 (unwrap (read-u64be buffer 32)))
           (payload-item-length (unwrap (read-u64be buffer 40)))
           (payload-item-value-int64 (unwrap (read-u64be buffer 40)))
           )

      (ok (list
        (cons 'signature (list (cons 'raw signature) (cons 'formatted (fmt-hex signature))))
        (cons 'payload-magic (list (cons 'raw payload-magic) (cons 'formatted (fmt-bytes payload-magic))))
        (cons 'payload-item (list (cons 'raw payload-item) (cons 'formatted (fmt-bytes payload-item))))
        (cons 'payload-item-key (list (cons 'raw payload-item-key) (cons 'formatted (utf8->string payload-item-key))))
        (cons 'payload-item-size (list (cons 'raw payload-item-size) (cons 'formatted (number->string payload-item-size))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'payload-item-value-int32 (list (cons 'raw payload-item-value-int32) (cons 'formatted (number->string payload-item-value-int32))))
        (cons 'payload-item-value-int16 (list (cons 'raw payload-item-value-int16) (cons 'formatted (number->string payload-item-value-int16))))
        (cons 'havetoreturn (list (cons 'raw havetoreturn) (cons 'formatted (number->string havetoreturn))))
        (cons 'payload-item-value-int8 (list (cons 'raw payload-item-value-int8) (cons 'formatted (number->string payload-item-value-int8))))
        (cons 'payload-item-value-uint64 (list (cons 'raw payload-item-value-uint64) (cons 'formatted (number->string payload-item-value-uint64))))
        (cons 'return-code (list (cons 'raw return-code) (cons 'formatted (number->string return-code))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (number->string flags))))
        (cons 'flags-request (list (cons 'raw flags-request) (cons 'formatted (if (= flags-request 0) "Not set" "Set"))))
        (cons 'flags-response (list (cons 'raw flags-response) (cons 'formatted (if (= flags-response 0) "Not set" "Set"))))
        (cons 'flags-start-fragment (list (cons 'raw flags-start-fragment) (cons 'formatted (if (= flags-start-fragment 0) "Not set" "Set"))))
        (cons 'flags-end-fragment (list (cons 'raw flags-end-fragment) (cons 'formatted (if (= flags-end-fragment 0) "Not set" "Set"))))
        (cons 'flags-reserved (list (cons 'raw flags-reserved) (cons 'formatted (if (= flags-reserved 0) "Not set" "Set"))))
        (cons 'payload-item-value-uint32 (list (cons 'raw payload-item-value-uint32) (cons 'formatted (number->string payload-item-value-uint32))))
        (cons 'protocol (list (cons 'raw protocol) (cons 'formatted (number->string protocol))))
        (cons 'payload-item-value-uint16 (list (cons 'raw payload-item-value-uint16) (cons 'formatted (number->string payload-item-value-uint16))))
        (cons 'payload-item-value-uint8 (list (cons 'raw payload-item-value-uint8) (cons 'formatted (number->string payload-item-value-uint8))))
        (cons 'payload-item-value-float64 (list (cons 'raw payload-item-value-float64) (cons 'formatted (number->string payload-item-value-float64))))
        (cons 'payload-item-length (list (cons 'raw payload-item-length) (cons 'formatted (number->string payload-item-length))))
        (cons 'payload-item-value-int64 (list (cons 'raw payload-item-value-int64) (cons 'formatted (number->string payload-item-value-int64))))
        )))

    (catch (e)
      (err (str "MONERO parse error: " e)))))

;; dissect-monero: parse MONERO from bytevector
;; Returns (ok fields-alist) or (err message)