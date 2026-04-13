;; packet-ipxwan.c
;; Routines for NetWare IPX WAN Protocol
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ipxwan.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ipxwan.c
;; RFC 1362

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
(def (dissect-ipxwan buffer)
  "IPX WAN"
  (try
    (let* (
           (identifier (unwrap (slice buffer 0 4)))
           (node-id (unwrap (read-u32be buffer 5)))
           (sequence-number (unwrap (read-u8 buffer 9)))
           (num-options (unwrap (read-u8 buffer 10)))
           (option-data-len (unwrap (read-u16be buffer 13)))
           (router-name (unwrap (slice buffer 15 48)))
           (request-size (unwrap (read-u32be buffer 15)))
           (node-number (unwrap (slice buffer 15 6)))
           (compression-options (unwrap (read-u8 buffer 15)))
           (compression-slots (unwrap (read-u8 buffer 15)))
           (compression-parameters (unwrap (slice buffer 15 1)))
           (padding (unwrap (slice buffer 15 1)))
           (option-value (unwrap (slice buffer 15 1)))
           )

      (ok (list
        (cons 'identifier (list (cons 'raw identifier) (cons 'formatted (utf8->string identifier))))
        (cons 'node-id (list (cons 'raw node-id) (cons 'formatted (fmt-hex node-id))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (number->string sequence-number))))
        (cons 'num-options (list (cons 'raw num-options) (cons 'formatted (number->string num-options))))
        (cons 'option-data-len (list (cons 'raw option-data-len) (cons 'formatted (number->string option-data-len))))
        (cons 'router-name (list (cons 'raw router-name) (cons 'formatted (utf8->string router-name))))
        (cons 'request-size (list (cons 'raw request-size) (cons 'formatted (number->string request-size))))
        (cons 'node-number (list (cons 'raw node-number) (cons 'formatted (fmt-mac node-number))))
        (cons 'compression-options (list (cons 'raw compression-options) (cons 'formatted (fmt-hex compression-options))))
        (cons 'compression-slots (list (cons 'raw compression-slots) (cons 'formatted (number->string compression-slots))))
        (cons 'compression-parameters (list (cons 'raw compression-parameters) (cons 'formatted (fmt-bytes compression-parameters))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'option-value (list (cons 'raw option-value) (cons 'formatted (fmt-bytes option-value))))
        )))

    (catch (e)
      (err (str "IPXWAN parse error: " e)))))

;; dissect-ipxwan: parse IPXWAN from bytevector
;; Returns (ok fields-alist) or (err message)