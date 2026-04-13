;; packet-tftp.c
;; Routines for tftp packet dissection
;;
;; Richard Sharpe <rsharpe@ns.aus.com>
;; Craig Newell <CraigN@cheque.uq.edu.au>
;; RFC2347 TFTP Option Extension
;; Joerg Mayer (see AUTHORS file)
;; RFC2348 TFTP Blocksize Option
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-bootp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tftp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tftp.c
;; RFC 2347

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
(def (dissect-tftp buffer)
  "Trivial File Transfer Protocol"
  (try
    (let* (
           (full-blocknum (unwrap (read-u32be buffer 0)))
           (request-frame (unwrap (read-u32be buffer 0)))
           (source-file (unwrap (slice buffer 2 1)))
           (transfer-type (unwrap (slice buffer 2 1)))
           (destination-file (unwrap (slice buffer 2 1)))
           (blocknum (unwrap (read-u16be buffer 2)))
           (nextwindowsize (unwrap (read-u16be buffer 6)))
           (error-string (unwrap (slice buffer 8 1)))
           (data (unwrap (slice buffer 8 1)))
           )

      (ok (list
        (cons 'full-blocknum (list (cons 'raw full-blocknum) (cons 'formatted (number->string full-blocknum))))
        (cons 'request-frame (list (cons 'raw request-frame) (cons 'formatted (number->string request-frame))))
        (cons 'source-file (list (cons 'raw source-file) (cons 'formatted (utf8->string source-file))))
        (cons 'transfer-type (list (cons 'raw transfer-type) (cons 'formatted (utf8->string transfer-type))))
        (cons 'destination-file (list (cons 'raw destination-file) (cons 'formatted (utf8->string destination-file))))
        (cons 'blocknum (list (cons 'raw blocknum) (cons 'formatted (number->string blocknum))))
        (cons 'nextwindowsize (list (cons 'raw nextwindowsize) (cons 'formatted (number->string nextwindowsize))))
        (cons 'error-string (list (cons 'raw error-string) (cons 'formatted (utf8->string error-string))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        )))

    (catch (e)
      (err (str "TFTP parse error: " e)))))

;; dissect-tftp: parse TFTP from bytevector
;; Returns (ok fields-alist) or (err message)