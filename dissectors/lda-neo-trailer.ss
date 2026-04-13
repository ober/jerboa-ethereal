;; packet-lda-neo-trailer.c
;; Routines for LDA Neo Device trailer dissection
;; Vladimir Arustamov <vladimir@ldatech.com>
;;
;; Copyright 2025 LDA Technologies https://ldatech.com
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lda-neo-trailer.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lda_neo_trailer.c

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
(def (dissect-lda-neo-trailer buffer)
  "LDA Neo Device trailer"
  (try
    (let* (
           (neo-trailer-seq-num (unwrap (read-u16be buffer 0)))
           (neo-trailer-crc-invalid (unwrap (read-u8 buffer 0)))
           (neo-trailer-dev-id (unwrap (read-u8 buffer 0)))
           (neo-trailer-pcs-code (unwrap (read-u8 buffer 0)))
           (neo-trailer-pcs-code-pos (unwrap (read-u8 buffer 0)))
           (neo-trailer-port-id (unwrap (read-u8 buffer 0)))
           (neo-trailer-port-preamble-lane (unwrap (read-u8 buffer 0)))
           (neo-trailer-timestamp (unwrap (slice buffer 0 1)))
           (neo-trailer-nanosec (unwrap (read-u64be buffer 0)))
           (neo-trailer-picosec (unwrap (read-u16be buffer 0)))
           (neo-trailer-sig (unwrap (slice buffer 8 1)))
           )

      (ok (list
        (cons 'neo-trailer-seq-num (list (cons 'raw neo-trailer-seq-num) (cons 'formatted (number->string neo-trailer-seq-num))))
        (cons 'neo-trailer-crc-invalid (list (cons 'raw neo-trailer-crc-invalid) (cons 'formatted (number->string neo-trailer-crc-invalid))))
        (cons 'neo-trailer-dev-id (list (cons 'raw neo-trailer-dev-id) (cons 'formatted (number->string neo-trailer-dev-id))))
        (cons 'neo-trailer-pcs-code (list (cons 'raw neo-trailer-pcs-code) (cons 'formatted (number->string neo-trailer-pcs-code))))
        (cons 'neo-trailer-pcs-code-pos (list (cons 'raw neo-trailer-pcs-code-pos) (cons 'formatted (number->string neo-trailer-pcs-code-pos))))
        (cons 'neo-trailer-port-id (list (cons 'raw neo-trailer-port-id) (cons 'formatted (number->string neo-trailer-port-id))))
        (cons 'neo-trailer-port-preamble-lane (list (cons 'raw neo-trailer-port-preamble-lane) (cons 'formatted (number->string neo-trailer-port-preamble-lane))))
        (cons 'neo-trailer-timestamp (list (cons 'raw neo-trailer-timestamp) (cons 'formatted (fmt-bytes neo-trailer-timestamp))))
        (cons 'neo-trailer-nanosec (list (cons 'raw neo-trailer-nanosec) (cons 'formatted (number->string neo-trailer-nanosec))))
        (cons 'neo-trailer-picosec (list (cons 'raw neo-trailer-picosec) (cons 'formatted (number->string neo-trailer-picosec))))
        (cons 'neo-trailer-sig (list (cons 'raw neo-trailer-sig) (cons 'formatted (utf8->string neo-trailer-sig))))
        )))

    (catch (e)
      (err (str "LDA-NEO-TRAILER parse error: " e)))))

;; dissect-lda-neo-trailer: parse LDA-NEO-TRAILER from bytevector
;; Returns (ok fields-alist) or (err message)