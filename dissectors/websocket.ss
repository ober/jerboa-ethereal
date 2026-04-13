;; packet-websocket.c
;; Routines for WebSocket dissection
;; Copyright 2012, Alexis La Goutte <alexis.lagoutte@gmail.com>
;; 2015, Peter Wu <peter@lekensteyn.nl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/websocket.ss
;; Auto-generated from wireshark/epan/dissectors/packet-websocket.c
;; RFC 6455

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
(def (dissect-websocket buffer)
  "WebSocket"
  (try
    (let* (
           (pmc (unwrap (read-u8 buffer 0)))
           (reserved (unwrap (read-u8 buffer 0)))
           (fin (unwrap (read-u8 buffer 0)))
           (payload-length (unwrap (read-u8 buffer 1)))
           (mask (unwrap (read-u8 buffer 1)))
           (payload-length-ext-64 (unwrap (read-u64be buffer 2)))
           (payload-length-ext-16 (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'pmc (list (cons 'raw pmc) (cons 'formatted (number->string pmc))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'fin (list (cons 'raw fin) (cons 'formatted (number->string fin))))
        (cons 'payload-length (list (cons 'raw payload-length) (cons 'formatted (number->string payload-length))))
        (cons 'mask (list (cons 'raw mask) (cons 'formatted (number->string mask))))
        (cons 'payload-length-ext-64 (list (cons 'raw payload-length-ext-64) (cons 'formatted (number->string payload-length-ext-64))))
        (cons 'payload-length-ext-16 (list (cons 'raw payload-length-ext-16) (cons 'formatted (number->string payload-length-ext-16))))
        )))

    (catch (e)
      (err (str "WEBSOCKET parse error: " e)))))

;; dissect-websocket: parse WEBSOCKET from bytevector
;; Returns (ok fields-alist) or (err message)