;; packet-yami.c
;; Routines for YAMI dissection
;; Copyright 2010, Pawel Korbut
;; Copyright 2012, Jakub Zawadzki <darkjames-ws@darkjames.pl>
;;
;; Protocol documentation available at http://www.inspirel.com/yami4/book/B-2.html
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/yami.ss
;; Auto-generated from wireshark/epan/dissectors/packet-yami.c

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
(def (dissect-yami buffer)
  "YAMI Protocol"
  (try
    (let* (
           (message-id (unwrap (read-u32be buffer 0)))
           (frame-number (unwrap (read-u32be buffer 4)))
           (param-value-bool (unwrap (read-u8 buffer 8)))
           (message-header-size (unwrap (read-u32be buffer 8)))
           (frame-payload-size (unwrap (read-u32be buffer 12)))
           (param-value-int (unwrap (read-u32be buffer 56)))
           (param-value-long (unwrap (read-u64be buffer 64)))
           (param-value-double (unwrap (read-u64be buffer 76)))
           (items-count (unwrap (read-u32be buffer 92)))
           (params-count (unwrap (read-u32be buffer 104)))
           )

      (ok (list
        (cons 'message-id (list (cons 'raw message-id) (cons 'formatted (number->string message-id))))
        (cons 'frame-number (list (cons 'raw frame-number) (cons 'formatted (number->string frame-number))))
        (cons 'param-value-bool (list (cons 'raw param-value-bool) (cons 'formatted (number->string param-value-bool))))
        (cons 'message-header-size (list (cons 'raw message-header-size) (cons 'formatted (number->string message-header-size))))
        (cons 'frame-payload-size (list (cons 'raw frame-payload-size) (cons 'formatted (number->string frame-payload-size))))
        (cons 'param-value-int (list (cons 'raw param-value-int) (cons 'formatted (number->string param-value-int))))
        (cons 'param-value-long (list (cons 'raw param-value-long) (cons 'formatted (number->string param-value-long))))
        (cons 'param-value-double (list (cons 'raw param-value-double) (cons 'formatted (number->string param-value-double))))
        (cons 'items-count (list (cons 'raw items-count) (cons 'formatted (number->string items-count))))
        (cons 'params-count (list (cons 'raw params-count) (cons 'formatted (number->string params-count))))
        )))

    (catch (e)
      (err (str "YAMI parse error: " e)))))

;; dissect-yami: parse YAMI from bytevector
;; Returns (ok fields-alist) or (err message)