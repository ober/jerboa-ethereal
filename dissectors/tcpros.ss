;; packet-tcpros.c
;; Routines for Robot Operating System TCP protocol (TCPROS)
;; Copyright 2015, Guillaume Autran  (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tcpros.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tcpros.c

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
(def (dissect-tcpros buffer)
  "TCP based Robot Operating System protocol (TCPROS)"
  (try
    (let* (
           (connection-header-field-length (unwrap (read-u32be buffer 0)))
           (connection-header-field-data (unwrap (slice buffer 0 1)))
           (connection-header-field-name (unwrap (slice buffer 0 1)))
           (connection-header (unwrap (slice buffer 0 1)))
           (connection-header-length (unwrap (read-u32be buffer 0)))
           (connection-header-content (unwrap (slice buffer 0 1)))
           (message-header-stamp-sec (unwrap (read-u32be buffer 0)))
           (message-header-stamp-nsec (unwrap (read-u32be buffer 0)))
           (clock (unwrap (slice buffer 0 1)))
           (clock-length (unwrap (read-u32be buffer 0)))
           (message-header (unwrap (slice buffer 0 1)))
           (message-header-seq (unwrap (read-u32be buffer 0)))
           (message-header-frame-length (unwrap (read-u32be buffer 0)))
           (message-header-frame-value (unwrap (slice buffer 0 1)))
           (message (unwrap (slice buffer 0 1)))
           (message-length (unwrap (read-u32be buffer 0)))
           (message-body (unwrap (slice buffer 0 1)))
           (message-payload (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'connection-header-field-length (list (cons 'raw connection-header-field-length) (cons 'formatted (number->string connection-header-field-length))))
        (cons 'connection-header-field-data (list (cons 'raw connection-header-field-data) (cons 'formatted (utf8->string connection-header-field-data))))
        (cons 'connection-header-field-name (list (cons 'raw connection-header-field-name) (cons 'formatted (utf8->string connection-header-field-name))))
        (cons 'connection-header (list (cons 'raw connection-header) (cons 'formatted (fmt-bytes connection-header))))
        (cons 'connection-header-length (list (cons 'raw connection-header-length) (cons 'formatted (number->string connection-header-length))))
        (cons 'connection-header-content (list (cons 'raw connection-header-content) (cons 'formatted (fmt-bytes connection-header-content))))
        (cons 'message-header-stamp-sec (list (cons 'raw message-header-stamp-sec) (cons 'formatted (number->string message-header-stamp-sec))))
        (cons 'message-header-stamp-nsec (list (cons 'raw message-header-stamp-nsec) (cons 'formatted (number->string message-header-stamp-nsec))))
        (cons 'clock (list (cons 'raw clock) (cons 'formatted (fmt-bytes clock))))
        (cons 'clock-length (list (cons 'raw clock-length) (cons 'formatted (number->string clock-length))))
        (cons 'message-header (list (cons 'raw message-header) (cons 'formatted (fmt-bytes message-header))))
        (cons 'message-header-seq (list (cons 'raw message-header-seq) (cons 'formatted (number->string message-header-seq))))
        (cons 'message-header-frame-length (list (cons 'raw message-header-frame-length) (cons 'formatted (number->string message-header-frame-length))))
        (cons 'message-header-frame-value (list (cons 'raw message-header-frame-value) (cons 'formatted (utf8->string message-header-frame-value))))
        (cons 'message (list (cons 'raw message) (cons 'formatted (fmt-bytes message))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'message-body (list (cons 'raw message-body) (cons 'formatted (fmt-bytes message-body))))
        (cons 'message-payload (list (cons 'raw message-payload) (cons 'formatted (fmt-bytes message-payload))))
        )))

    (catch (e)
      (err (str "TCPROS parse error: " e)))))

;; dissect-tcpros: parse TCPROS from bytevector
;; Returns (ok fields-alist) or (err message)