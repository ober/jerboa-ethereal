;; packet-icep.c
;; Routines for "The ICE Protocol" dissection
;; Copyright 2004 _FF_
;; Francesco Fondelli <fondelli dot francesco, tiscali dot it>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/icep.ss
;; Auto-generated from wireshark/epan/dissectors/packet-icep.c

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
(def (dissect-icep buffer)
  "Internet Communications Engine Protocol"
  (try
    (let* (
           (magic-number (unwrap (slice buffer 0 4)))
           (protocol-major (unwrap (read-u8 buffer 4)))
           (protocol-minor (unwrap (read-u8 buffer 4)))
           (encoding-major (unwrap (read-u8 buffer 4)))
           (encoding-minor (unwrap (read-u8 buffer 4)))
           (message-size (unwrap (read-u32be buffer 4)))
           (context (unwrap (slice buffer 8 1)))
           (params-size (unwrap (read-u32be buffer 8)))
           (params-major (unwrap (read-u8 buffer 12)))
           (params-minor (unwrap (read-u8 buffer 13)))
           (request-id (unwrap (read-u32be buffer 28)))
           (reply-data (unwrap (slice buffer 32 1)))
           )

      (ok (list
        (cons 'magic-number (list (cons 'raw magic-number) (cons 'formatted (utf8->string magic-number))))
        (cons 'protocol-major (list (cons 'raw protocol-major) (cons 'formatted (number->string protocol-major))))
        (cons 'protocol-minor (list (cons 'raw protocol-minor) (cons 'formatted (number->string protocol-minor))))
        (cons 'encoding-major (list (cons 'raw encoding-major) (cons 'formatted (number->string encoding-major))))
        (cons 'encoding-minor (list (cons 'raw encoding-minor) (cons 'formatted (number->string encoding-minor))))
        (cons 'message-size (list (cons 'raw message-size) (cons 'formatted (number->string message-size))))
        (cons 'context (list (cons 'raw context) (cons 'formatted (utf8->string context))))
        (cons 'params-size (list (cons 'raw params-size) (cons 'formatted (number->string params-size))))
        (cons 'params-major (list (cons 'raw params-major) (cons 'formatted (number->string params-major))))
        (cons 'params-minor (list (cons 'raw params-minor) (cons 'formatted (number->string params-minor))))
        (cons 'request-id (list (cons 'raw request-id) (cons 'formatted (number->string request-id))))
        (cons 'reply-data (list (cons 'raw reply-data) (cons 'formatted (fmt-bytes reply-data))))
        )))

    (catch (e)
      (err (str "ICEP parse error: " e)))))

;; dissect-icep: parse ICEP from bytevector
;; Returns (ok fields-alist) or (err message)