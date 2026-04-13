;; packet-sigcomp.c
;; Routines for Signaling Compression (SigComp) dissection.
;; Copyright 2004-2005, Anders Broman <anders.broman@ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; References:
;; https://www.ietf.org/rfc/rfc3320
;; https://www.ietf.org/rfc/rfc3321
;; https://www.ietf.org/rfc/rfc4077
;; Useful links :
;; https://tools.ietf.org/html/draft-ietf-rohc-sigcomp-impl-guide-10
;; https://tools.ietf.org/html/draft-ietf-rohc-sigcomp-sip-01
;;

;; jerboa-ethereal/dissectors/sigcomp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sigcomp.c

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
(def (dissect-sigcomp buffer)
  "Signaling Compression"
  (try
    (let* (
           (accessing-state (unwrap (slice buffer 0 1)))
           (addr-value (unwrap (read-u8 buffer 0)))
           (copying-bytes-literally (unwrap (slice buffer 0 1)))
           (t-bit (unwrap (read-u8 buffer 0)))
           (returned-feedback-item-len (unwrap (read-u8 buffer 0)))
           (returned-feedback-item (unwrap (slice buffer 0 1)))
           (partial-state (unwrap (slice buffer 0 1)))
           (remaining-message-bytes (unwrap (read-u32be buffer 0)))
           (nack-ver (unwrap (read-u8 buffer 0)))
           (nack-pc (unwrap (read-u16be buffer 0)))
           (nack-sha1 (unwrap (slice buffer 0 1)))
           (nack-state-id (unwrap (slice buffer 0 1)))
           (nack-cycles-per-bit (unwrap (read-u8 buffer 0)))
           (nack-memory-size (unwrap (read-u16be buffer 0)))
           (code-len (unwrap (read-u16be buffer 0)))
           (remaining-sigcomp-message (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'accessing-state (list (cons 'raw accessing-state) (cons 'formatted (fmt-bytes accessing-state))))
        (cons 'addr-value (list (cons 'raw addr-value) (cons 'formatted (fmt-hex addr-value))))
        (cons 'copying-bytes-literally (list (cons 'raw copying-bytes-literally) (cons 'formatted (fmt-bytes copying-bytes-literally))))
        (cons 't-bit (list (cons 'raw t-bit) (cons 'formatted (number->string t-bit))))
        (cons 'returned-feedback-item-len (list (cons 'raw returned-feedback-item-len) (cons 'formatted (number->string returned-feedback-item-len))))
        (cons 'returned-feedback-item (list (cons 'raw returned-feedback-item) (cons 'formatted (fmt-bytes returned-feedback-item))))
        (cons 'partial-state (list (cons 'raw partial-state) (cons 'formatted (utf8->string partial-state))))
        (cons 'remaining-message-bytes (list (cons 'raw remaining-message-bytes) (cons 'formatted (number->string remaining-message-bytes))))
        (cons 'nack-ver (list (cons 'raw nack-ver) (cons 'formatted (number->string nack-ver))))
        (cons 'nack-pc (list (cons 'raw nack-pc) (cons 'formatted (number->string nack-pc))))
        (cons 'nack-sha1 (list (cons 'raw nack-sha1) (cons 'formatted (fmt-bytes nack-sha1))))
        (cons 'nack-state-id (list (cons 'raw nack-state-id) (cons 'formatted (fmt-bytes nack-state-id))))
        (cons 'nack-cycles-per-bit (list (cons 'raw nack-cycles-per-bit) (cons 'formatted (number->string nack-cycles-per-bit))))
        (cons 'nack-memory-size (list (cons 'raw nack-memory-size) (cons 'formatted (number->string nack-memory-size))))
        (cons 'code-len (list (cons 'raw code-len) (cons 'formatted (fmt-hex code-len))))
        (cons 'remaining-sigcomp-message (list (cons 'raw remaining-sigcomp-message) (cons 'formatted (fmt-bytes remaining-sigcomp-message))))
        )))

    (catch (e)
      (err (str "SIGCOMP parse error: " e)))))

;; dissect-sigcomp: parse SIGCOMP from bytevector
;; Returns (ok fields-alist) or (err message)