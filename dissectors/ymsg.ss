;; packet-ymsg.c
;; Routines for Yahoo Messenger YMSG protocol packet version 13 dissection
;; Copyright 2003, Wayne Parrott <wayne_p@pacific.net.au>
;; Copied from packet-yhoo.c and updated
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ymsg.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ymsg.c

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
(def (dissect-ymsg buffer)
  "Yahoo YMSG Messenger Protocol"
  (try
    (let* (
           (vendor (unwrap (read-u16be buffer 6)))
           (len (unwrap (read-u16be buffer 8)))
           (session-id (unwrap (read-u32be buffer 16)))
           (content (unwrap (slice buffer 20 1)))
           (content-line (unwrap (slice buffer 20 1)))
           (content-line-key (unwrap (slice buffer 20 1)))
           (version (unwrap (read-u16be buffer 21)))
           )

      (ok (list
        (cons 'vendor (list (cons 'raw vendor) (cons 'formatted (number->string vendor))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (fmt-hex session-id))))
        (cons 'content (list (cons 'raw content) (cons 'formatted (fmt-bytes content))))
        (cons 'content-line (list (cons 'raw content-line) (cons 'formatted (utf8->string content-line))))
        (cons 'content-line-key (list (cons 'raw content-line-key) (cons 'formatted (utf8->string content-line-key))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        )))

    (catch (e)
      (err (str "YMSG parse error: " e)))))

;; dissect-ymsg: parse YMSG from bytevector
;; Returns (ok fields-alist) or (err message)