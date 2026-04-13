;; packet-dsi.c
;; Routines for dsi packet dissection
;; Copyright 2001, Randy McEoin <rmceoin@pe.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-pop.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dsi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dsi.c

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
(def (dissect-dsi buffer)
  "Data Stream Interface"
  (try
    (let* (
           (open-len (unwrap (read-u8 buffer 0)))
           (open-quantum (unwrap (read-u32be buffer 0)))
           (replay-cache-size (unwrap (read-u32be buffer 0)))
           (open-option (unwrap (slice buffer 0 1)))
           (attn-flag-shutdown (unwrap (read-u8 buffer 0)))
           (attn-flag-crash (unwrap (read-u8 buffer 0)))
           (attn-flag-msg (unwrap (read-u8 buffer 0)))
           (attn-flag-reconnect (unwrap (read-u8 buffer 0)))
           (attn-flag-time (unwrap (read-u16be buffer 0)))
           (attn-flag-bitmap (unwrap (read-u16be buffer 0)))
           (requestid (unwrap (read-u16be buffer 2)))
           (offset (unwrap (read-u32be buffer 4)))
           (reserved (unwrap (read-u32be buffer 12)))
           )

      (ok (list
        (cons 'open-len (list (cons 'raw open-len) (cons 'formatted (number->string open-len))))
        (cons 'open-quantum (list (cons 'raw open-quantum) (cons 'formatted (number->string open-quantum))))
        (cons 'replay-cache-size (list (cons 'raw replay-cache-size) (cons 'formatted (number->string replay-cache-size))))
        (cons 'open-option (list (cons 'raw open-option) (cons 'formatted (fmt-bytes open-option))))
        (cons 'attn-flag-shutdown (list (cons 'raw attn-flag-shutdown) (cons 'formatted (number->string attn-flag-shutdown))))
        (cons 'attn-flag-crash (list (cons 'raw attn-flag-crash) (cons 'formatted (number->string attn-flag-crash))))
        (cons 'attn-flag-msg (list (cons 'raw attn-flag-msg) (cons 'formatted (number->string attn-flag-msg))))
        (cons 'attn-flag-reconnect (list (cons 'raw attn-flag-reconnect) (cons 'formatted (number->string attn-flag-reconnect))))
        (cons 'attn-flag-time (list (cons 'raw attn-flag-time) (cons 'formatted (number->string attn-flag-time))))
        (cons 'attn-flag-bitmap (list (cons 'raw attn-flag-bitmap) (cons 'formatted (fmt-hex attn-flag-bitmap))))
        (cons 'requestid (list (cons 'raw requestid) (cons 'formatted (number->string requestid))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (number->string offset))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        )))

    (catch (e)
      (err (str "DSI parse error: " e)))))

;; dissect-dsi: parse DSI from bytevector
;; Returns (ok fields-alist) or (err message)