;; packet-linx.c
;; Routines for LINX packet dissection
;;
;; Copyright 2006, Martin Peylo <martin.peylo@siemens.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/linx.ss
;; Auto-generated from wireshark/epan/dissectors/packet-linx.c

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
(def (dissect-linx buffer)
  "ENEA LINX"
  (try
    (let* (
           (tcp-oob (unwrap (read-u32be buffer 0)))
           (tcp-version (unwrap (read-u32be buffer 0)))
           (tcp-src (unwrap (read-u32be buffer 4)))
           (tcp-dst (unwrap (read-u32be buffer 8)))
           (tcp-size (unwrap (read-u32be buffer 12)))
           (tcp-rlnh-msg-reserved (unwrap (read-u32be buffer 20)))
           (tcp-rlnh-name (unwrap (slice buffer 32 1)))
           (tcp-rlnh-version (unwrap (read-u32be buffer 40)))
           (tcp-rlnh-feat-neg-str (unwrap (slice buffer 48 1)))
           (tcp-rlnh-src-linkaddr (unwrap (read-u32be buffer 48)))
           (tcp-rlnh-peer-linkaddr (unwrap (read-u32be buffer 52)))
           (tcp-payload (unwrap (slice buffer 52 1)))
           )

      (ok (list
        (cons 'tcp-oob (list (cons 'raw tcp-oob) (cons 'formatted (number->string tcp-oob))))
        (cons 'tcp-version (list (cons 'raw tcp-version) (cons 'formatted (number->string tcp-version))))
        (cons 'tcp-src (list (cons 'raw tcp-src) (cons 'formatted (number->string tcp-src))))
        (cons 'tcp-dst (list (cons 'raw tcp-dst) (cons 'formatted (number->string tcp-dst))))
        (cons 'tcp-size (list (cons 'raw tcp-size) (cons 'formatted (number->string tcp-size))))
        (cons 'tcp-rlnh-msg-reserved (list (cons 'raw tcp-rlnh-msg-reserved) (cons 'formatted (number->string tcp-rlnh-msg-reserved))))
        (cons 'tcp-rlnh-name (list (cons 'raw tcp-rlnh-name) (cons 'formatted (utf8->string tcp-rlnh-name))))
        (cons 'tcp-rlnh-version (list (cons 'raw tcp-rlnh-version) (cons 'formatted (number->string tcp-rlnh-version))))
        (cons 'tcp-rlnh-feat-neg-str (list (cons 'raw tcp-rlnh-feat-neg-str) (cons 'formatted (utf8->string tcp-rlnh-feat-neg-str))))
        (cons 'tcp-rlnh-src-linkaddr (list (cons 'raw tcp-rlnh-src-linkaddr) (cons 'formatted (number->string tcp-rlnh-src-linkaddr))))
        (cons 'tcp-rlnh-peer-linkaddr (list (cons 'raw tcp-rlnh-peer-linkaddr) (cons 'formatted (number->string tcp-rlnh-peer-linkaddr))))
        (cons 'tcp-payload (list (cons 'raw tcp-payload) (cons 'formatted (fmt-bytes tcp-payload))))
        )))

    (catch (e)
      (err (str "LINX parse error: " e)))))

;; dissect-linx: parse LINX from bytevector
;; Returns (ok fields-alist) or (err message)