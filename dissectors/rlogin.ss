;; packet-rlogin.c
;; Routines for unix rlogin packet dissection
;; Copyright 2000, Jeffrey C. Foster <jfoste[AT]woodward.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Based upon RFC-1282 - BSD Rlogin
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rlogin.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rlogin.c

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
(def (dissect-rlogin buffer)
  "Rlogin Protocol"
  (try
    (let* (
           (info-received-flag (unwrap (read-u8 buffer 0)))
           (startup-flag (unwrap (read-u8 buffer 0)))
           (info (unwrap (slice buffer 0 1)))
           (info-client-user-name (unwrap (slice buffer 0 1)))
           (info-server-user-name (unwrap (slice buffer 0 1)))
           (info-terminal-type (unwrap (slice buffer 0 1)))
           (info-terminal-speed (unwrap (read-u32be buffer 0)))
           (cookie (unwrap (read-u16be buffer 0)))
           (info-ss (unwrap (slice buffer 2 2)))
           (info-rows (unwrap (read-u16be buffer 4)))
           (info-cols (unwrap (read-u16be buffer 6)))
           (info-x-pixels (unwrap (read-u16be buffer 8)))
           (info-y-pixels (unwrap (read-u16be buffer 10)))
           (hf-data (unwrap (slice buffer 12 1)))
           )

      (ok (list
        (cons 'info-received-flag (list (cons 'raw info-received-flag) (cons 'formatted (fmt-hex info-received-flag))))
        (cons 'startup-flag (list (cons 'raw startup-flag) (cons 'formatted (fmt-hex startup-flag))))
        (cons 'info (list (cons 'raw info) (cons 'formatted (utf8->string info))))
        (cons 'info-client-user-name (list (cons 'raw info-client-user-name) (cons 'formatted (utf8->string info-client-user-name))))
        (cons 'info-server-user-name (list (cons 'raw info-server-user-name) (cons 'formatted (utf8->string info-server-user-name))))
        (cons 'info-terminal-type (list (cons 'raw info-terminal-type) (cons 'formatted (utf8->string info-terminal-type))))
        (cons 'info-terminal-speed (list (cons 'raw info-terminal-speed) (cons 'formatted (number->string info-terminal-speed))))
        (cons 'cookie (list (cons 'raw cookie) (cons 'formatted (fmt-hex cookie))))
        (cons 'info-ss (list (cons 'raw info-ss) (cons 'formatted (utf8->string info-ss))))
        (cons 'info-rows (list (cons 'raw info-rows) (cons 'formatted (number->string info-rows))))
        (cons 'info-cols (list (cons 'raw info-cols) (cons 'formatted (number->string info-cols))))
        (cons 'info-x-pixels (list (cons 'raw info-x-pixels) (cons 'formatted (number->string info-x-pixels))))
        (cons 'info-y-pixels (list (cons 'raw info-y-pixels) (cons 'formatted (number->string info-y-pixels))))
        (cons 'hf-data (list (cons 'raw hf-data) (cons 'formatted (utf8->string hf-data))))
        )))

    (catch (e)
      (err (str "RLOGIN parse error: " e)))))

;; dissect-rlogin: parse RLOGIN from bytevector
;; Returns (ok fields-alist) or (err message)