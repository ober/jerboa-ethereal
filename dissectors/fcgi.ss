;; packet-fcgi.c
;; Routines for FastCGI dissection
;; Copyright 2010, Tom Hughes <tom@compton.nu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fcgi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fcgi.c

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
(def (dissect-fcgi buffer)
  "FastCGI"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (id (unwrap (read-u16be buffer 2)))
           (content-length (unwrap (read-u16be buffer 4)))
           (padding-length (unwrap (read-u8 buffer 6)))
           (content-data (unwrap (slice buffer 8 1)))
           (padding-data (unwrap (slice buffer 8 1)))
           (begin-request-flags (unwrap (read-u8 buffer 12)))
           (begin-request-keep-conn (unwrap (read-u8 buffer 12)))
           (end-request-app-status (unwrap (read-u32be buffer 18)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'content-length (list (cons 'raw content-length) (cons 'formatted (number->string content-length))))
        (cons 'padding-length (list (cons 'raw padding-length) (cons 'formatted (number->string padding-length))))
        (cons 'content-data (list (cons 'raw content-data) (cons 'formatted (fmt-bytes content-data))))
        (cons 'padding-data (list (cons 'raw padding-data) (cons 'formatted (fmt-bytes padding-data))))
        (cons 'begin-request-flags (list (cons 'raw begin-request-flags) (cons 'formatted (fmt-hex begin-request-flags))))
        (cons 'begin-request-keep-conn (list (cons 'raw begin-request-keep-conn) (cons 'formatted (number->string begin-request-keep-conn))))
        (cons 'end-request-app-status (list (cons 'raw end-request-app-status) (cons 'formatted (number->string end-request-app-status))))
        )))

    (catch (e)
      (err (str "FCGI parse error: " e)))))

;; dissect-fcgi: parse FCGI from bytevector
;; Returns (ok fields-alist) or (err message)