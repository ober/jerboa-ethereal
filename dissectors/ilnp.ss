;; packet-ilnp.c
;; Routines for ILNP dissection
;; Copyright 2025, Shubh Sinhal <shubh.sinhal@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ilnp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ilnp.c
;; RFC 6740

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
(def (dissect-ilnp buffer)
  "Identifier-Locator Network Protocol"
  (try
    (let* (
           (stream (unwrap (read-u32be buffer 0)))
           (dst-ilv (unwrap (slice buffer 0 1)))
           (dst-nid (unwrap (slice buffer 0 1)))
           (dst-l64 (unwrap (slice buffer 0 1)))
           (ilv (unwrap (slice buffer 0 1)))
           (src-ilv (unwrap (slice buffer 0 1)))
           (nid (unwrap (slice buffer 0 1)))
           (src-nid (unwrap (slice buffer 0 1)))
           (l64 (unwrap (slice buffer 0 1)))
           (src-l64 (unwrap (slice buffer 0 1)))
           (nonce (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'stream (list (cons 'raw stream) (cons 'formatted (number->string stream))))
        (cons 'dst-ilv (list (cons 'raw dst-ilv) (cons 'formatted (utf8->string dst-ilv))))
        (cons 'dst-nid (list (cons 'raw dst-nid) (cons 'formatted (utf8->string dst-nid))))
        (cons 'dst-l64 (list (cons 'raw dst-l64) (cons 'formatted (utf8->string dst-l64))))
        (cons 'ilv (list (cons 'raw ilv) (cons 'formatted (utf8->string ilv))))
        (cons 'src-ilv (list (cons 'raw src-ilv) (cons 'formatted (utf8->string src-ilv))))
        (cons 'nid (list (cons 'raw nid) (cons 'formatted (utf8->string nid))))
        (cons 'src-nid (list (cons 'raw src-nid) (cons 'formatted (utf8->string src-nid))))
        (cons 'l64 (list (cons 'raw l64) (cons 'formatted (utf8->string l64))))
        (cons 'src-l64 (list (cons 'raw src-l64) (cons 'formatted (utf8->string src-l64))))
        (cons 'nonce (list (cons 'raw nonce) (cons 'formatted (fmt-bytes nonce))))
        )))

    (catch (e)
      (err (str "ILNP parse error: " e)))))

;; dissect-ilnp: parse ILNP from bytevector
;; Returns (ok fields-alist) or (err message)