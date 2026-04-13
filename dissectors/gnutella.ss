;; packet-gnutella.c
;; Routines for gnutella dissection
;; Copyright 2001, B. Johannessen <bob@havoq.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gnutella.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gnutella.c

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
(def (dissect-gnutella buffer)
  "Gnutella Protocol"
  (try
    (let* (
           (pong-port (unwrap (read-u16be buffer 0)))
           (pong-ip (unwrap (read-u32be buffer 0)))
           (pong-files (unwrap (read-u32be buffer 0)))
           (pong-kbytes (unwrap (read-u32be buffer 0)))
           (query-min-speed (unwrap (read-u32be buffer 0)))
           (query-search (unwrap (slice buffer 0 1)))
           (queryhit-count (unwrap (read-u8 buffer 0)))
           (queryhit-port (unwrap (read-u16be buffer 0)))
           (queryhit-ip (unwrap (read-u32be buffer 0)))
           (queryhit-speed (unwrap (read-u32be buffer 0)))
           (push-servent-id (unwrap (slice buffer 0 1)))
           (push-index (unwrap (read-u32be buffer 0)))
           (push-ip (unwrap (read-u32be buffer 0)))
           (push-port (unwrap (read-u16be buffer 0)))
           )

      (ok (list
        (cons 'pong-port (list (cons 'raw pong-port) (cons 'formatted (fmt-port pong-port))))
        (cons 'pong-ip (list (cons 'raw pong-ip) (cons 'formatted (fmt-ipv4 pong-ip))))
        (cons 'pong-files (list (cons 'raw pong-files) (cons 'formatted (number->string pong-files))))
        (cons 'pong-kbytes (list (cons 'raw pong-kbytes) (cons 'formatted (number->string pong-kbytes))))
        (cons 'query-min-speed (list (cons 'raw query-min-speed) (cons 'formatted (number->string query-min-speed))))
        (cons 'query-search (list (cons 'raw query-search) (cons 'formatted (utf8->string query-search))))
        (cons 'queryhit-count (list (cons 'raw queryhit-count) (cons 'formatted (number->string queryhit-count))))
        (cons 'queryhit-port (list (cons 'raw queryhit-port) (cons 'formatted (fmt-port queryhit-port))))
        (cons 'queryhit-ip (list (cons 'raw queryhit-ip) (cons 'formatted (fmt-ipv4 queryhit-ip))))
        (cons 'queryhit-speed (list (cons 'raw queryhit-speed) (cons 'formatted (number->string queryhit-speed))))
        (cons 'push-servent-id (list (cons 'raw push-servent-id) (cons 'formatted (fmt-bytes push-servent-id))))
        (cons 'push-index (list (cons 'raw push-index) (cons 'formatted (number->string push-index))))
        (cons 'push-ip (list (cons 'raw push-ip) (cons 'formatted (fmt-ipv4 push-ip))))
        (cons 'push-port (list (cons 'raw push-port) (cons 'formatted (number->string push-port))))
        )))

    (catch (e)
      (err (str "GNUTELLA parse error: " e)))))

;; dissect-gnutella: parse GNUTELLA from bytevector
;; Returns (ok fields-alist) or (err message)