;; packet-sapenqueue.c
;; Routines for SAP Enqueue (Enqueue Server) dissection
;; Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
;; Code contributed by SecureAuth Corp.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sapenqueue.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sapenqueue.c

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
(def (dissect-sapenqueue buffer)
  "SAP Enqueue Protocol"
  (try
    (let* (
           (server-admin-version (unwrap (read-u8 buffer 4)))
           (magic (unwrap (slice buffer 4 4)))
           (id (unwrap (read-u32be buffer 8)))
           (server-admin-flag (unwrap (read-u8 buffer 12)))
           (length (unwrap (read-u32be buffer 12)))
           (server-admin-length (unwrap (read-u32be buffer 13)))
           (length-frag (unwrap (read-u32be buffer 16)))
           (server-admin-flags (unwrap (read-u8 buffer 18)))
           (server-admin-rc (unwrap (read-u32be buffer 19)))
           (more-frags (unwrap (read-u8 buffer 22)))
           (server-admin-eyecatcher (unwrap (slice buffer 23 4)))
           (server-admin-trace-protocol-version (unwrap (read-u8 buffer 27)))
           (server-admin-trace-level (unwrap (read-u32be buffer 35)))
           (server-admin-trace-logging (unwrap (read-u8 buffer 43)))
           (server-admin-trace-max-file-size (unwrap (read-u32be buffer 44)))
           (server-admin-trace-nopatterns (unwrap (read-u32be buffer 48)))
           (server-admin-trace-unknown (unwrap (slice buffer 52 8)))
           (server-admin-trace-pattern-len (unwrap (read-u8 buffer 64)))
           (server-admin-trace-pattern-value (unwrap (slice buffer 65 1)))
           (server-admin-trace-eyecatcher (unwrap (slice buffer 65 4)))
           (conn-admin-params-count (unwrap (read-u32be buffer 65)))
           (conn-admin-param-name (unwrap (slice buffer 73 1)))
           (conn-admin-param-len (unwrap (read-u32be buffer 77)))
           (conn-admin-param-value (unwrap (read-u32be buffer 81)))
           )

      (ok (list
        (cons 'server-admin-version (list (cons 'raw server-admin-version) (cons 'formatted (number->string server-admin-version))))
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-bytes magic))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'server-admin-flag (list (cons 'raw server-admin-flag) (cons 'formatted (number->string server-admin-flag))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'server-admin-length (list (cons 'raw server-admin-length) (cons 'formatted (number->string server-admin-length))))
        (cons 'length-frag (list (cons 'raw length-frag) (cons 'formatted (number->string length-frag))))
        (cons 'server-admin-flags (list (cons 'raw server-admin-flags) (cons 'formatted (number->string server-admin-flags))))
        (cons 'server-admin-rc (list (cons 'raw server-admin-rc) (cons 'formatted (number->string server-admin-rc))))
        (cons 'more-frags (list (cons 'raw more-frags) (cons 'formatted (number->string more-frags))))
        (cons 'server-admin-eyecatcher (list (cons 'raw server-admin-eyecatcher) (cons 'formatted (utf8->string server-admin-eyecatcher))))
        (cons 'server-admin-trace-protocol-version (list (cons 'raw server-admin-trace-protocol-version) (cons 'formatted (number->string server-admin-trace-protocol-version))))
        (cons 'server-admin-trace-level (list (cons 'raw server-admin-trace-level) (cons 'formatted (number->string server-admin-trace-level))))
        (cons 'server-admin-trace-logging (list (cons 'raw server-admin-trace-logging) (cons 'formatted (number->string server-admin-trace-logging))))
        (cons 'server-admin-trace-max-file-size (list (cons 'raw server-admin-trace-max-file-size) (cons 'formatted (number->string server-admin-trace-max-file-size))))
        (cons 'server-admin-trace-nopatterns (list (cons 'raw server-admin-trace-nopatterns) (cons 'formatted (number->string server-admin-trace-nopatterns))))
        (cons 'server-admin-trace-unknown (list (cons 'raw server-admin-trace-unknown) (cons 'formatted (fmt-bytes server-admin-trace-unknown))))
        (cons 'server-admin-trace-pattern-len (list (cons 'raw server-admin-trace-pattern-len) (cons 'formatted (number->string server-admin-trace-pattern-len))))
        (cons 'server-admin-trace-pattern-value (list (cons 'raw server-admin-trace-pattern-value) (cons 'formatted (utf8->string server-admin-trace-pattern-value))))
        (cons 'server-admin-trace-eyecatcher (list (cons 'raw server-admin-trace-eyecatcher) (cons 'formatted (utf8->string server-admin-trace-eyecatcher))))
        (cons 'conn-admin-params-count (list (cons 'raw conn-admin-params-count) (cons 'formatted (number->string conn-admin-params-count))))
        (cons 'conn-admin-param-name (list (cons 'raw conn-admin-param-name) (cons 'formatted (utf8->string conn-admin-param-name))))
        (cons 'conn-admin-param-len (list (cons 'raw conn-admin-param-len) (cons 'formatted (number->string conn-admin-param-len))))
        (cons 'conn-admin-param-value (list (cons 'raw conn-admin-param-value) (cons 'formatted (number->string conn-admin-param-value))))
        )))

    (catch (e)
      (err (str "SAPENQUEUE parse error: " e)))))

;; dissect-sapenqueue: parse SAPENQUEUE from bytevector
;; Returns (ok fields-alist) or (err message)