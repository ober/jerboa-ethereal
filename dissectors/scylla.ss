;; packet-scylla.c
;; Routines for Scylla RPC dissection
;; Copyright 2020 ScyllaDB, Piotr Sarna <sarna@scylladb.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/scylla.ss
;; Auto-generated from wireshark/epan/dissectors/packet-scylla.c

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
(def (dissect-scylla buffer)
  "Scylla RPC protocol"
  (try
    (let* (
           (negotiation-magic (unwrap (slice buffer 0 8)))
           (response (unwrap (slice buffer 0 1)))
           (request (unwrap (slice buffer 0 1)))
           (timeout (unwrap (read-u64be buffer 0)))
           (negotiation-size (unwrap (read-u32be buffer 8)))
           (response-size (unwrap (read-u32be buffer 8)))
           (feature-len (unwrap (read-u32be buffer 16)))
           (msg-id (unwrap (read-u64be buffer 16)))
           (connection-id (unwrap (read-u64be buffer 20)))
           (isolation-cookie (unwrap (slice buffer 20 1)))
           (feature-data (unwrap (slice buffer 20 1)))
           (len (unwrap (read-u32be buffer 24)))
           (mut-size1 (unwrap (read-u32be buffer 28)))
           (mut-size2 (unwrap (read-u32be buffer 32)))
           (mut-table-id (unwrap (slice buffer 36 16)))
           (mut-schema-id (unwrap (slice buffer 52 16)))
           (mut-len-pkeys (unwrap (read-u32be buffer 68)))
           (mut-num-pkeys (unwrap (read-u32be buffer 72)))
           (mut-len-pkey (unwrap (read-u32be buffer 76)))
           (mut-pkey (unwrap (slice buffer 80 1)))
           (read-data-timeout (unwrap (read-u32be buffer 80)))
           (read-data-table-id (unwrap (slice buffer 84 16)))
           (read-data-schema-version (unwrap (slice buffer 100 16)))
           (payload (unwrap (slice buffer 116 1)))
           )

      (ok (list
        (cons 'negotiation-magic (list (cons 'raw negotiation-magic) (cons 'formatted (utf8->string negotiation-magic))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (utf8->string response))))
        (cons 'request (list (cons 'raw request) (cons 'formatted (utf8->string request))))
        (cons 'timeout (list (cons 'raw timeout) (cons 'formatted (number->string timeout))))
        (cons 'negotiation-size (list (cons 'raw negotiation-size) (cons 'formatted (number->string negotiation-size))))
        (cons 'response-size (list (cons 'raw response-size) (cons 'formatted (number->string response-size))))
        (cons 'feature-len (list (cons 'raw feature-len) (cons 'formatted (number->string feature-len))))
        (cons 'msg-id (list (cons 'raw msg-id) (cons 'formatted (number->string msg-id))))
        (cons 'connection-id (list (cons 'raw connection-id) (cons 'formatted (fmt-hex connection-id))))
        (cons 'isolation-cookie (list (cons 'raw isolation-cookie) (cons 'formatted (fmt-bytes isolation-cookie))))
        (cons 'feature-data (list (cons 'raw feature-data) (cons 'formatted (fmt-bytes feature-data))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'mut-size1 (list (cons 'raw mut-size1) (cons 'formatted (number->string mut-size1))))
        (cons 'mut-size2 (list (cons 'raw mut-size2) (cons 'formatted (number->string mut-size2))))
        (cons 'mut-table-id (list (cons 'raw mut-table-id) (cons 'formatted (fmt-bytes mut-table-id))))
        (cons 'mut-schema-id (list (cons 'raw mut-schema-id) (cons 'formatted (fmt-bytes mut-schema-id))))
        (cons 'mut-len-pkeys (list (cons 'raw mut-len-pkeys) (cons 'formatted (number->string mut-len-pkeys))))
        (cons 'mut-num-pkeys (list (cons 'raw mut-num-pkeys) (cons 'formatted (number->string mut-num-pkeys))))
        (cons 'mut-len-pkey (list (cons 'raw mut-len-pkey) (cons 'formatted (number->string mut-len-pkey))))
        (cons 'mut-pkey (list (cons 'raw mut-pkey) (cons 'formatted (fmt-bytes mut-pkey))))
        (cons 'read-data-timeout (list (cons 'raw read-data-timeout) (cons 'formatted (number->string read-data-timeout))))
        (cons 'read-data-table-id (list (cons 'raw read-data-table-id) (cons 'formatted (fmt-bytes read-data-table-id))))
        (cons 'read-data-schema-version (list (cons 'raw read-data-schema-version) (cons 'formatted (fmt-bytes read-data-schema-version))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        )))

    (catch (e)
      (err (str "SCYLLA parse error: " e)))))

;; dissect-scylla: parse SCYLLA from bytevector
;; Returns (ok fields-alist) or (err message)