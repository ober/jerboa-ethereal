;; packet-elasticsearch.c
;;
;; Routines for dissecting Elasticsearch
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/elasticsearch.ss
;; Auto-generated from wireshark/epan/dissectors/packet-elasticsearch.c

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
(def (dissect-elasticsearch buffer)
  "Elasticsearch"
  (try
    (let* (
           (internal-header (unwrap (read-u32be buffer 0)))
           (header-token (unwrap (slice buffer 0 2)))
           (header-message-length (unwrap (read-u32be buffer 2)))
           (address-length (unwrap (read-u8 buffer 3)))
           (address-ipv4 (unwrap (read-u32be buffer 4)))
           (ping-request-id (unwrap (read-u32be buffer 4)))
           (header-request-id (unwrap (read-u64be buffer 6)))
           (address-ipv6 (unwrap (slice buffer 8 16)))
           (cluster-name (unwrap (slice buffer 8 1)))
           (node-name (unwrap (slice buffer 8 1)))
           (node-id (unwrap (slice buffer 8 1)))
           (host-name (unwrap (slice buffer 8 1)))
           (host-address (unwrap (slice buffer 8 1)))
           (attributes-length (unwrap (read-u32be buffer 8)))
           (feature (unwrap (slice buffer 8 1)))
           (action (unwrap (slice buffer 8 1)))
           (header-status-flags (unwrap (read-u8 buffer 14)))
           (header-size (unwrap (read-u32be buffer 19)))
           (header-key (unwrap (slice buffer 23 1)))
           (header-value (unwrap (slice buffer 23 1)))
           (address-ipv6-scope-id (unwrap (read-u32be buffer 24)))
           (address-name (unwrap (slice buffer 28 1)))
           (address-port (unwrap (read-u32be buffer 28)))
           )

      (ok (list
        (cons 'internal-header (list (cons 'raw internal-header) (cons 'formatted (fmt-hex internal-header))))
        (cons 'header-token (list (cons 'raw header-token) (cons 'formatted (utf8->string header-token))))
        (cons 'header-message-length (list (cons 'raw header-message-length) (cons 'formatted (number->string header-message-length))))
        (cons 'address-length (list (cons 'raw address-length) (cons 'formatted (number->string address-length))))
        (cons 'address-ipv4 (list (cons 'raw address-ipv4) (cons 'formatted (fmt-ipv4 address-ipv4))))
        (cons 'ping-request-id (list (cons 'raw ping-request-id) (cons 'formatted (number->string ping-request-id))))
        (cons 'header-request-id (list (cons 'raw header-request-id) (cons 'formatted (number->string header-request-id))))
        (cons 'address-ipv6 (list (cons 'raw address-ipv6) (cons 'formatted (fmt-ipv6-address address-ipv6))))
        (cons 'cluster-name (list (cons 'raw cluster-name) (cons 'formatted (utf8->string cluster-name))))
        (cons 'node-name (list (cons 'raw node-name) (cons 'formatted (utf8->string node-name))))
        (cons 'node-id (list (cons 'raw node-id) (cons 'formatted (utf8->string node-id))))
        (cons 'host-name (list (cons 'raw host-name) (cons 'formatted (utf8->string host-name))))
        (cons 'host-address (list (cons 'raw host-address) (cons 'formatted (utf8->string host-address))))
        (cons 'attributes-length (list (cons 'raw attributes-length) (cons 'formatted (number->string attributes-length))))
        (cons 'feature (list (cons 'raw feature) (cons 'formatted (utf8->string feature))))
        (cons 'action (list (cons 'raw action) (cons 'formatted (utf8->string action))))
        (cons 'header-status-flags (list (cons 'raw header-status-flags) (cons 'formatted (fmt-hex header-status-flags))))
        (cons 'header-size (list (cons 'raw header-size) (cons 'formatted (number->string header-size))))
        (cons 'header-key (list (cons 'raw header-key) (cons 'formatted (utf8->string header-key))))
        (cons 'header-value (list (cons 'raw header-value) (cons 'formatted (utf8->string header-value))))
        (cons 'address-ipv6-scope-id (list (cons 'raw address-ipv6-scope-id) (cons 'formatted (number->string address-ipv6-scope-id))))
        (cons 'address-name (list (cons 'raw address-name) (cons 'formatted (utf8->string address-name))))
        (cons 'address-port (list (cons 'raw address-port) (cons 'formatted (number->string address-port))))
        )))

    (catch (e)
      (err (str "ELASTICSEARCH parse error: " e)))))

;; dissect-elasticsearch: parse ELASTICSEARCH from bytevector
;; Returns (ok fields-alist) or (err message)