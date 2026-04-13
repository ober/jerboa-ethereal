;; packet-ipdr.c
;;
;; Routines for IP Detail Record (IPDR) dissection.
;;
;; Original dissection based off of a Lua script found at
;; https://bitbucket.org/abn/ipdr-dissector/overview
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ipdr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ipdr.c

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
(def (dissect-ipdr buffer)
  "IPDR"
  (try
    (let* (
           (session-id (unwrap (read-u8 buffer 0)))
           (message-flags (unwrap (read-u8 buffer 0)))
           (message-len (unwrap (read-u32be buffer 0)))
           (initiator-id (unwrap (read-u32be buffer 6)))
           (initiator-port (unwrap (read-u16be buffer 10)))
           (capabilities (unwrap (read-u32be buffer 20)))
           (keepalive-interval (unwrap (read-u32be buffer 24)))
           (exporter-boot-time (unwrap (read-u32be buffer 28)))
           (first-record-sequence-number (unwrap (read-u64be buffer 32)))
           (dropped-record-count (unwrap (read-u64be buffer 40)))
           (primary (unwrap (read-u8 buffer 48)))
           (ack-time-interval (unwrap (read-u32be buffer 48)))
           (ack-sequence-interval (unwrap (read-u32be buffer 52)))
           (document-id (unwrap (slice buffer 56 16)))
           (reason-code (unwrap (read-u16be buffer 56)))
           (reason-info (unwrap (slice buffer 58 1)))
           (request-id (unwrap (read-u16be buffer 60)))
           (sequence-num (unwrap (read-u64be buffer 78)))
           (timestamp (unwrap (read-u32be buffer 78)))
           (error-code (unwrap (read-u16be buffer 82)))
           (description (unwrap (slice buffer 84 1)))
           (template-id (unwrap (read-u16be buffer 96)))
           (config-id (unwrap (read-u16be buffer 98)))
           (flags (unwrap (read-u8 buffer 100)))
           (request-number (unwrap (read-u64be buffer 100)))
           (data-record (unwrap (slice buffer 108 1)))
           (version (unwrap (read-u8 buffer 109)))
           )

      (ok (list
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (number->string session-id))))
        (cons 'message-flags (list (cons 'raw message-flags) (cons 'formatted (fmt-hex message-flags))))
        (cons 'message-len (list (cons 'raw message-len) (cons 'formatted (number->string message-len))))
        (cons 'initiator-id (list (cons 'raw initiator-id) (cons 'formatted (fmt-ipv4 initiator-id))))
        (cons 'initiator-port (list (cons 'raw initiator-port) (cons 'formatted (number->string initiator-port))))
        (cons 'capabilities (list (cons 'raw capabilities) (cons 'formatted (fmt-hex capabilities))))
        (cons 'keepalive-interval (list (cons 'raw keepalive-interval) (cons 'formatted (number->string keepalive-interval))))
        (cons 'exporter-boot-time (list (cons 'raw exporter-boot-time) (cons 'formatted (number->string exporter-boot-time))))
        (cons 'first-record-sequence-number (list (cons 'raw first-record-sequence-number) (cons 'formatted (number->string first-record-sequence-number))))
        (cons 'dropped-record-count (list (cons 'raw dropped-record-count) (cons 'formatted (number->string dropped-record-count))))
        (cons 'primary (list (cons 'raw primary) (cons 'formatted (number->string primary))))
        (cons 'ack-time-interval (list (cons 'raw ack-time-interval) (cons 'formatted (number->string ack-time-interval))))
        (cons 'ack-sequence-interval (list (cons 'raw ack-sequence-interval) (cons 'formatted (number->string ack-sequence-interval))))
        (cons 'document-id (list (cons 'raw document-id) (cons 'formatted (fmt-bytes document-id))))
        (cons 'reason-code (list (cons 'raw reason-code) (cons 'formatted (number->string reason-code))))
        (cons 'reason-info (list (cons 'raw reason-info) (cons 'formatted (utf8->string reason-info))))
        (cons 'request-id (list (cons 'raw request-id) (cons 'formatted (number->string request-id))))
        (cons 'sequence-num (list (cons 'raw sequence-num) (cons 'formatted (number->string sequence-num))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'error-code (list (cons 'raw error-code) (cons 'formatted (number->string error-code))))
        (cons 'description (list (cons 'raw description) (cons 'formatted (utf8->string description))))
        (cons 'template-id (list (cons 'raw template-id) (cons 'formatted (number->string template-id))))
        (cons 'config-id (list (cons 'raw config-id) (cons 'formatted (number->string config-id))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'request-number (list (cons 'raw request-number) (cons 'formatted (number->string request-number))))
        (cons 'data-record (list (cons 'raw data-record) (cons 'formatted (fmt-bytes data-record))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        )))

    (catch (e)
      (err (str "IPDR parse error: " e)))))

;; dissect-ipdr: parse IPDR from bytevector
;; Returns (ok fields-alist) or (err message)