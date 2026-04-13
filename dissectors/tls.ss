;; packet-tls.c
;; Routines for TLS dissection
;; Copyright (c) 2000-2001, Scott Renfro <scott@renfro.org>
;; Copyright 2013-2019, Peter Wu <peter@lekensteyn.nl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tls.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tls.c

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
(def (dissect-tls buffer)
  "Transport Layer Security"
  (try
    (let* (
           (handshake-reassembled-in (unwrap (read-u32be buffer 0)))
           (record-appdata-proto (unwrap (slice buffer 0 1)))
           (record-sequence-number (unwrap (read-u64be buffer 0)))
           (stream (unwrap (read-u32be buffer 0)))
           (segment-data (unwrap (slice buffer 0 1)))
           (record-length (unwrap (read-u16be buffer 2)))
           (record-appdata (unwrap (slice buffer 4 1)))
           (handshake-length (unwrap (read-u24be buffer 5)))
           (heartbeat-message-payload-length (unwrap (read-u16be buffer 9)))
           (heartbeat-message-payload (unwrap (slice buffer 11 1)))
           (heartbeat-message-padding (unwrap (slice buffer 11 1)))
           (handshake-npn-selected-protocol-len (unwrap (read-u8 buffer 11)))
           (handshake-npn-selected-protocol (unwrap (slice buffer 11 1)))
           (handshake-npn-padding-len (unwrap (read-u8 buffer 11)))
           (handshake-npn-padding (unwrap (slice buffer 11 1)))
           (handshake-session-id-len (unwrap (read-u16be buffer 16)))
           (handshake-challenge-len (unwrap (read-u16be buffer 18)))
           (handshake-clear-key-len (unwrap (read-u16be buffer 26)))
           (handshake-enc-key-len (unwrap (read-u16be buffer 28)))
           (handshake-key-arg-len (unwrap (read-u16be buffer 30)))
           (handshake-session-id-hit (unwrap (read-u8 buffer 32)))
           (handshake-cipher-spec-len (unwrap (read-u16be buffer 38)))
           (handshake-connection-id-len (unwrap (read-u16be buffer 40)))
           )

      (ok (list
        (cons 'handshake-reassembled-in (list (cons 'raw handshake-reassembled-in) (cons 'formatted (number->string handshake-reassembled-in))))
        (cons 'record-appdata-proto (list (cons 'raw record-appdata-proto) (cons 'formatted (utf8->string record-appdata-proto))))
        (cons 'record-sequence-number (list (cons 'raw record-sequence-number) (cons 'formatted (number->string record-sequence-number))))
        (cons 'stream (list (cons 'raw stream) (cons 'formatted (number->string stream))))
        (cons 'segment-data (list (cons 'raw segment-data) (cons 'formatted (fmt-bytes segment-data))))
        (cons 'record-length (list (cons 'raw record-length) (cons 'formatted (number->string record-length))))
        (cons 'record-appdata (list (cons 'raw record-appdata) (cons 'formatted (fmt-bytes record-appdata))))
        (cons 'handshake-length (list (cons 'raw handshake-length) (cons 'formatted (number->string handshake-length))))
        (cons 'heartbeat-message-payload-length (list (cons 'raw heartbeat-message-payload-length) (cons 'formatted (number->string heartbeat-message-payload-length))))
        (cons 'heartbeat-message-payload (list (cons 'raw heartbeat-message-payload) (cons 'formatted (fmt-bytes heartbeat-message-payload))))
        (cons 'heartbeat-message-padding (list (cons 'raw heartbeat-message-padding) (cons 'formatted (fmt-bytes heartbeat-message-padding))))
        (cons 'handshake-npn-selected-protocol-len (list (cons 'raw handshake-npn-selected-protocol-len) (cons 'formatted (number->string handshake-npn-selected-protocol-len))))
        (cons 'handshake-npn-selected-protocol (list (cons 'raw handshake-npn-selected-protocol) (cons 'formatted (utf8->string handshake-npn-selected-protocol))))
        (cons 'handshake-npn-padding-len (list (cons 'raw handshake-npn-padding-len) (cons 'formatted (number->string handshake-npn-padding-len))))
        (cons 'handshake-npn-padding (list (cons 'raw handshake-npn-padding) (cons 'formatted (fmt-bytes handshake-npn-padding))))
        (cons 'handshake-session-id-len (list (cons 'raw handshake-session-id-len) (cons 'formatted (number->string handshake-session-id-len))))
        (cons 'handshake-challenge-len (list (cons 'raw handshake-challenge-len) (cons 'formatted (number->string handshake-challenge-len))))
        (cons 'handshake-clear-key-len (list (cons 'raw handshake-clear-key-len) (cons 'formatted (number->string handshake-clear-key-len))))
        (cons 'handshake-enc-key-len (list (cons 'raw handshake-enc-key-len) (cons 'formatted (number->string handshake-enc-key-len))))
        (cons 'handshake-key-arg-len (list (cons 'raw handshake-key-arg-len) (cons 'formatted (number->string handshake-key-arg-len))))
        (cons 'handshake-session-id-hit (list (cons 'raw handshake-session-id-hit) (cons 'formatted (number->string handshake-session-id-hit))))
        (cons 'handshake-cipher-spec-len (list (cons 'raw handshake-cipher-spec-len) (cons 'formatted (number->string handshake-cipher-spec-len))))
        (cons 'handshake-connection-id-len (list (cons 'raw handshake-connection-id-len) (cons 'formatted (number->string handshake-connection-id-len))))
        )))

    (catch (e)
      (err (str "TLS parse error: " e)))))

;; dissect-tls: parse TLS from bytevector
;; Returns (ok fields-alist) or (err message)