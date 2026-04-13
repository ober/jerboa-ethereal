;;
;; packet-raknet.c
;;
;; Routines for RakNet protocol packet disassembly.
;;
;; Ref: https://github.com/OculusVR/RakNet
;;
;; Nick Carter <ncarter100@gmail.com>
;; Copyright 2014 Nick Carter
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/raknet.ss
;; Auto-generated from wireshark/epan/dissectors/packet-raknet.c

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
(def (dissect-raknet buffer)
  "RakNet game networking protocol"
  (try
    (let* (
           (NACK-record-count (unwrap (read-u16be buffer 0)))
           (client-guid (unwrap (slice buffer 1 8)))
           (system-index (unwrap (read-u16be buffer 1)))
           (payload-length (unwrap (read-u16be buffer 1)))
           (AS (unwrap (read-u32be buffer 1)))
           (timestamp (unwrap (read-u64be buffer 3)))
           (reliable-message-number (unwrap (read-u24be buffer 3)))
           (packet-type (unwrap (read-u8 buffer 5)))
           (packet-is-for-connected (extract-bits packet-type 0x80 7))
           (packet-is-ACK (extract-bits packet-type 0x40 6))
           (packet-is-NAK (extract-bits packet-type 0x20 5))
           (packet-number-range (unwrap (slice buffer 6 1)))
           (range-max-equal-to-min (unwrap (read-u8 buffer 6)))
           (message-sequencing-index (unwrap (read-u24be buffer 6)))
           (packet-number-min (unwrap (read-u24be buffer 7)))
           (packet-number (unwrap (read-u24be buffer 7)))
           (message-ordering-index (unwrap (read-u24be buffer 9)))
           (packet-number-max (unwrap (read-u24be buffer 10)))
           (message-ordering-channel (unwrap (read-u8 buffer 12)))
           (split-packet-count (unwrap (read-u32be buffer 13)))
           (use-encryption (unwrap (read-u8 buffer 17)))
           (split-packet-id (unwrap (read-u16be buffer 17)))
           (client-proof (unwrap (slice buffer 18 32)))
           (split-packet-index (unwrap (read-u32be buffer 19)))
           (use-client-key (unwrap (read-u8 buffer 50)))
           (client-identity (unwrap (slice buffer 51 160)))
           (server-public-key (unwrap (slice buffer 102 64)))
           (cookie (unwrap (read-u32be buffer 184)))
           (client-wrote-challenge (unwrap (read-u8 buffer 188)))
           (client-challenge (unwrap (slice buffer 189 64)))
           (password (unwrap (slice buffer 211 1)))
           (mtu-size (unwrap (read-u16be buffer 287)))
           (server-answer (unwrap (slice buffer 290 128)))
           (raknet-proto-ver (unwrap (read-u8 buffer 418)))
           (server-guid (unwrap (slice buffer 475 8)))
           (offline-message-data-id (unwrap (slice buffer 483 16)))
           (0x1C-server-id-str-len (unwrap (read-u16be buffer 499)))
           (0x1C-server-id-str (unwrap (slice buffer 501 1)))
           )

      (ok (list
        (cons 'NACK-record-count (list (cons 'raw NACK-record-count) (cons 'formatted (number->string NACK-record-count))))
        (cons 'client-guid (list (cons 'raw client-guid) (cons 'formatted (fmt-bytes client-guid))))
        (cons 'system-index (list (cons 'raw system-index) (cons 'formatted (number->string system-index))))
        (cons 'payload-length (list (cons 'raw payload-length) (cons 'formatted (number->string payload-length))))
        (cons 'AS (list (cons 'raw AS) (cons 'formatted (number->string AS))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'reliable-message-number (list (cons 'raw reliable-message-number) (cons 'formatted (number->string reliable-message-number))))
        (cons 'packet-type (list (cons 'raw packet-type) (cons 'formatted (fmt-hex packet-type))))
        (cons 'packet-is-for-connected (list (cons 'raw packet-is-for-connected) (cons 'formatted (if (= packet-is-for-connected 0) "Not set" "Set"))))
        (cons 'packet-is-ACK (list (cons 'raw packet-is-ACK) (cons 'formatted (if (= packet-is-ACK 0) "Not set" "Set"))))
        (cons 'packet-is-NAK (list (cons 'raw packet-is-NAK) (cons 'formatted (if (= packet-is-NAK 0) "Not set" "Set"))))
        (cons 'packet-number-range (list (cons 'raw packet-number-range) (cons 'formatted (utf8->string packet-number-range))))
        (cons 'range-max-equal-to-min (list (cons 'raw range-max-equal-to-min) (cons 'formatted (number->string range-max-equal-to-min))))
        (cons 'message-sequencing-index (list (cons 'raw message-sequencing-index) (cons 'formatted (number->string message-sequencing-index))))
        (cons 'packet-number-min (list (cons 'raw packet-number-min) (cons 'formatted (number->string packet-number-min))))
        (cons 'packet-number (list (cons 'raw packet-number) (cons 'formatted (number->string packet-number))))
        (cons 'message-ordering-index (list (cons 'raw message-ordering-index) (cons 'formatted (number->string message-ordering-index))))
        (cons 'packet-number-max (list (cons 'raw packet-number-max) (cons 'formatted (number->string packet-number-max))))
        (cons 'message-ordering-channel (list (cons 'raw message-ordering-channel) (cons 'formatted (number->string message-ordering-channel))))
        (cons 'split-packet-count (list (cons 'raw split-packet-count) (cons 'formatted (number->string split-packet-count))))
        (cons 'use-encryption (list (cons 'raw use-encryption) (cons 'formatted (number->string use-encryption))))
        (cons 'split-packet-id (list (cons 'raw split-packet-id) (cons 'formatted (number->string split-packet-id))))
        (cons 'client-proof (list (cons 'raw client-proof) (cons 'formatted (fmt-bytes client-proof))))
        (cons 'split-packet-index (list (cons 'raw split-packet-index) (cons 'formatted (number->string split-packet-index))))
        (cons 'use-client-key (list (cons 'raw use-client-key) (cons 'formatted (number->string use-client-key))))
        (cons 'client-identity (list (cons 'raw client-identity) (cons 'formatted (fmt-bytes client-identity))))
        (cons 'server-public-key (list (cons 'raw server-public-key) (cons 'formatted (fmt-bytes server-public-key))))
        (cons 'cookie (list (cons 'raw cookie) (cons 'formatted (fmt-hex cookie))))
        (cons 'client-wrote-challenge (list (cons 'raw client-wrote-challenge) (cons 'formatted (number->string client-wrote-challenge))))
        (cons 'client-challenge (list (cons 'raw client-challenge) (cons 'formatted (fmt-bytes client-challenge))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (fmt-bytes password))))
        (cons 'mtu-size (list (cons 'raw mtu-size) (cons 'formatted (number->string mtu-size))))
        (cons 'server-answer (list (cons 'raw server-answer) (cons 'formatted (fmt-bytes server-answer))))
        (cons 'raknet-proto-ver (list (cons 'raw raknet-proto-ver) (cons 'formatted (number->string raknet-proto-ver))))
        (cons 'server-guid (list (cons 'raw server-guid) (cons 'formatted (fmt-bytes server-guid))))
        (cons 'offline-message-data-id (list (cons 'raw offline-message-data-id) (cons 'formatted (fmt-bytes offline-message-data-id))))
        (cons '0x1C-server-id-str-len (list (cons 'raw 0x1C-server-id-str-len) (cons 'formatted (number->string 0x1C-server-id-str-len))))
        (cons '0x1C-server-id-str (list (cons 'raw 0x1C-server-id-str) (cons 'formatted (utf8->string 0x1C-server-id-str))))
        )))

    (catch (e)
      (err (str "RAKNET parse error: " e)))))

;; dissect-raknet: parse RAKNET from bytevector
;; Returns (ok fields-alist) or (err message)