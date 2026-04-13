;; packet-mqtt.c
;; Routines for MQTT Protocol dissection
;;
;; MQTT v5.0 support sponsored by 1byt3 <customers at 1byt3.com>
;;
;; By Lakshmi Narayana Madala  <madalanarayana@outlook.com>
;; Stig Bjorlykke  <stig@bjorlykke.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mqtt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mqtt.c

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
(def (dissect-mqtt buffer)
  "MQ Telemetry Transport Protocol"
  (try
    (let* (
           (hdrflags (unwrap (read-u8 buffer 0)))
           (dup-flag (extract-bits hdrflags 0x0 0))
           (retain (extract-bits hdrflags 0x0 0))
           (msg-len (unwrap (read-u64be buffer 1)))
           (proto-len (unwrap (read-u16be buffer 1)))
           (proto-name (unwrap (slice buffer 3 1)))
           (keep-alive (unwrap (read-u16be buffer 5)))
           (client-id-len (unwrap (read-u16be buffer 7)))
           (client-id (unwrap (slice buffer 9 1)))
           (will-topic-len (unwrap (read-u16be buffer 9)))
           (will-topic (unwrap (slice buffer 11 1)))
           (will-msg-len (unwrap (read-u16be buffer 11)))
           (will-msg-text (unwrap (slice buffer 13 1)))
           (will-msg (unwrap (slice buffer 13 1)))
           (username-len (unwrap (read-u16be buffer 13)))
           (username (unwrap (slice buffer 15 1)))
           (passwd-len (unwrap (read-u16be buffer 15)))
           (passwd (unwrap (slice buffer 17 1)))
           (conack-reserved (unwrap (read-u8 buffer 17)))
           (conack-flags (unwrap (read-u8 buffer 17)))
           (conackflag-reserved (extract-bits conack-flags 0x0 0))
           (conackflag-sp (extract-bits conack-flags 0x0 0))
           (pubmsg-text (unwrap (slice buffer 23 1)))
           (pubmsg (unwrap (slice buffer 23 1)))
           (subscription-options (unwrap (read-u8 buffer 27)))
           (subscription-reserved (extract-bits subscription-options 0x0 0))
           (subscription-rap (extract-bits subscription-options 0x0 0))
           (subscription-nl (extract-bits subscription-options 0x0 0))
           (topic-len (unwrap (read-u16be buffer 30)))
           (topic (unwrap (slice buffer 32 1)))
           (msgid (unwrap (read-u16be buffer 35)))
           )

      (ok (list
        (cons 'hdrflags (list (cons 'raw hdrflags) (cons 'formatted (fmt-hex hdrflags))))
        (cons 'dup-flag (list (cons 'raw dup-flag) (cons 'formatted (if (= dup-flag 0) "Not set" "Set"))))
        (cons 'retain (list (cons 'raw retain) (cons 'formatted (if (= retain 0) "Not set" "Set"))))
        (cons 'msg-len (list (cons 'raw msg-len) (cons 'formatted (number->string msg-len))))
        (cons 'proto-len (list (cons 'raw proto-len) (cons 'formatted (number->string proto-len))))
        (cons 'proto-name (list (cons 'raw proto-name) (cons 'formatted (utf8->string proto-name))))
        (cons 'keep-alive (list (cons 'raw keep-alive) (cons 'formatted (number->string keep-alive))))
        (cons 'client-id-len (list (cons 'raw client-id-len) (cons 'formatted (number->string client-id-len))))
        (cons 'client-id (list (cons 'raw client-id) (cons 'formatted (utf8->string client-id))))
        (cons 'will-topic-len (list (cons 'raw will-topic-len) (cons 'formatted (number->string will-topic-len))))
        (cons 'will-topic (list (cons 'raw will-topic) (cons 'formatted (utf8->string will-topic))))
        (cons 'will-msg-len (list (cons 'raw will-msg-len) (cons 'formatted (number->string will-msg-len))))
        (cons 'will-msg-text (list (cons 'raw will-msg-text) (cons 'formatted (utf8->string will-msg-text))))
        (cons 'will-msg (list (cons 'raw will-msg) (cons 'formatted (fmt-bytes will-msg))))
        (cons 'username-len (list (cons 'raw username-len) (cons 'formatted (number->string username-len))))
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'passwd-len (list (cons 'raw passwd-len) (cons 'formatted (number->string passwd-len))))
        (cons 'passwd (list (cons 'raw passwd) (cons 'formatted (utf8->string passwd))))
        (cons 'conack-reserved (list (cons 'raw conack-reserved) (cons 'formatted (if (= conack-reserved 0) "False" "True"))))
        (cons 'conack-flags (list (cons 'raw conack-flags) (cons 'formatted (fmt-hex conack-flags))))
        (cons 'conackflag-reserved (list (cons 'raw conackflag-reserved) (cons 'formatted (if (= conackflag-reserved 0) "Not set" "Set"))))
        (cons 'conackflag-sp (list (cons 'raw conackflag-sp) (cons 'formatted (if (= conackflag-sp 0) "Not set" "Set"))))
        (cons 'pubmsg-text (list (cons 'raw pubmsg-text) (cons 'formatted (utf8->string pubmsg-text))))
        (cons 'pubmsg (list (cons 'raw pubmsg) (cons 'formatted (fmt-bytes pubmsg))))
        (cons 'subscription-options (list (cons 'raw subscription-options) (cons 'formatted (fmt-hex subscription-options))))
        (cons 'subscription-reserved (list (cons 'raw subscription-reserved) (cons 'formatted (if (= subscription-reserved 0) "Not set" "Set"))))
        (cons 'subscription-rap (list (cons 'raw subscription-rap) (cons 'formatted (if (= subscription-rap 0) "Not set" "Set"))))
        (cons 'subscription-nl (list (cons 'raw subscription-nl) (cons 'formatted (if (= subscription-nl 0) "Not set" "Set"))))
        (cons 'topic-len (list (cons 'raw topic-len) (cons 'formatted (number->string topic-len))))
        (cons 'topic (list (cons 'raw topic) (cons 'formatted (utf8->string topic))))
        (cons 'msgid (list (cons 'raw msgid) (cons 'formatted (number->string msgid))))
        )))

    (catch (e)
      (err (str "MQTT parse error: " e)))))

;; dissect-mqtt: parse MQTT from bytevector
;; Returns (ok fields-alist) or (err message)