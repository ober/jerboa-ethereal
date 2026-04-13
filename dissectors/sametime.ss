;; packet-sametime.c
;; Routines for SAMETIME dissection
;; Copyright 2010, Toralf Foerster <toralf.foerster [AT] gmx.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sametime.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sametime.c

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
(def (dissect-sametime buffer)
  "Sametime Protocol"
  (try
    (let* (
           (field-length (unwrap (read-u16be buffer 0)))
           (heartbeat (unwrap (read-u8 buffer 0)))
           (message-length (unwrap (read-u32be buffer 0)))
           (time (unwrap (read-u32be buffer 2)))
           (message-options-attribute (unwrap (read-u8 buffer 6)))
           (message-options-encrypted (unwrap (read-u8 buffer 6)))
           (message-channel (unwrap (read-u32be buffer 8)))
           (handshake-srvrcalc-addr (unwrap (read-u32be buffer 14)))
           (handshake-major (unwrap (read-u16be buffer 38)))
           (handshake-minor (unwrap (read-u16be buffer 40)))
           (login-type (unwrap (read-u16be buffer 58)))
           (handshake-loclcalc-addr (unwrap (read-u32be buffer 63)))
           (channel-id (unwrap (read-u32be buffer 92)))
           (channel-service (unwrap (read-u32be buffer 96)))
           )

      (ok (list
        (cons 'field-length (list (cons 'raw field-length) (cons 'formatted (number->string field-length))))
        (cons 'heartbeat (list (cons 'raw heartbeat) (cons 'formatted (fmt-hex heartbeat))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'time (list (cons 'raw time) (cons 'formatted (number->string time))))
        (cons 'message-options-attribute (list (cons 'raw message-options-attribute) (cons 'formatted (number->string message-options-attribute))))
        (cons 'message-options-encrypted (list (cons 'raw message-options-encrypted) (cons 'formatted (number->string message-options-encrypted))))
        (cons 'message-channel (list (cons 'raw message-channel) (cons 'formatted (number->string message-channel))))
        (cons 'handshake-srvrcalc-addr (list (cons 'raw handshake-srvrcalc-addr) (cons 'formatted (fmt-ipv4 handshake-srvrcalc-addr))))
        (cons 'handshake-major (list (cons 'raw handshake-major) (cons 'formatted (fmt-hex handshake-major))))
        (cons 'handshake-minor (list (cons 'raw handshake-minor) (cons 'formatted (fmt-hex handshake-minor))))
        (cons 'login-type (list (cons 'raw login-type) (cons 'formatted (fmt-hex login-type))))
        (cons 'handshake-loclcalc-addr (list (cons 'raw handshake-loclcalc-addr) (cons 'formatted (fmt-ipv4 handshake-loclcalc-addr))))
        (cons 'channel-id (list (cons 'raw channel-id) (cons 'formatted (number->string channel-id))))
        (cons 'channel-service (list (cons 'raw channel-service) (cons 'formatted (number->string channel-service))))
        )))

    (catch (e)
      (err (str "SAMETIME parse error: " e)))))

;; dissect-sametime: parse SAMETIME from bytevector
;; Returns (ok fields-alist) or (err message)