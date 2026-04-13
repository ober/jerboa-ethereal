;; packet-enttec.c
;; Routines for ENTTEC packet disassembly
;;
;; Copyright (c) 2003,2004 by Erwin Rol <erwin@erwinrol.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/enttec.ss
;; Auto-generated from wireshark/epan/dissectors/packet-enttec.c

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
(def (dissect-enttec buffer)
  "ENTTEC"
  (try
    (let* (
           (poll-reply-node-type (unwrap (read-u16be buffer 6)))
           (poll-reply-version (unwrap (read-u8 buffer 8)))
           (poll-reply-switch (unwrap (read-u8 buffer 9)))
           (poll-reply-name (unwrap (slice buffer 10 10)))
           (poll-reply-option (unwrap (read-u8 buffer 20)))
           (poll-reply-tos (unwrap (read-u8 buffer 21)))
           (poll-reply-ttl (unwrap (read-u8 buffer 22)))
           (poll-type (unwrap (read-u8 buffer 23)))
           (dmx-data-universe (unwrap (read-u8 buffer 24)))
           (dmx-data-start-code (unwrap (read-u8 buffer 25)))
           (dmx-data-size (unwrap (read-u16be buffer 27)))
           (dmx-data-data-filter (unwrap (slice buffer 29 1)))
           (poll-reply-mac (unwrap (slice buffer 30 6)))
           )

      (ok (list
        (cons 'poll-reply-node-type (list (cons 'raw poll-reply-node-type) (cons 'formatted (fmt-hex poll-reply-node-type))))
        (cons 'poll-reply-version (list (cons 'raw poll-reply-version) (cons 'formatted (number->string poll-reply-version))))
        (cons 'poll-reply-switch (list (cons 'raw poll-reply-switch) (cons 'formatted (fmt-hex poll-reply-switch))))
        (cons 'poll-reply-name (list (cons 'raw poll-reply-name) (cons 'formatted (utf8->string poll-reply-name))))
        (cons 'poll-reply-option (list (cons 'raw poll-reply-option) (cons 'formatted (fmt-hex poll-reply-option))))
        (cons 'poll-reply-tos (list (cons 'raw poll-reply-tos) (cons 'formatted (fmt-hex poll-reply-tos))))
        (cons 'poll-reply-ttl (list (cons 'raw poll-reply-ttl) (cons 'formatted (number->string poll-reply-ttl))))
        (cons 'poll-type (list (cons 'raw poll-type) (cons 'formatted (number->string poll-type))))
        (cons 'dmx-data-universe (list (cons 'raw dmx-data-universe) (cons 'formatted (number->string dmx-data-universe))))
        (cons 'dmx-data-start-code (list (cons 'raw dmx-data-start-code) (cons 'formatted (number->string dmx-data-start-code))))
        (cons 'dmx-data-size (list (cons 'raw dmx-data-size) (cons 'formatted (number->string dmx-data-size))))
        (cons 'dmx-data-data-filter (list (cons 'raw dmx-data-data-filter) (cons 'formatted (fmt-bytes dmx-data-data-filter))))
        (cons 'poll-reply-mac (list (cons 'raw poll-reply-mac) (cons 'formatted (fmt-mac poll-reply-mac))))
        )))

    (catch (e)
      (err (str "ENTTEC parse error: " e)))))

;; dissect-enttec: parse ENTTEC from bytevector
;; Returns (ok fields-alist) or (err message)