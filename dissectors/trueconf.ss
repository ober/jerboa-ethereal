;; packet-trueconf.c
;; Routines for TrueConf packet dissection
;; Copyright 2025, Sergey Rudakov <rudakov.private.bsf@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/trueconf.ss
;; Auto-generated from wireshark/epan/dissectors/packet-trueconf.c

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
(def (dissect-trueconf buffer)
  "TrueConf Protocol"
  (try
    (let* (
           (magic (unwrap (slice buffer 0 14)))
           (zero2 (unwrap (slice buffer 14 2)))
           (conn-id (unwrap (slice buffer 16 3)))
           (flags (unwrap (read-u8 buffer 19)))
           (cap (unwrap (read-u16be buffer 20)))
           (unk1 (unwrap (read-u8 buffer 22)))
           (ver-major (unwrap (read-u8 buffer 23)))
           (ver-minor (unwrap (read-u8 buffer 24)))
           (name-len (unwrap (read-u8 buffer 25)))
           (host (unwrap (slice buffer 26 1)))
           (sep0 (unwrap (read-u8 buffer 26)))
           (token-len (unwrap (read-u16be buffer 27)))
           (token (unwrap (slice buffer 28 1)))
           (msg-type (unwrap (read-u16be buffer 28)))
           (len-a (unwrap (read-u32be buffer 30)))
           (len-b (unwrap (read-u32be buffer 34)))
           (seed16 (unwrap (slice buffer 38 16)))
           (payload (unwrap (slice buffer 54 1)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (utf8->string magic))))
        (cons 'zero2 (list (cons 'raw zero2) (cons 'formatted (fmt-bytes zero2))))
        (cons 'conn-id (list (cons 'raw conn-id) (cons 'formatted (fmt-bytes conn-id))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'cap (list (cons 'raw cap) (cons 'formatted (fmt-hex cap))))
        (cons 'unk1 (list (cons 'raw unk1) (cons 'formatted (fmt-hex unk1))))
        (cons 'ver-major (list (cons 'raw ver-major) (cons 'formatted (number->string ver-major))))
        (cons 'ver-minor (list (cons 'raw ver-minor) (cons 'formatted (number->string ver-minor))))
        (cons 'name-len (list (cons 'raw name-len) (cons 'formatted (number->string name-len))))
        (cons 'host (list (cons 'raw host) (cons 'formatted (utf8->string host))))
        (cons 'sep0 (list (cons 'raw sep0) (cons 'formatted (fmt-hex sep0))))
        (cons 'token-len (list (cons 'raw token-len) (cons 'formatted (number->string token-len))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (utf8->string token))))
        (cons 'msg-type (list (cons 'raw msg-type) (cons 'formatted (number->string msg-type))))
        (cons 'len-a (list (cons 'raw len-a) (cons 'formatted (number->string len-a))))
        (cons 'len-b (list (cons 'raw len-b) (cons 'formatted (number->string len-b))))
        (cons 'seed16 (list (cons 'raw seed16) (cons 'formatted (fmt-bytes seed16))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        )))

    (catch (e)
      (err (str "TRUECONF parse error: " e)))))

;; dissect-trueconf: parse TRUECONF from bytevector
;; Returns (ok fields-alist) or (err message)