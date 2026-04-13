;; packet-twamp.c
;; Routines for TWAMP packet dissection
;;
;; Murat Demirten <murat@debian.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/twamp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-twamp.c
;; RFC 4656

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
(def (dissect-twamp buffer)
  "TwoWay Active Measurement Test Protocol"
  (try
    (let* (
           (control-receiver-port (unwrap (read-u16be buffer 2)))
           (control-sessionid (unwrap (slice buffer 4 16)))
           (control-modes (unwrap (read-u32be buffer 12)))
           (control-challenge (unwrap (slice buffer 16 16)))
           (control-salt (unwrap (slice buffer 32 16)))
           (control-count (unwrap (read-u32be buffer 48)))
           (control-mode (unwrap (read-u32be buffer 64)))
           (control-keyid (unwrap (slice buffer 68 40)))
           (control-mbz1 (unwrap (slice buffer 98 2)))
           (control-num-sessions (unwrap (read-u32be buffer 100)))
           (control-mbz2 (unwrap (slice buffer 104 8)))
           (control-hmac (unwrap (slice buffer 112 16)))
           (control-iv (unwrap (slice buffer 124 16)))
           (control-ipvn (unwrap (read-u8 buffer 149)))
           (control-conf-sender (unwrap (read-u8 buffer 150)))
           (control-conf-receiver (unwrap (read-u8 buffer 151)))
           (control-number-of-schedule-slots (unwrap (read-u32be buffer 152)))
           (control-number-of-packets (unwrap (read-u32be buffer 156)))
           (control-sender-port (unwrap (read-u16be buffer 160)))
           (control-sender-ipv6 (unwrap (slice buffer 164 16)))
           (control-sender-ipv4 (unwrap (read-u32be buffer 164)))
           (control-receiver-ipv6 (unwrap (slice buffer 180 16)))
           (control-receiver-ipv4 (unwrap (read-u32be buffer 180)))
           (control-padding-length (unwrap (read-u32be buffer 212)))
           (control-type-p (unwrap (read-u32be buffer 232)))
           (control-unused (unwrap (slice buffer 236 12)))
           )

      (ok (list
        (cons 'control-receiver-port (list (cons 'raw control-receiver-port) (cons 'formatted (number->string control-receiver-port))))
        (cons 'control-sessionid (list (cons 'raw control-sessionid) (cons 'formatted (fmt-bytes control-sessionid))))
        (cons 'control-modes (list (cons 'raw control-modes) (cons 'formatted (number->string control-modes))))
        (cons 'control-challenge (list (cons 'raw control-challenge) (cons 'formatted (fmt-bytes control-challenge))))
        (cons 'control-salt (list (cons 'raw control-salt) (cons 'formatted (fmt-bytes control-salt))))
        (cons 'control-count (list (cons 'raw control-count) (cons 'formatted (number->string control-count))))
        (cons 'control-mode (list (cons 'raw control-mode) (cons 'formatted (number->string control-mode))))
        (cons 'control-keyid (list (cons 'raw control-keyid) (cons 'formatted (fmt-bytes control-keyid))))
        (cons 'control-mbz1 (list (cons 'raw control-mbz1) (cons 'formatted (fmt-bytes control-mbz1))))
        (cons 'control-num-sessions (list (cons 'raw control-num-sessions) (cons 'formatted (number->string control-num-sessions))))
        (cons 'control-mbz2 (list (cons 'raw control-mbz2) (cons 'formatted (fmt-bytes control-mbz2))))
        (cons 'control-hmac (list (cons 'raw control-hmac) (cons 'formatted (fmt-bytes control-hmac))))
        (cons 'control-iv (list (cons 'raw control-iv) (cons 'formatted (fmt-bytes control-iv))))
        (cons 'control-ipvn (list (cons 'raw control-ipvn) (cons 'formatted (number->string control-ipvn))))
        (cons 'control-conf-sender (list (cons 'raw control-conf-sender) (cons 'formatted (number->string control-conf-sender))))
        (cons 'control-conf-receiver (list (cons 'raw control-conf-receiver) (cons 'formatted (number->string control-conf-receiver))))
        (cons 'control-number-of-schedule-slots (list (cons 'raw control-number-of-schedule-slots) (cons 'formatted (number->string control-number-of-schedule-slots))))
        (cons 'control-number-of-packets (list (cons 'raw control-number-of-packets) (cons 'formatted (number->string control-number-of-packets))))
        (cons 'control-sender-port (list (cons 'raw control-sender-port) (cons 'formatted (number->string control-sender-port))))
        (cons 'control-sender-ipv6 (list (cons 'raw control-sender-ipv6) (cons 'formatted (fmt-ipv6-address control-sender-ipv6))))
        (cons 'control-sender-ipv4 (list (cons 'raw control-sender-ipv4) (cons 'formatted (fmt-ipv4 control-sender-ipv4))))
        (cons 'control-receiver-ipv6 (list (cons 'raw control-receiver-ipv6) (cons 'formatted (fmt-ipv6-address control-receiver-ipv6))))
        (cons 'control-receiver-ipv4 (list (cons 'raw control-receiver-ipv4) (cons 'formatted (fmt-ipv4 control-receiver-ipv4))))
        (cons 'control-padding-length (list (cons 'raw control-padding-length) (cons 'formatted (number->string control-padding-length))))
        (cons 'control-type-p (list (cons 'raw control-type-p) (cons 'formatted (fmt-hex control-type-p))))
        (cons 'control-unused (list (cons 'raw control-unused) (cons 'formatted (fmt-bytes control-unused))))
        )))

    (catch (e)
      (err (str "TWAMP parse error: " e)))))

;; dissect-twamp: parse TWAMP from bytevector
;; Returns (ok fields-alist) or (err message)