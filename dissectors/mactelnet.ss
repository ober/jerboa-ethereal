;; packet-mactelnet.c
;; Routines for MAC-Telnet dissection
;; Copyright 2010, Haakon Nessjoen <haakon.nessjoen@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mactelnet.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mactelnet.c

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
(def (dissect-mactelnet buffer)
  "MikroTik MAC-Telnet Protocol"
  (try
    (let* (
           (source-mac (unwrap (slice buffer 2 6)))
           (destination-mac (unwrap (slice buffer 8 6)))
           (session-id (unwrap (read-u16be buffer 18)))
           (databytes (unwrap (read-u32be buffer 26)))
           (control-packet (unwrap (read-u32be buffer 30)))
           (control-length (unwrap (read-u32be buffer 35)))
           (control-encryption-key (unwrap (slice buffer 39 1)))
           (control-password (unwrap (slice buffer 39 1)))
           (control-username (unwrap (slice buffer 39 1)))
           (control-terminal (unwrap (slice buffer 39 1)))
           (control-width (unwrap (read-u16be buffer 39)))
           (control-height (unwrap (read-u16be buffer 39)))
           (protocolver (unwrap (read-u8 buffer 41)))
           )

      (ok (list
        (cons 'source-mac (list (cons 'raw source-mac) (cons 'formatted (fmt-mac source-mac))))
        (cons 'destination-mac (list (cons 'raw destination-mac) (cons 'formatted (fmt-mac destination-mac))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (fmt-hex session-id))))
        (cons 'databytes (list (cons 'raw databytes) (cons 'formatted (number->string databytes))))
        (cons 'control-packet (list (cons 'raw control-packet) (cons 'formatted (fmt-hex control-packet))))
        (cons 'control-length (list (cons 'raw control-length) (cons 'formatted (number->string control-length))))
        (cons 'control-encryption-key (list (cons 'raw control-encryption-key) (cons 'formatted (fmt-bytes control-encryption-key))))
        (cons 'control-password (list (cons 'raw control-password) (cons 'formatted (fmt-bytes control-password))))
        (cons 'control-username (list (cons 'raw control-username) (cons 'formatted (utf8->string control-username))))
        (cons 'control-terminal (list (cons 'raw control-terminal) (cons 'formatted (utf8->string control-terminal))))
        (cons 'control-width (list (cons 'raw control-width) (cons 'formatted (number->string control-width))))
        (cons 'control-height (list (cons 'raw control-height) (cons 'formatted (number->string control-height))))
        (cons 'protocolver (list (cons 'raw protocolver) (cons 'formatted (number->string protocolver))))
        )))

    (catch (e)
      (err (str "MACTELNET parse error: " e)))))

;; dissect-mactelnet: parse MACTELNET from bytevector
;; Returns (ok fields-alist) or (err message)