;; packet-realtek.c
;; Routines for Realtek layer 2 protocols dissection
;;
;; Based on code from a 2004 submission
;; Copyright 2004, Horst Kronstorfer <hkronsto@frequentis.com>
;; but significantly modernized.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@ethereal.com>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/realtek.ss
;; Auto-generated from wireshark/epan/dissectors/packet-realtek.c

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
(def (dissect-realtek buffer)
  "Realtek Layer 2 Protocols"
  (try
    (let* (
           (packet (unwrap (slice buffer 0 1)))
           (protocol (unwrap (read-u8 buffer 0)))
           (reply (unwrap (read-u8 buffer 1)))
           (authkey (unwrap (read-u16be buffer 1)))
           (regaddr (unwrap (read-u16be buffer 1)))
           (regdata (unwrap (read-u16be buffer 1)))
           (hello-reply-dl-port (unwrap (read-u8 buffer 1)))
           (hello-reply-ul-port (unwrap (read-u8 buffer 1)))
           (hello-reply-ul-mac (unwrap (slice buffer 1 6)))
           (hello-reply-chip-id (unwrap (read-u16be buffer 1)))
           (hello-reply-vendor-id (unwrap (read-u32be buffer 1)))
           )

      (ok (list
        (cons 'packet (list (cons 'raw packet) (cons 'formatted (fmt-bytes packet))))
        (cons 'protocol (list (cons 'raw protocol) (cons 'formatted (fmt-hex protocol))))
        (cons 'reply (list (cons 'raw reply) (cons 'formatted (number->string reply))))
        (cons 'authkey (list (cons 'raw authkey) (cons 'formatted (fmt-hex authkey))))
        (cons 'regaddr (list (cons 'raw regaddr) (cons 'formatted (fmt-hex regaddr))))
        (cons 'regdata (list (cons 'raw regdata) (cons 'formatted (fmt-hex regdata))))
        (cons 'hello-reply-dl-port (list (cons 'raw hello-reply-dl-port) (cons 'formatted (number->string hello-reply-dl-port))))
        (cons 'hello-reply-ul-port (list (cons 'raw hello-reply-ul-port) (cons 'formatted (number->string hello-reply-ul-port))))
        (cons 'hello-reply-ul-mac (list (cons 'raw hello-reply-ul-mac) (cons 'formatted (fmt-mac hello-reply-ul-mac))))
        (cons 'hello-reply-chip-id (list (cons 'raw hello-reply-chip-id) (cons 'formatted (fmt-hex hello-reply-chip-id))))
        (cons 'hello-reply-vendor-id (list (cons 'raw hello-reply-vendor-id) (cons 'formatted (fmt-hex hello-reply-vendor-id))))
        )))

    (catch (e)
      (err (str "REALTEK parse error: " e)))))

;; dissect-realtek: parse REALTEK from bytevector
;; Returns (ok fields-alist) or (err message)