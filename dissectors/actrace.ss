;; packet-actrace.c
;; Routines for AudioCodes Trunk traces packet disassembly
;;
;; Copyright (c) 2005 by Alejandro Vaquero <alejandro.vaquero@verso.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/actrace.ss
;; Auto-generated from wireshark/epan/dissectors/packet-actrace.c

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
(def (dissect-actrace buffer)
  "Trunk Trace"
  (try
    (let* (
           (cas-current-state (unwrap (read-u32be buffer 8)))
           (isdn-trunk (unwrap (read-u16be buffer 8)))
           (cas-next-state (unwrap (read-u32be buffer 16)))
           (cas-par0 (unwrap (read-u32be buffer 24)))
           (cas-par1 (unwrap (read-u32be buffer 28)))
           (cas-par2 (unwrap (read-u32be buffer 32)))
           (cas-trunk (unwrap (read-u32be buffer 36)))
           (cas-bchannel (unwrap (read-u32be buffer 40)))
           (cas-connection-id (unwrap (read-u32be buffer 44)))
           (isdn-length (unwrap (read-u16be buffer 44)))
           (cas-time (unwrap (read-u32be buffer 48)))
           )

      (ok (list
        (cons 'cas-current-state (list (cons 'raw cas-current-state) (cons 'formatted (number->string cas-current-state))))
        (cons 'isdn-trunk (list (cons 'raw isdn-trunk) (cons 'formatted (number->string isdn-trunk))))
        (cons 'cas-next-state (list (cons 'raw cas-next-state) (cons 'formatted (number->string cas-next-state))))
        (cons 'cas-par0 (list (cons 'raw cas-par0) (cons 'formatted (number->string cas-par0))))
        (cons 'cas-par1 (list (cons 'raw cas-par1) (cons 'formatted (number->string cas-par1))))
        (cons 'cas-par2 (list (cons 'raw cas-par2) (cons 'formatted (number->string cas-par2))))
        (cons 'cas-trunk (list (cons 'raw cas-trunk) (cons 'formatted (number->string cas-trunk))))
        (cons 'cas-bchannel (list (cons 'raw cas-bchannel) (cons 'formatted (number->string cas-bchannel))))
        (cons 'cas-connection-id (list (cons 'raw cas-connection-id) (cons 'formatted (number->string cas-connection-id))))
        (cons 'isdn-length (list (cons 'raw isdn-length) (cons 'formatted (number->string isdn-length))))
        (cons 'cas-time (list (cons 'raw cas-time) (cons 'formatted (number->string cas-time))))
        )))

    (catch (e)
      (err (str "ACTRACE parse error: " e)))))

;; dissect-actrace: parse ACTRACE from bytevector
;; Returns (ok fields-alist) or (err message)