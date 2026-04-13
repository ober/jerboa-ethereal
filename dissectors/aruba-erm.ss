;; packet-aruba-erm.c
;; Routines for the disassembly of Aruba encapsulated remote mirroring frames
;; (Adapted from packet-hp-erm.c and packet-cisco-erspan.c)
;;
;; Copyright 2010  Alexis La Goutte <alexis.lagoutte at gmail dot com>
;;
;; ERM Radio-Format added by Hadriel Kaplan
;;
;; Type 6 added by Jeffrey Goff <jgoff at arubanetworks dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/aruba-erm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-aruba_erm.c

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
(def (dissect-aruba-erm buffer)
  "Aruba Networks encapsulated remote mirroring"
  (try
    (let* (
           (erm-data-rate (unwrap (read-u16be buffer 0)))
           (erm-channel (unwrap (read-u8 buffer 2)))
           (erm-signal-strength (unwrap (read-u8 buffer 3)))
           (erm-incl-len (unwrap (read-u32be buffer 8)))
           (erm-orig-len (unwrap (read-u32be buffer 12)))
           (erm-data-rate-gen (unwrap (read-u32be buffer 16)))
           )

      (ok (list
        (cons 'erm-data-rate (list (cons 'raw erm-data-rate) (cons 'formatted (number->string erm-data-rate))))
        (cons 'erm-channel (list (cons 'raw erm-channel) (cons 'formatted (number->string erm-channel))))
        (cons 'erm-signal-strength (list (cons 'raw erm-signal-strength) (cons 'formatted (number->string erm-signal-strength))))
        (cons 'erm-incl-len (list (cons 'raw erm-incl-len) (cons 'formatted (number->string erm-incl-len))))
        (cons 'erm-orig-len (list (cons 'raw erm-orig-len) (cons 'formatted (number->string erm-orig-len))))
        (cons 'erm-data-rate-gen (list (cons 'raw erm-data-rate-gen) (cons 'formatted (number->string erm-data-rate-gen))))
        )))

    (catch (e)
      (err (str "ARUBA-ERM parse error: " e)))))

;; dissect-aruba-erm: parse ARUBA-ERM from bytevector
;; Returns (ok fields-alist) or (err message)