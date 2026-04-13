;; packet-rmt-alc.c
;; Reliable Multicast Transport (RMT)
;; ALC Protocol Instantiation dissector
;; Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
;; Copyright 2023, Sergey V. Lobanov <sergey@lobanov.in>
;;
;; Asynchronous Layered Coding (ALC):
;; ----------------------------------
;;
;; A massively scalable reliable content delivery protocol.
;; Asynchronous Layered Coding combines the Layered Coding Transport
;; (LCT) building block, a multiple rate congestion control building
;; block and the Forward Error Correction (FEC) building block to
;; provide congestion controlled reliable asynchronous delivery of
;; content to an unlimited number of concurrent receivers from a single
;; sender.
;;
;; References:
;; RFC 3450, Asynchronous Layered Coding protocol instantiation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rmt-alc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rmt_alc.c
;; RFC 3450

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
(def (dissect-rmt-alc buffer)
  "Asynchronous Layered Coding"
  (try
    (let* (
           (start-offset (unwrap (read-u32be buffer 0)))
           (hf-payload (unwrap (slice buffer 4 1)))
           (hf-version (unwrap (read-u8 buffer 5)))
           )

      (ok (list
        (cons 'start-offset (list (cons 'raw start-offset) (cons 'formatted (number->string start-offset))))
        (cons 'hf-payload (list (cons 'raw hf-payload) (cons 'formatted (fmt-bytes hf-payload))))
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        )))

    (catch (e)
      (err (str "RMT-ALC parse error: " e)))))

;; dissect-rmt-alc: parse RMT-ALC from bytevector
;; Returns (ok fields-alist) or (err message)