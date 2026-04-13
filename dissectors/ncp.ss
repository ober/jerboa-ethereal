;; packet-ncp.c
;; Routines for NetWare Core Protocol
;; Gilbert Ramirez <gram@alumni.rice.edu>
;; Modified to allow NCP over TCP/IP decodes by James Coe <jammer@cin.net>
;; Modified to decode server op-lock, packet signature,
;; & NDS packets by Greg Morris <gmorris@novell.com>
;;
;; Portions Copyright (c) by Gilbert Ramirez 2000-2002
;; Portions Copyright (c) by James Coe 2000-2002
;; Portions Copyright (c) Novell, Inc. 2000-2003
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 2000 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ncp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ncp.c

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
(def (dissect-ncp buffer)
  "NetWare Core Protocol"
  (try
    (let* (
           (burst-file-handle (unwrap (read-u32be buffer 4)))
           (burst-reserved (unwrap (slice buffer 8 8)))
           (burst-offset (unwrap (read-u32be buffer 16)))
           (burst-len (unwrap (read-u32be buffer 20)))
           (missing-data-offset (unwrap (read-u32be buffer 24)))
           (missing-data-count (unwrap (read-u16be buffer 28)))
           )

      (ok (list
        (cons 'burst-file-handle (list (cons 'raw burst-file-handle) (cons 'formatted (fmt-hex burst-file-handle))))
        (cons 'burst-reserved (list (cons 'raw burst-reserved) (cons 'formatted (fmt-bytes burst-reserved))))
        (cons 'burst-offset (list (cons 'raw burst-offset) (cons 'formatted (number->string burst-offset))))
        (cons 'burst-len (list (cons 'raw burst-len) (cons 'formatted (number->string burst-len))))
        (cons 'missing-data-offset (list (cons 'raw missing-data-offset) (cons 'formatted (number->string missing-data-offset))))
        (cons 'missing-data-count (list (cons 'raw missing-data-count) (cons 'formatted (number->string missing-data-count))))
        )))

    (catch (e)
      (err (str "NCP parse error: " e)))))

;; dissect-ncp: parse NCP from bytevector
;; Returns (ok fields-alist) or (err message)