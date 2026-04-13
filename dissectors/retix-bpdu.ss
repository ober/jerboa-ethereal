;; packet-retix-bpdu.c
;; Routines for BPDU (Retix Spanning Tree Protocol) disassembly
;;
;; Copyright 2005 Giles Scott (gscott <AT> arubanetworks dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/retix-bpdu.ss
;; Auto-generated from wireshark/epan/dissectors/packet-retix_bpdu.c

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
(def (dissect-retix-bpdu buffer)
  "Retix Spanning Tree Protocol"
  (try
    (let* (
           (bpdu-root-mac (unwrap (slice buffer 0 6)))
           (bpdu-bridge-mac (unwrap (slice buffer 10 6)))
           (bpdu-max-age (unwrap (read-u16be buffer 20)))
           (bpdu-hello-time (unwrap (read-u16be buffer 22)))
           (bpdu-forward-delay (unwrap (read-u16be buffer 24)))
           )

      (ok (list
        (cons 'bpdu-root-mac (list (cons 'raw bpdu-root-mac) (cons 'formatted (fmt-mac bpdu-root-mac))))
        (cons 'bpdu-bridge-mac (list (cons 'raw bpdu-bridge-mac) (cons 'formatted (fmt-mac bpdu-bridge-mac))))
        (cons 'bpdu-max-age (list (cons 'raw bpdu-max-age) (cons 'formatted (number->string bpdu-max-age))))
        (cons 'bpdu-hello-time (list (cons 'raw bpdu-hello-time) (cons 'formatted (number->string bpdu-hello-time))))
        (cons 'bpdu-forward-delay (list (cons 'raw bpdu-forward-delay) (cons 'formatted (number->string bpdu-forward-delay))))
        )))

    (catch (e)
      (err (str "RETIX-BPDU parse error: " e)))))

;; dissect-retix-bpdu: parse RETIX-BPDU from bytevector
;; Returns (ok fields-alist) or (err message)