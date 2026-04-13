;; packet-spp.c
;; Routines for XNS SPP
;; Based on the Netware SPX dissector by Gilbert Ramirez <gram@alumni.rice.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/spp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-spp.c

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
(def (dissect-spp buffer)
  "Sequenced Packet Protocol"
  (try
    (let* (
           (connection-control (unwrap (read-u8 buffer 0)))
           (connection-control-sys (extract-bits connection-control 0x0 0))
           (connection-control-send-ack (extract-bits connection-control 0x0 0))
           (connection-control-attn (extract-bits connection-control 0x0 0))
           (connection-control-eom (extract-bits connection-control 0x0 0))
           (datastream-type (unwrap (read-u8 buffer 1)))
           (src-id (unwrap (read-u16be buffer 2)))
           (dst-id (unwrap (read-u16be buffer 4)))
           (seq-nr (unwrap (read-u16be buffer 6)))
           (ack-nr (unwrap (read-u16be buffer 8)))
           (all-nr (unwrap (read-u16be buffer 10)))
           )

      (ok (list
        (cons 'connection-control (list (cons 'raw connection-control) (cons 'formatted (fmt-hex connection-control))))
        (cons 'connection-control-sys (list (cons 'raw connection-control-sys) (cons 'formatted (if (= connection-control-sys 0) "Not set" "Set"))))
        (cons 'connection-control-send-ack (list (cons 'raw connection-control-send-ack) (cons 'formatted (if (= connection-control-send-ack 0) "Not set" "Set"))))
        (cons 'connection-control-attn (list (cons 'raw connection-control-attn) (cons 'formatted (if (= connection-control-attn 0) "Not set" "Set"))))
        (cons 'connection-control-eom (list (cons 'raw connection-control-eom) (cons 'formatted (if (= connection-control-eom 0) "Not set" "Set"))))
        (cons 'datastream-type (list (cons 'raw datastream-type) (cons 'formatted (fmt-hex datastream-type))))
        (cons 'src-id (list (cons 'raw src-id) (cons 'formatted (number->string src-id))))
        (cons 'dst-id (list (cons 'raw dst-id) (cons 'formatted (number->string dst-id))))
        (cons 'seq-nr (list (cons 'raw seq-nr) (cons 'formatted (number->string seq-nr))))
        (cons 'ack-nr (list (cons 'raw ack-nr) (cons 'formatted (number->string ack-nr))))
        (cons 'all-nr (list (cons 'raw all-nr) (cons 'formatted (number->string all-nr))))
        )))

    (catch (e)
      (err (str "SPP parse error: " e)))))

;; dissect-spp: parse SPP from bytevector
;; Returns (ok fields-alist) or (err message)