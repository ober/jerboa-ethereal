;; packet-fcsp.c
;; Routines for Fibre Channel Security Protocol (FC-SP)
;; This decoder is for FC-SP version 1.1
;; Copyright 2003, Dinesh G Dutt <ddutt@cisco.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fcsp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fcsp.c

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
(def (dissect-fcsp buffer)
  "Fibre Channel Security Protocol"
  (try
    (let* (
           (flags (unwrap (read-u8 buffer 0)))
           (proto-ver (unwrap (read-u8 buffer 0)))
           (len (unwrap (read-u32be buffer 0)))
           (tid (unwrap (read-u32be buffer 0)))
           (dhchap-param-len (unwrap (read-u16be buffer 2)))
           (responder-name-len (unwrap (read-u16be buffer 12)))
           (responder-name (unwrap (slice buffer 12 1)))
           (dhchap-chal-len (unwrap (read-u32be buffer 12)))
           (dhchap-chal-value (unwrap (slice buffer 12 1)))
           (dhchap-val-len (unwrap (read-u32be buffer 12)))
           (dhchap-dhvalue (unwrap (slice buffer 12 1)))
           (dhchap-rsp-len (unwrap (read-u32be buffer 12)))
           (dhchap-rsp-value (unwrap (slice buffer 12 1)))
           (initiator-name-len (unwrap (read-u16be buffer 12)))
           (initiator-name (unwrap (slice buffer 12 1)))
           (usable-proto (unwrap (read-u32be buffer 12)))
           (proto-param-len (unwrap (read-u32be buffer 16)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'proto-ver (list (cons 'raw proto-ver) (cons 'formatted (fmt-hex proto-ver))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'tid (list (cons 'raw tid) (cons 'formatted (fmt-hex tid))))
        (cons 'dhchap-param-len (list (cons 'raw dhchap-param-len) (cons 'formatted (number->string dhchap-param-len))))
        (cons 'responder-name-len (list (cons 'raw responder-name-len) (cons 'formatted (number->string responder-name-len))))
        (cons 'responder-name (list (cons 'raw responder-name) (cons 'formatted (fmt-bytes responder-name))))
        (cons 'dhchap-chal-len (list (cons 'raw dhchap-chal-len) (cons 'formatted (number->string dhchap-chal-len))))
        (cons 'dhchap-chal-value (list (cons 'raw dhchap-chal-value) (cons 'formatted (fmt-bytes dhchap-chal-value))))
        (cons 'dhchap-val-len (list (cons 'raw dhchap-val-len) (cons 'formatted (number->string dhchap-val-len))))
        (cons 'dhchap-dhvalue (list (cons 'raw dhchap-dhvalue) (cons 'formatted (fmt-bytes dhchap-dhvalue))))
        (cons 'dhchap-rsp-len (list (cons 'raw dhchap-rsp-len) (cons 'formatted (number->string dhchap-rsp-len))))
        (cons 'dhchap-rsp-value (list (cons 'raw dhchap-rsp-value) (cons 'formatted (fmt-bytes dhchap-rsp-value))))
        (cons 'initiator-name-len (list (cons 'raw initiator-name-len) (cons 'formatted (number->string initiator-name-len))))
        (cons 'initiator-name (list (cons 'raw initiator-name) (cons 'formatted (fmt-bytes initiator-name))))
        (cons 'usable-proto (list (cons 'raw usable-proto) (cons 'formatted (number->string usable-proto))))
        (cons 'proto-param-len (list (cons 'raw proto-param-len) (cons 'formatted (number->string proto-param-len))))
        )))

    (catch (e)
      (err (str "FCSP parse error: " e)))))

;; dissect-fcsp: parse FCSP from bytevector
;; Returns (ok fields-alist) or (err message)