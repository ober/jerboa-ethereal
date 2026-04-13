;; packet-pw-atm.c
;; Routines for ATM PW dissection: it should be conform to RFC 4717.
;;
;; Copyright 2009 _FF_, _ATA_
;;
;; Francesco Fondelli <francesco dot fondelli, gmail dot com>
;; Artem Tamazov <artem [dot] tamazov [at] tellabs [dot] com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pw-atm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pw_atm.c
;; RFC 4717

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
(def (dissect-pw-atm buffer)
  "MPLS PW ATM Control Word"
  (try
    (let* (
           (payload-len (unwrap (read-u32be buffer 0)))
           (h-v (unwrap (read-u8 buffer 0)))
           (h-vpi (unwrap (read-u16be buffer 0)))
           (cw-a5s-u (unwrap (read-u8 buffer 0)))
           (cw-flags (unwrap (read-u8 buffer 0)))
           (bits03 (unwrap (read-u8 buffer 0)))
           (nocw-ncells (unwrap (read-u32be buffer 0)))
           (type-n1-nocw (unwrap (read-u8 buffer 0)))
           (cw-ncells (unwrap (read-u32be buffer 0)))
           (type-n1-cw (unwrap (read-u8 buffer 0)))
           (type-aal5-sdu (unwrap (read-u8 buffer 0)))
           (ncells (unwrap (read-u32be buffer 0)))
           (h-vci (unwrap (read-u16be buffer 1)))
           (cw-rsv (unwrap (read-u8 buffer 1)))
           (cw-atmbyte (unwrap (read-u8 buffer 3)))
           )

      (ok (list
        (cons 'payload-len (list (cons 'raw payload-len) (cons 'formatted (number->string payload-len))))
        (cons 'h-v (list (cons 'raw h-v) (cons 'formatted (if (= h-v 0) "False" "True"))))
        (cons 'h-vpi (list (cons 'raw h-vpi) (cons 'formatted (number->string h-vpi))))
        (cons 'cw-a5s-u (list (cons 'raw cw-a5s-u) (cons 'formatted (number->string cw-a5s-u))))
        (cons 'cw-flags (list (cons 'raw cw-flags) (cons 'formatted (fmt-hex cw-flags))))
        (cons 'bits03 (list (cons 'raw bits03) (cons 'formatted (fmt-hex bits03))))
        (cons 'nocw-ncells (list (cons 'raw nocw-ncells) (cons 'formatted (number->string nocw-ncells))))
        (cons 'type-n1-nocw (list (cons 'raw type-n1-nocw) (cons 'formatted (number->string type-n1-nocw))))
        (cons 'cw-ncells (list (cons 'raw cw-ncells) (cons 'formatted (number->string cw-ncells))))
        (cons 'type-n1-cw (list (cons 'raw type-n1-cw) (cons 'formatted (number->string type-n1-cw))))
        (cons 'type-aal5-sdu (list (cons 'raw type-aal5-sdu) (cons 'formatted (number->string type-aal5-sdu))))
        (cons 'ncells (list (cons 'raw ncells) (cons 'formatted (number->string ncells))))
        (cons 'h-vci (list (cons 'raw h-vci) (cons 'formatted (number->string h-vci))))
        (cons 'cw-rsv (list (cons 'raw cw-rsv) (cons 'formatted (number->string cw-rsv))))
        (cons 'cw-atmbyte (list (cons 'raw cw-atmbyte) (cons 'formatted (fmt-hex cw-atmbyte))))
        )))

    (catch (e)
      (err (str "PW-ATM parse error: " e)))))

;; dissect-pw-atm: parse PW-ATM from bytevector
;; Returns (ok fields-alist) or (err message)