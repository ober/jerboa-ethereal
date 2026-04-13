;; packet-dcerpc-epm.c
;; Routines for dcerpc endpoint mapper dissection
;; Copyright 2001, Todd Sabin <tas@webspan.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dcerpc-epm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dcerpc_epm.c

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
(def (dissect-dcerpc-epm buffer)
  "DCE/RPC Endpoint Mapper"
  (try
    (let* (
           (annotation (unwrap (slice buffer 0 1)))
           (tower-num-floors (unwrap (read-u16be buffer 0)))
           (tower-lhs-len (unwrap (read-u16be buffer 2)))
           (uuid (unwrap (slice buffer 4 16)))
           (tower-rhs-len (unwrap (read-u16be buffer 4)))
           (ver-min (unwrap (read-u16be buffer 6)))
           (proto-tcp-port (unwrap (read-u16be buffer 6)))
           (proto-udp-port (unwrap (read-u16be buffer 6)))
           (proto-ip (unwrap (read-u32be buffer 6)))
           (proto-named-pipes (unwrap (slice buffer 6 1)))
           (proto-netbios-name (unwrap (slice buffer 6 1)))
           (proto-http-port (unwrap (read-u16be buffer 6)))
           )

      (ok (list
        (cons 'annotation (list (cons 'raw annotation) (cons 'formatted (utf8->string annotation))))
        (cons 'tower-num-floors (list (cons 'raw tower-num-floors) (cons 'formatted (number->string tower-num-floors))))
        (cons 'tower-lhs-len (list (cons 'raw tower-lhs-len) (cons 'formatted (number->string tower-lhs-len))))
        (cons 'uuid (list (cons 'raw uuid) (cons 'formatted (fmt-bytes uuid))))
        (cons 'tower-rhs-len (list (cons 'raw tower-rhs-len) (cons 'formatted (number->string tower-rhs-len))))
        (cons 'ver-min (list (cons 'raw ver-min) (cons 'formatted (number->string ver-min))))
        (cons 'proto-tcp-port (list (cons 'raw proto-tcp-port) (cons 'formatted (fmt-port proto-tcp-port))))
        (cons 'proto-udp-port (list (cons 'raw proto-udp-port) (cons 'formatted (fmt-port proto-udp-port))))
        (cons 'proto-ip (list (cons 'raw proto-ip) (cons 'formatted (fmt-ipv4 proto-ip))))
        (cons 'proto-named-pipes (list (cons 'raw proto-named-pipes) (cons 'formatted (utf8->string proto-named-pipes))))
        (cons 'proto-netbios-name (list (cons 'raw proto-netbios-name) (cons 'formatted (utf8->string proto-netbios-name))))
        (cons 'proto-http-port (list (cons 'raw proto-http-port) (cons 'formatted (fmt-port proto-http-port))))
        )))

    (catch (e)
      (err (str "DCERPC-EPM parse error: " e)))))

;; dissect-dcerpc-epm: parse DCERPC-EPM from bytevector
;; Returns (ok fields-alist) or (err message)