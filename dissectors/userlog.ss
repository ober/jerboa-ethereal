;; packet-userlog.c
;; Routines for userlog protocol packet disassembly
;; Copyright 2016,  Jun Wang <sdn_app@163.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/userlog.ss
;; Auto-generated from wireshark/epan/dissectors/packet-userlog.c

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
(def (dissect-userlog buffer)
  "UserLog Protocol"
  (try
    (let* (
           (count (unwrap (read-u16be buffer 2)))
           (header-reserved (unwrap (slice buffer 8 8)))
           (IPVerion (unwrap (read-u8 buffer 18)))
           (IPToS (unwrap (read-u8 buffer 19)))
           (SourceIP (unwrap (read-u32be buffer 20)))
           (SrcNatIP (unwrap (read-u32be buffer 24)))
           (DestIP (unwrap (read-u32be buffer 28)))
           (DestNatIP (unwrap (read-u32be buffer 32)))
           (SrcPort (unwrap (read-u16be buffer 36)))
           (SrcNatPort (unwrap (read-u16be buffer 38)))
           (DestPort (unwrap (read-u16be buffer 40)))
           (DestNatPort (unwrap (read-u16be buffer 42)))
           (InTotalPkg (unwrap (read-u32be buffer 52)))
           (InTotalByte (unwrap (read-u32be buffer 56)))
           (OutTotalPkg (unwrap (read-u32be buffer 60)))
           (OutTotalByte (unwrap (read-u32be buffer 64)))
           (Reserved1 (unwrap (read-u32be buffer 68)))
           (Reserved2 (unwrap (read-u32be buffer 72)))
           (Reserved3 (unwrap (read-u32be buffer 76)))
           )

      (ok (list
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'header-reserved (list (cons 'raw header-reserved) (cons 'formatted (fmt-bytes header-reserved))))
        (cons 'IPVerion (list (cons 'raw IPVerion) (cons 'formatted (number->string IPVerion))))
        (cons 'IPToS (list (cons 'raw IPToS) (cons 'formatted (number->string IPToS))))
        (cons 'SourceIP (list (cons 'raw SourceIP) (cons 'formatted (fmt-ipv4 SourceIP))))
        (cons 'SrcNatIP (list (cons 'raw SrcNatIP) (cons 'formatted (fmt-ipv4 SrcNatIP))))
        (cons 'DestIP (list (cons 'raw DestIP) (cons 'formatted (fmt-ipv4 DestIP))))
        (cons 'DestNatIP (list (cons 'raw DestNatIP) (cons 'formatted (fmt-ipv4 DestNatIP))))
        (cons 'SrcPort (list (cons 'raw SrcPort) (cons 'formatted (number->string SrcPort))))
        (cons 'SrcNatPort (list (cons 'raw SrcNatPort) (cons 'formatted (number->string SrcNatPort))))
        (cons 'DestPort (list (cons 'raw DestPort) (cons 'formatted (number->string DestPort))))
        (cons 'DestNatPort (list (cons 'raw DestNatPort) (cons 'formatted (number->string DestNatPort))))
        (cons 'InTotalPkg (list (cons 'raw InTotalPkg) (cons 'formatted (number->string InTotalPkg))))
        (cons 'InTotalByte (list (cons 'raw InTotalByte) (cons 'formatted (number->string InTotalByte))))
        (cons 'OutTotalPkg (list (cons 'raw OutTotalPkg) (cons 'formatted (number->string OutTotalPkg))))
        (cons 'OutTotalByte (list (cons 'raw OutTotalByte) (cons 'formatted (number->string OutTotalByte))))
        (cons 'Reserved1 (list (cons 'raw Reserved1) (cons 'formatted (number->string Reserved1))))
        (cons 'Reserved2 (list (cons 'raw Reserved2) (cons 'formatted (number->string Reserved2))))
        (cons 'Reserved3 (list (cons 'raw Reserved3) (cons 'formatted (number->string Reserved3))))
        )))

    (catch (e)
      (err (str "USERLOG parse error: " e)))))

;; dissect-userlog: parse USERLOG from bytevector
;; Returns (ok fields-alist) or (err message)