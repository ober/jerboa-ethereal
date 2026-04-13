;; packet-gmhdr.c
;; Routines for Gigamon header disassembly (modified from packet-vlan.c)
;;
;; Dissector for Gigamon Header and Trailer
;; Copyright Gigamon 2010
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gmhdr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gmhdr.c

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
(def (dissect-gmhdr buffer)
  "Gigamon Header"
  (try
    (let* (
           (portid (unwrap (read-u16be buffer 0)))
           (srcport-g-gid (unwrap (read-u24be buffer 2)))
           (srcport-g-bid (unwrap (read-u24be buffer 2)))
           (srcport-g-pid (unwrap (read-u24be buffer 2)))
           (pktsize (unwrap (read-u16be buffer 2)))
           (origcrc (unwrap (read-u32be buffer 2)))
           (srcport-h (unwrap (read-u32be buffer 2)))
           (srcport-h-gid (unwrap (read-u32be buffer 2)))
           (srcport-h-bid (unwrap (read-u32be buffer 2)))
           (srcport-h-sid (unwrap (read-u32be buffer 2)))
           (srcport-h-pid (unwrap (read-u32be buffer 2)))
           (generic (unwrap (slice buffer 2 1)))
           (srcport-g (unwrap (read-u24be buffer 6)))
           )

      (ok (list
        (cons 'portid (list (cons 'raw portid) (cons 'formatted (fmt-hex portid))))
        (cons 'srcport-g-gid (list (cons 'raw srcport-g-gid) (cons 'formatted (number->string srcport-g-gid))))
        (cons 'srcport-g-bid (list (cons 'raw srcport-g-bid) (cons 'formatted (number->string srcport-g-bid))))
        (cons 'srcport-g-pid (list (cons 'raw srcport-g-pid) (cons 'formatted (number->string srcport-g-pid))))
        (cons 'pktsize (list (cons 'raw pktsize) (cons 'formatted (number->string pktsize))))
        (cons 'origcrc (list (cons 'raw origcrc) (cons 'formatted (fmt-hex origcrc))))
        (cons 'srcport-h (list (cons 'raw srcport-h) (cons 'formatted (fmt-hex srcport-h))))
        (cons 'srcport-h-gid (list (cons 'raw srcport-h-gid) (cons 'formatted (number->string srcport-h-gid))))
        (cons 'srcport-h-bid (list (cons 'raw srcport-h-bid) (cons 'formatted (number->string srcport-h-bid))))
        (cons 'srcport-h-sid (list (cons 'raw srcport-h-sid) (cons 'formatted (number->string srcport-h-sid))))
        (cons 'srcport-h-pid (list (cons 'raw srcport-h-pid) (cons 'formatted (number->string srcport-h-pid))))
        (cons 'generic (list (cons 'raw generic) (cons 'formatted (fmt-bytes generic))))
        (cons 'srcport-g (list (cons 'raw srcport-g) (cons 'formatted (fmt-hex srcport-g))))
        )))

    (catch (e)
      (err (str "GMHDR parse error: " e)))))

;; dissect-gmhdr: parse GMHDR from bytevector
;; Returns (ok fields-alist) or (err message)