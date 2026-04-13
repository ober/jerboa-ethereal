;; packet-miwi-p2pstar.c
;; Dissector  routines for the Microchip MiWi_P2P_Star
;; Copyright 2013 Martin Leixner <info@sewio.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; ------------------------------------------------------------
;;

;; jerboa-ethereal/dissectors/miwi-p2pstar.ss
;; Auto-generated from wireshark/epan/dissectors/packet-miwi_p2pstar.c

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
(def (dissect-miwi-p2pstar buffer)
  "MiWi P2P Star (v6.4)"
  (try
    (let* (
           (src64-origin (unwrap (read-u32be buffer 0)))
           (seq (unwrap (read-u8 buffer 0)))
           (dst-panid (unwrap (read-u16be buffer 1)))
           (short-dst-addr (unwrap (read-u16be buffer 3)))
           (src-panid (unwrap (read-u16be buffer 13)))
           (short-src-addr (unwrap (read-u16be buffer 15)))
           (addr16 (unwrap (read-u16be buffer 15)))
           (fcs (unwrap (read-u16be buffer 25)))
           (fcs-ok (unwrap (read-u8 buffer 25)))
           )

      (ok (list
        (cons 'src64-origin (list (cons 'raw src64-origin) (cons 'formatted (number->string src64-origin))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'dst-panid (list (cons 'raw dst-panid) (cons 'formatted (fmt-hex dst-panid))))
        (cons 'short-dst-addr (list (cons 'raw short-dst-addr) (cons 'formatted (fmt-hex short-dst-addr))))
        (cons 'src-panid (list (cons 'raw src-panid) (cons 'formatted (fmt-hex src-panid))))
        (cons 'short-src-addr (list (cons 'raw short-src-addr) (cons 'formatted (fmt-hex short-src-addr))))
        (cons 'addr16 (list (cons 'raw addr16) (cons 'formatted (fmt-hex addr16))))
        (cons 'fcs (list (cons 'raw fcs) (cons 'formatted (fmt-hex fcs))))
        (cons 'fcs-ok (list (cons 'raw fcs-ok) (cons 'formatted (number->string fcs-ok))))
        )))

    (catch (e)
      (err (str "MIWI-P2PSTAR parse error: " e)))))

;; dissect-miwi-p2pstar: parse MIWI-P2PSTAR from bytevector
;; Returns (ok fields-alist) or (err message)