;; packet-netrom.c
;;
;; Routines for Amateur Packet Radio protocol dissection
;; NET/ROM inter-node frames.
;; Copyright 2005,2006,2007,2008,2009,2010,2012 R.W. Stearn <richard@rns-stearn.demon.co.uk>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netrom.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netrom.c

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
(def (dissect-netrom buffer)
  "Amateur Radio NET/ROM"
  (try
    (let* (
           (ttl (unwrap (read-u8 buffer 0)))
           (my-cct-index (unwrap (read-u8 buffer 11)))
           (my-cct-id (unwrap (read-u8 buffer 12)))
           (n-s (unwrap (read-u8 buffer 23)))
           (your-cct-index (unwrap (read-u8 buffer 25)))
           (your-cct-id (unwrap (read-u8 buffer 26)))
           (n-r (unwrap (read-u8 buffer 28)))
           (pwindow (unwrap (read-u8 buffer 34)))
           (awindow (unwrap (read-u8 buffer 35)))
           )

      (ok (list
        (cons 'ttl (list (cons 'raw ttl) (cons 'formatted (fmt-hex ttl))))
        (cons 'my-cct-index (list (cons 'raw my-cct-index) (cons 'formatted (fmt-hex my-cct-index))))
        (cons 'my-cct-id (list (cons 'raw my-cct-id) (cons 'formatted (fmt-hex my-cct-id))))
        (cons 'n-s (list (cons 'raw n-s) (cons 'formatted (number->string n-s))))
        (cons 'your-cct-index (list (cons 'raw your-cct-index) (cons 'formatted (fmt-hex your-cct-index))))
        (cons 'your-cct-id (list (cons 'raw your-cct-id) (cons 'formatted (fmt-hex your-cct-id))))
        (cons 'n-r (list (cons 'raw n-r) (cons 'formatted (number->string n-r))))
        (cons 'pwindow (list (cons 'raw pwindow) (cons 'formatted (number->string pwindow))))
        (cons 'awindow (list (cons 'raw awindow) (cons 'formatted (number->string awindow))))
        )))

    (catch (e)
      (err (str "NETROM parse error: " e)))))

;; dissect-netrom: parse NETROM from bytevector
;; Returns (ok fields-alist) or (err message)