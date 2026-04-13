;; packet-btamp.c
;; Routines for the Bluetooth AMP dissection
;;
;; Copyright 2009, Kovarththanan Rajaratnam <kovarththanan.rajaratnam@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btamp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btamp.c

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
(def (dissect-btamp buffer)
  "Bluetooth AMP Packet"
  (try
    (let* (
           (cmd-ident (unwrap (read-u8 buffer 1)))
           (cmd-length (unwrap (read-u16be buffer 2)))
           (mtu (unwrap (read-u16be buffer 9)))
           (extfeatures (unwrap (read-u16be buffer 11)))
           (total-bw (unwrap (read-u32be buffer 16)))
           (max-guaran-bw (unwrap (read-u32be buffer 20)))
           (min-latency (unwrap (read-u32be buffer 24)))
           (pal-caps-guaranteed (unwrap (read-u8 buffer 28)))
           (amp-assoc-size (unwrap (read-u16be buffer 30)))
           (amp-assoc (unwrap (slice buffer 33 1)))
           (controller-id (unwrap (read-u8 buffer 33)))
           (lcontroller-id (unwrap (read-u8 buffer 42)))
           (rcontroller-id (unwrap (read-u8 buffer 43)))
           )

      (ok (list
        (cons 'cmd-ident (list (cons 'raw cmd-ident) (cons 'formatted (fmt-hex cmd-ident))))
        (cons 'cmd-length (list (cons 'raw cmd-length) (cons 'formatted (number->string cmd-length))))
        (cons 'mtu (list (cons 'raw mtu) (cons 'formatted (fmt-hex mtu))))
        (cons 'extfeatures (list (cons 'raw extfeatures) (cons 'formatted (fmt-hex extfeatures))))
        (cons 'total-bw (list (cons 'raw total-bw) (cons 'formatted (fmt-hex total-bw))))
        (cons 'max-guaran-bw (list (cons 'raw max-guaran-bw) (cons 'formatted (fmt-hex max-guaran-bw))))
        (cons 'min-latency (list (cons 'raw min-latency) (cons 'formatted (fmt-hex min-latency))))
        (cons 'pal-caps-guaranteed (list (cons 'raw pal-caps-guaranteed) (cons 'formatted (number->string pal-caps-guaranteed))))
        (cons 'amp-assoc-size (list (cons 'raw amp-assoc-size) (cons 'formatted (fmt-hex amp-assoc-size))))
        (cons 'amp-assoc (list (cons 'raw amp-assoc) (cons 'formatted (fmt-bytes amp-assoc))))
        (cons 'controller-id (list (cons 'raw controller-id) (cons 'formatted (number->string controller-id))))
        (cons 'lcontroller-id (list (cons 'raw lcontroller-id) (cons 'formatted (number->string lcontroller-id))))
        (cons 'rcontroller-id (list (cons 'raw rcontroller-id) (cons 'formatted (number->string rcontroller-id))))
        )))

    (catch (e)
      (err (str "BTAMP parse error: " e)))))

;; dissect-btamp: parse BTAMP from bytevector
;; Returns (ok fields-alist) or (err message)