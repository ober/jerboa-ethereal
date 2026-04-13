;; packet-lwm.c
;; Dissector  routines for the ATMEL Lightweight Mesh 1.1.1
;; Copyright 2013 Martin Leixner <info@sewio.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; ------------------------------------------------------------
;;

;; jerboa-ethereal/dissectors/lwm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lwm.c

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
(def (dissect-lwm buffer)
  "Lightweight Mesh (v1.1.1)"
  (try
    (let* (
           (fcf-reserved (unwrap (read-u8 buffer 0)))
           (fcf-multicast (unwrap (read-u8 buffer 0)))
           (fcf-linklocal (unwrap (read-u8 buffer 0)))
           (fcf-security (unwrap (read-u8 buffer 0)))
           (fcf-ack-req (unwrap (read-u8 buffer 0)))
           (fcf (unwrap (read-u8 buffer 0)))
           (seq (unwrap (read-u8 buffer 1)))
           (src-addr (unwrap (read-u16be buffer 2)))
           (dst-addr (unwrap (read-u16be buffer 4)))
           (dst-endp (unwrap (read-u8 buffer 6)))
           (src-endp (unwrap (read-u8 buffer 6)))
           (multi-mmrad (unwrap (read-u16be buffer 7)))
           (multi-mrad (unwrap (read-u16be buffer 7)))
           (multi-mnmrad (unwrap (read-u16be buffer 7)))
           (multi-nmrad (unwrap (read-u16be buffer 7)))
           )

      (ok (list
        (cons 'fcf-reserved (list (cons 'raw fcf-reserved) (cons 'formatted (fmt-hex fcf-reserved))))
        (cons 'fcf-multicast (list (cons 'raw fcf-multicast) (cons 'formatted (number->string fcf-multicast))))
        (cons 'fcf-linklocal (list (cons 'raw fcf-linklocal) (cons 'formatted (number->string fcf-linklocal))))
        (cons 'fcf-security (list (cons 'raw fcf-security) (cons 'formatted (number->string fcf-security))))
        (cons 'fcf-ack-req (list (cons 'raw fcf-ack-req) (cons 'formatted (number->string fcf-ack-req))))
        (cons 'fcf (list (cons 'raw fcf) (cons 'formatted (fmt-hex fcf))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'src-addr (list (cons 'raw src-addr) (cons 'formatted (fmt-hex src-addr))))
        (cons 'dst-addr (list (cons 'raw dst-addr) (cons 'formatted (fmt-hex dst-addr))))
        (cons 'dst-endp (list (cons 'raw dst-endp) (cons 'formatted (number->string dst-endp))))
        (cons 'src-endp (list (cons 'raw src-endp) (cons 'formatted (number->string src-endp))))
        (cons 'multi-mmrad (list (cons 'raw multi-mmrad) (cons 'formatted (number->string multi-mmrad))))
        (cons 'multi-mrad (list (cons 'raw multi-mrad) (cons 'formatted (number->string multi-mrad))))
        (cons 'multi-mnmrad (list (cons 'raw multi-mnmrad) (cons 'formatted (number->string multi-mnmrad))))
        (cons 'multi-nmrad (list (cons 'raw multi-nmrad) (cons 'formatted (number->string multi-nmrad))))
        )))

    (catch (e)
      (err (str "LWM parse error: " e)))))

;; dissect-lwm: parse LWM from bytevector
;; Returns (ok fields-alist) or (err message)