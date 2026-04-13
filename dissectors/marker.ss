;; packet-marker.c
;; Routines for Link Aggregation Marker protocol dissection.
;; IEEE Std 802.1AX-2014 Section 6.5
;;
;; Copyright 2002 Steve Housley <steve_housley@3com.com>
;; Copyright 2005 Dominique Bastien <dbastien@accedian.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/marker.ss
;; Auto-generated from wireshark/epan/dissectors/packet-marker.c

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
(def (dissect-marker buffer)
  "Link Aggregation Marker Protocol"
  (try
    (let* (
           (version-number (unwrap (read-u8 buffer 0)))
           (req-port (unwrap (read-u16be buffer 3)))
           (req-system (unwrap (slice buffer 5 6)))
           (req-trans-id (unwrap (read-u32be buffer 11)))
           (req-pad (unwrap (read-u32be buffer 15)))
           (tlv-length (unwrap (read-u8 buffer 18)))
           (reserved (unwrap (slice buffer 19 90)))
           )

      (ok (list
        (cons 'version-number (list (cons 'raw version-number) (cons 'formatted (fmt-hex version-number))))
        (cons 'req-port (list (cons 'raw req-port) (cons 'formatted (number->string req-port))))
        (cons 'req-system (list (cons 'raw req-system) (cons 'formatted (fmt-mac req-system))))
        (cons 'req-trans-id (list (cons 'raw req-trans-id) (cons 'formatted (number->string req-trans-id))))
        (cons 'req-pad (list (cons 'raw req-pad) (cons 'formatted (number->string req-pad))))
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (fmt-hex tlv-length))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        )))

    (catch (e)
      (err (str "MARKER parse error: " e)))))

;; dissect-marker: parse MARKER from bytevector
;; Returns (ok fields-alist) or (err message)