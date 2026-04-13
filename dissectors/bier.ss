;; @file
;; Routines for Bit Index Explicit Replication (BIER) dissection
;;
;; Copyright 2024, John Thacker <johnthacker@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; RFC 8296: https://www.rfc-editor.org/rfc/rfc8296.html
;;

;; jerboa-ethereal/dissectors/bier.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bier.c
;; RFC 8296

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
(def (dissect-bier buffer)
  "Bit Index Explicit Replication"
  (try
    (let* (
           (nibble (unwrap (read-u8 buffer 0)))
           (ver (unwrap (read-u8 buffer 0)))
           (entropy (unwrap (read-u24be buffer 1)))
           (oam (unwrap (read-u8 buffer 4)))
           (rsv (unwrap (read-u8 buffer 4)))
           (dscp (unwrap (read-u16be buffer 4)))
           (bfir-id (unwrap (read-u16be buffer 6)))
           (bitstring (unwrap (slice buffer 8 1)))
           )

      (ok (list
        (cons 'nibble (list (cons 'raw nibble) (cons 'formatted (fmt-hex nibble))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'entropy (list (cons 'raw entropy) (cons 'formatted (fmt-hex entropy))))
        (cons 'oam (list (cons 'raw oam) (cons 'formatted (fmt-hex oam))))
        (cons 'rsv (list (cons 'raw rsv) (cons 'formatted (fmt-hex rsv))))
        (cons 'dscp (list (cons 'raw dscp) (cons 'formatted (fmt-hex dscp))))
        (cons 'bfir-id (list (cons 'raw bfir-id) (cons 'formatted (number->string bfir-id))))
        (cons 'bitstring (list (cons 'raw bitstring) (cons 'formatted (fmt-bytes bitstring))))
        )))

    (catch (e)
      (err (str "BIER parse error: " e)))))

;; dissect-bier: parse BIER from bytevector
;; Returns (ok fields-alist) or (err message)