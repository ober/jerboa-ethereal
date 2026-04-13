;; packet-iwarp-mpa.c
;; Routines for Marker Protocol data unit Aligned framing (MPA) dissection
;; According to IETF RFC 5044
;; Copyright 2008, Yves Geissbuehler <yves.geissbuehler@gmx.net>
;; Copyright 2008, Philip Frey <frey.philip@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/iwarp-mpa.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iwarp_mpa.c
;; RFC 5044

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
(def (dissect-iwarp-mpa buffer)
  "iWARP Marker Protocol data unit Aligned framing"
  (try
    (let* (
           (key-req (unwrap (slice buffer 0 1)))
           (key-rep (unwrap (slice buffer 0 1)))
           (flag-m (unwrap (read-u8 buffer 0)))
           (flag-c (unwrap (read-u8 buffer 0)))
           (flag-r (unwrap (read-u8 buffer 0)))
           (flag-s (unwrap (read-u8 buffer 0)))
           (flag-res (unwrap (read-u8 buffer 0)))
           (rev (unwrap (read-u8 buffer 0)))
           (enhanced-a (unwrap (read-u8 buffer 0)))
           (enhanced-b (unwrap (read-u8 buffer 0)))
           (enhanced-ird (unwrap (read-u16be buffer 0)))
           (pad (unwrap (slice buffer 0 1)))
           (enhanced-c (unwrap (read-u8 buffer 2)))
           (enhanced-d (unwrap (read-u8 buffer 2)))
           (enhanced-ord (unwrap (read-u16be buffer 2)))
           (private-data (unwrap (slice buffer 4 1)))
           (legacy-ird (unwrap (read-u32be buffer 4)))
           (legacy-ord (unwrap (read-u32be buffer 4)))
           (crc-check (unwrap (read-u32be buffer 4)))
           (crc (unwrap (read-u32be buffer 4)))
           (marker-res (unwrap (read-u16be buffer 4)))
           )

      (ok (list
        (cons 'key-req (list (cons 'raw key-req) (cons 'formatted (fmt-bytes key-req))))
        (cons 'key-rep (list (cons 'raw key-rep) (cons 'formatted (fmt-bytes key-rep))))
        (cons 'flag-m (list (cons 'raw flag-m) (cons 'formatted (number->string flag-m))))
        (cons 'flag-c (list (cons 'raw flag-c) (cons 'formatted (number->string flag-c))))
        (cons 'flag-r (list (cons 'raw flag-r) (cons 'formatted (number->string flag-r))))
        (cons 'flag-s (list (cons 'raw flag-s) (cons 'formatted (number->string flag-s))))
        (cons 'flag-res (list (cons 'raw flag-res) (cons 'formatted (fmt-hex flag-res))))
        (cons 'rev (list (cons 'raw rev) (cons 'formatted (number->string rev))))
        (cons 'enhanced-a (list (cons 'raw enhanced-a) (cons 'formatted (if (= enhanced-a 0) "False" "True"))))
        (cons 'enhanced-b (list (cons 'raw enhanced-b) (cons 'formatted (if (= enhanced-b 0) "False" "True"))))
        (cons 'enhanced-ird (list (cons 'raw enhanced-ird) (cons 'formatted (number->string enhanced-ird))))
        (cons 'pad (list (cons 'raw pad) (cons 'formatted (fmt-bytes pad))))
        (cons 'enhanced-c (list (cons 'raw enhanced-c) (cons 'formatted (if (= enhanced-c 0) "False" "True"))))
        (cons 'enhanced-d (list (cons 'raw enhanced-d) (cons 'formatted (if (= enhanced-d 0) "False" "True"))))
        (cons 'enhanced-ord (list (cons 'raw enhanced-ord) (cons 'formatted (number->string enhanced-ord))))
        (cons 'private-data (list (cons 'raw private-data) (cons 'formatted (fmt-bytes private-data))))
        (cons 'legacy-ird (list (cons 'raw legacy-ird) (cons 'formatted (number->string legacy-ird))))
        (cons 'legacy-ord (list (cons 'raw legacy-ord) (cons 'formatted (number->string legacy-ord))))
        (cons 'crc-check (list (cons 'raw crc-check) (cons 'formatted (fmt-hex crc-check))))
        (cons 'crc (list (cons 'raw crc) (cons 'formatted (fmt-hex crc))))
        (cons 'marker-res (list (cons 'raw marker-res) (cons 'formatted (fmt-hex marker-res))))
        )))

    (catch (e)
      (err (str "IWARP-MPA parse error: " e)))))

;; dissect-iwarp-mpa: parse IWARP-MPA from bytevector
;; Returns (ok fields-alist) or (err message)