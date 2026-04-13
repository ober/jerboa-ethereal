;; packet-aruba-iap.c
;; Routines for Aruba IAP header disassembly
;; Copyright 2014, Alexis La Goutte <alexis.lagoutte at gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/aruba-iap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-aruba_iap.c

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
(def (dissect-aruba-iap buffer)
  "Aruba Instant AP Protocol"
  (try
    (let* (
           (magic (unwrap (read-u16be buffer 0)))
           (version (unwrap (read-u8 buffer 2)))
           (type (unwrap (read-u8 buffer 3)))
           (length (unwrap (read-u8 buffer 4)))
           (id (unwrap (read-u8 buffer 5)))
           (status (unwrap (read-u8 buffer 6)))
           (uptime (unwrap (read-u32be buffer 7)))
           (vc-ip (unwrap (read-u32be buffer 11)))
           (pvid (unwrap (read-u16be buffer 16)))
           (unknown-uint (unwrap (read-u32be buffer 18)))
           (unknown-bytes (unwrap (slice buffer 22 1)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (number->string type))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (number->string status))))
        (cons 'uptime (list (cons 'raw uptime) (cons 'formatted (number->string uptime))))
        (cons 'vc-ip (list (cons 'raw vc-ip) (cons 'formatted (fmt-ipv4 vc-ip))))
        (cons 'pvid (list (cons 'raw pvid) (cons 'formatted (number->string pvid))))
        (cons 'unknown-uint (list (cons 'raw unknown-uint) (cons 'formatted (number->string unknown-uint))))
        (cons 'unknown-bytes (list (cons 'raw unknown-bytes) (cons 'formatted (fmt-bytes unknown-bytes))))
        )))

    (catch (e)
      (err (str "ARUBA-IAP parse error: " e)))))

;; dissect-aruba-iap: parse ARUBA-IAP from bytevector
;; Returns (ok fields-alist) or (err message)