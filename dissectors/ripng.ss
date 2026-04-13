;; packet-ripng.c
;; Routines for RIPng disassembly
;; (c) Copyright Jun-ichiro itojun Hagino <itojun@itojun.org>
;; derived from packet-rip.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Enhance RIPng by Alexis La Goutte
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References:
;; RFC2080: RIPng for IPv6
;;

;; jerboa-ethereal/dissectors/ripng.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ripng.c
;; RFC 2080

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
(def (dissect-ripng buffer)
  "RIPng"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 1)))
           (reserved (unwrap (slice buffer 2 2)))
           (rte-ipv6-prefix (unwrap (slice buffer 4 16)))
           (rte-route-tag (unwrap (read-u16be buffer 20)))
           (rte-prefix-length (unwrap (read-u8 buffer 22)))
           (rte-metric (unwrap (read-u8 buffer 23)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'rte-ipv6-prefix (list (cons 'raw rte-ipv6-prefix) (cons 'formatted (fmt-ipv6-address rte-ipv6-prefix))))
        (cons 'rte-route-tag (list (cons 'raw rte-route-tag) (cons 'formatted (fmt-hex rte-route-tag))))
        (cons 'rte-prefix-length (list (cons 'raw rte-prefix-length) (cons 'formatted (number->string rte-prefix-length))))
        (cons 'rte-metric (list (cons 'raw rte-metric) (cons 'formatted (number->string rte-metric))))
        )))

    (catch (e)
      (err (str "RIPNG parse error: " e)))))

;; dissect-ripng: parse RIPNG from bytevector
;; Returns (ok fields-alist) or (err message)