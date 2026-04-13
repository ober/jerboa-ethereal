;;
;; packet-ppi.c
;; Routines for PPI Packet Header dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 2007 Gerald Combs
;;
;; Copyright (c) 2006 CACE Technologies, Davis (California)
;; All rights reserved.
;;
;; SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
;;
;;
;; Dustin Johnson - Dustin@Dustinj.us, Dustin.Johnson@cacetech.com
;; May 7, 2008 - Added 'Aggregation Extension' and '802.3 Extension'
;;

;; jerboa-ethereal/dissectors/ppi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ppi.c

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
(def (dissect-ppi buffer)
  "PPI Packet Header"
  (try
    (let* (
           (count (unwrap (read-u16be buffer 0)))
           (reassembled-in (unwrap (read-u32be buffer 0)))
           (segment (unwrap (read-u32be buffer 0)))
           (head-version (unwrap (read-u8 buffer 0)))
           (head-flags (unwrap (read-u8 buffer 0)))
           (head-flag-alignment (unwrap (read-u8 buffer 0)))
           (head-flag-reserved (unwrap (read-u8 buffer 0)))
           (head-len (unwrap (read-u16be buffer 0)))
           (head-dlt (unwrap (read-u32be buffer 0)))
           (gps (unwrap (slice buffer 8 1)))
           (vector (unwrap (slice buffer 8 1)))
           (harris (unwrap (slice buffer 8 1)))
           (antenna (unwrap (slice buffer 8 1)))
           (fnet (unwrap (slice buffer 8 1)))
           (reserved (unwrap (slice buffer 8 1)))
           )

      (ok (list
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'reassembled-in (list (cons 'raw reassembled-in) (cons 'formatted (number->string reassembled-in))))
        (cons 'segment (list (cons 'raw segment) (cons 'formatted (number->string segment))))
        (cons 'head-version (list (cons 'raw head-version) (cons 'formatted (number->string head-version))))
        (cons 'head-flags (list (cons 'raw head-flags) (cons 'formatted (fmt-hex head-flags))))
        (cons 'head-flag-alignment (list (cons 'raw head-flag-alignment) (cons 'formatted (if (= head-flag-alignment 0) "Not aligned" "32-bit aligned"))))
        (cons 'head-flag-reserved (list (cons 'raw head-flag-reserved) (cons 'formatted (fmt-hex head-flag-reserved))))
        (cons 'head-len (list (cons 'raw head-len) (cons 'formatted (number->string head-len))))
        (cons 'head-dlt (list (cons 'raw head-dlt) (cons 'formatted (number->string head-dlt))))
        (cons 'gps (list (cons 'raw gps) (cons 'formatted (fmt-bytes gps))))
        (cons 'vector (list (cons 'raw vector) (cons 'formatted (fmt-bytes vector))))
        (cons 'harris (list (cons 'raw harris) (cons 'formatted (fmt-bytes harris))))
        (cons 'antenna (list (cons 'raw antenna) (cons 'formatted (fmt-bytes antenna))))
        (cons 'fnet (list (cons 'raw fnet) (cons 'formatted (fmt-bytes fnet))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        )))

    (catch (e)
      (err (str "PPI parse error: " e)))))

;; dissect-ppi: parse PPI from bytevector
;; Returns (ok fields-alist) or (err message)