;; packet-pana.c
;; Routines for Protocol for carrying Authentication for Network Access dissection
;; Copyright 2006, Peter Racz <racz@ifi.unizh.ch>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pana.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pana.c
;; RFC 5191

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
(def (dissect-pana buffer)
  "Protocol for carrying Authentication for Network Access"
  (try
    (let* (
           (reserved-type (unwrap (slice buffer 0 2)))
           (length-type (unwrap (read-u16be buffer 2)))
           (avp-data-length (unwrap (read-u16be buffer 4)))
           (avp-reserved (unwrap (slice buffer 6 2)))
           (msg-type (unwrap (read-u16be buffer 6)))
           (avp-vendorid (unwrap (read-u32be buffer 8)))
           (session-id (unwrap (read-u32be buffer 8)))
           (avp-data-string (unwrap (slice buffer 12 1)))
           (avp-data-bytes (unwrap (slice buffer 12 1)))
           (avp-data-int32 (unwrap (read-u32be buffer 12)))
           (avp-data-uint32 (unwrap (read-u32be buffer 12)))
           (avp-data-int64 (unwrap (read-u64be buffer 12)))
           (avp-data-uint64 (unwrap (read-u64be buffer 12)))
           (avp-data-enumerated (unwrap (read-u32be buffer 12)))
           (avp-code (unwrap (read-u16be buffer 12)))
           (seqnumber (unwrap (read-u32be buffer 12)))
           )

      (ok (list
        (cons 'reserved-type (list (cons 'raw reserved-type) (cons 'formatted (fmt-bytes reserved-type))))
        (cons 'length-type (list (cons 'raw length-type) (cons 'formatted (number->string length-type))))
        (cons 'avp-data-length (list (cons 'raw avp-data-length) (cons 'formatted (number->string avp-data-length))))
        (cons 'avp-reserved (list (cons 'raw avp-reserved) (cons 'formatted (fmt-bytes avp-reserved))))
        (cons 'msg-type (list (cons 'raw msg-type) (cons 'formatted (number->string msg-type))))
        (cons 'avp-vendorid (list (cons 'raw avp-vendorid) (cons 'formatted (fmt-hex avp-vendorid))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (fmt-hex session-id))))
        (cons 'avp-data-string (list (cons 'raw avp-data-string) (cons 'formatted (utf8->string avp-data-string))))
        (cons 'avp-data-bytes (list (cons 'raw avp-data-bytes) (cons 'formatted (fmt-bytes avp-data-bytes))))
        (cons 'avp-data-int32 (list (cons 'raw avp-data-int32) (cons 'formatted (number->string avp-data-int32))))
        (cons 'avp-data-uint32 (list (cons 'raw avp-data-uint32) (cons 'formatted (fmt-hex avp-data-uint32))))
        (cons 'avp-data-int64 (list (cons 'raw avp-data-int64) (cons 'formatted (number->string avp-data-int64))))
        (cons 'avp-data-uint64 (list (cons 'raw avp-data-uint64) (cons 'formatted (fmt-hex avp-data-uint64))))
        (cons 'avp-data-enumerated (list (cons 'raw avp-data-enumerated) (cons 'formatted (number->string avp-data-enumerated))))
        (cons 'avp-code (list (cons 'raw avp-code) (cons 'formatted (number->string avp-code))))
        (cons 'seqnumber (list (cons 'raw seqnumber) (cons 'formatted (fmt-hex seqnumber))))
        )))

    (catch (e)
      (err (str "PANA parse error: " e)))))

;; dissect-pana: parse PANA from bytevector
;; Returns (ok fields-alist) or (err message)