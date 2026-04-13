;; packet-rpl.c
;; Routines for RPL
;; Jochen Friedrich <jochen@scram.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rpl.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rpl.c

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
(def (dissect-rpl buffer)
  "Remote Program Load"
  (try
    (let* (
           (len (unwrap (read-u16be buffer 0)))
           (corrval (unwrap (read-u32be buffer 4)))
           (lmac (unwrap (slice buffer 8 6)))
           (maxframe (unwrap (read-u16be buffer 14)))
           (connclass (unwrap (read-u16be buffer 16)))
           (respval (unwrap (read-u8 buffer 18)))
           (smac (unwrap (slice buffer 18 6)))
           (sequence (unwrap (read-u32be buffer 24)))
           (data (unwrap (slice buffer 28 1)))
           (config (unwrap (slice buffer 28 8)))
           (equipment (unwrap (read-u16be buffer 36)))
           (memsize (unwrap (read-u16be buffer 38)))
           (bsmversion (unwrap (read-u16be buffer 40)))
           (ec (unwrap (slice buffer 42 6)))
           (adapterid (unwrap (read-u16be buffer 48)))
           (shortname (unwrap (slice buffer 50 10)))
           (laddress (unwrap (read-u32be buffer 60)))
           (xaddress (unwrap (read-u32be buffer 64)))
           (flags (unwrap (read-u8 buffer 68)))
           )

      (ok (list
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'corrval (list (cons 'raw corrval) (cons 'formatted (fmt-hex corrval))))
        (cons 'lmac (list (cons 'raw lmac) (cons 'formatted (fmt-mac lmac))))
        (cons 'maxframe (list (cons 'raw maxframe) (cons 'formatted (number->string maxframe))))
        (cons 'connclass (list (cons 'raw connclass) (cons 'formatted (fmt-hex connclass))))
        (cons 'respval (list (cons 'raw respval) (cons 'formatted (number->string respval))))
        (cons 'smac (list (cons 'raw smac) (cons 'formatted (fmt-mac smac))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (fmt-hex sequence))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'config (list (cons 'raw config) (cons 'formatted (fmt-bytes config))))
        (cons 'equipment (list (cons 'raw equipment) (cons 'formatted (fmt-hex equipment))))
        (cons 'memsize (list (cons 'raw memsize) (cons 'formatted (number->string memsize))))
        (cons 'bsmversion (list (cons 'raw bsmversion) (cons 'formatted (fmt-hex bsmversion))))
        (cons 'ec (list (cons 'raw ec) (cons 'formatted (fmt-bytes ec))))
        (cons 'adapterid (list (cons 'raw adapterid) (cons 'formatted (fmt-hex adapterid))))
        (cons 'shortname (list (cons 'raw shortname) (cons 'formatted (fmt-bytes shortname))))
        (cons 'laddress (list (cons 'raw laddress) (cons 'formatted (fmt-hex laddress))))
        (cons 'xaddress (list (cons 'raw xaddress) (cons 'formatted (fmt-hex xaddress))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        )))

    (catch (e)
      (err (str "RPL parse error: " e)))))

;; dissect-rpl: parse RPL from bytevector
;; Returns (ok fields-alist) or (err message)