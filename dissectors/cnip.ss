;; packet-cnip.c
;; Traffic analyzer for the CN/IP (EIA-852) protocol
;; Daniel Willmann <daniel@totalueberwachung.de>
;; (c) 2011 Daniel Willmann
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cnip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cnip.c

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
(def (dissect-cnip buffer)
  "Component Network over IP"
  (try
    (let* (
           (ver (unwrap (read-u8 buffer 2)))
           (exth (unwrap (read-u8 buffer 4)))
           (pf (unwrap (read-u8 buffer 5)))
           (pf-sec (extract-bits pf 0x20 5))
           (pf-pcode (extract-bits pf 0x1F 0))
           (vcode (unwrap (read-u16be buffer 6)))
           (sessid (unwrap (read-u32be buffer 8)))
           (seqno (unwrap (read-u32be buffer 12)))
           (tstamp (unwrap (read-u32be buffer 16)))
           (len (unwrap (read-u16be buffer 20)))
           )

      (ok (list
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'exth (list (cons 'raw exth) (cons 'formatted (number->string exth))))
        (cons 'pf (list (cons 'raw pf) (cons 'formatted (number->string pf))))
        (cons 'pf-sec (list (cons 'raw pf-sec) (cons 'formatted (if (= pf-sec 0) "Not set" "Set"))))
        (cons 'pf-pcode (list (cons 'raw pf-pcode) (cons 'formatted (if (= pf-pcode 0) "Not set" "Set"))))
        (cons 'vcode (list (cons 'raw vcode) (cons 'formatted (number->string vcode))))
        (cons 'sessid (list (cons 'raw sessid) (cons 'formatted (number->string sessid))))
        (cons 'seqno (list (cons 'raw seqno) (cons 'formatted (number->string seqno))))
        (cons 'tstamp (list (cons 'raw tstamp) (cons 'formatted (number->string tstamp))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        )))

    (catch (e)
      (err (str "CNIP parse error: " e)))))

;; dissect-cnip: parse CNIP from bytevector
;; Returns (ok fields-alist) or (err message)