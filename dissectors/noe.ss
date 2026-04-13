;; packet-noe.c
;; Routines for UA/UDP (Universal Alcatel over UDP) and NOE packet dissection.
;; Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
;; Copyright 2017, Alcatel-Lucent Enterprise <nicolas.bertin@al-enterprise.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/noe.ss
;; Auto-generated from wireshark/epan/dissectors/packet-noe.c

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
(def (dissect-noe buffer)
  "NOE Protocol"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 0)))
           (method-ack (unwrap (read-u8 buffer 4)))
           (message (unwrap (slice buffer 14 1)))
           (psize (unwrap (read-u16be buffer 16)))
           (property-item-utf8 (unwrap (slice buffer 19 1)))
           (property-item-u8 (unwrap (read-u8 buffer 19)))
           (property-item-u16 (unwrap (read-u16be buffer 19)))
           (property-item-u24 (unwrap (read-u24be buffer 19)))
           (property-item-u32 (unwrap (read-u32be buffer 19)))
           (property-item-bytes (unwrap (slice buffer 19 1)))
           (aindx (unwrap (read-u8 buffer 20)))
           (bt-key (unwrap (read-u8 buffer 22)))
           (key-name (unwrap (slice buffer 23 1)))
           (widget-gc (unwrap (read-u32be buffer 26)))
           (bonded (unwrap (read-u8 buffer 28)))
           (value (unwrap (read-u32be buffer 29)))
           (objectid (unwrap (read-u16be buffer 32)))
           (method-index (unwrap (read-u8 buffer 35)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'method-ack (list (cons 'raw method-ack) (cons 'formatted (number->string method-ack))))
        (cons 'message (list (cons 'raw message) (cons 'formatted (fmt-bytes message))))
        (cons 'psize (list (cons 'raw psize) (cons 'formatted (number->string psize))))
        (cons 'property-item-utf8 (list (cons 'raw property-item-utf8) (cons 'formatted (utf8->string property-item-utf8))))
        (cons 'property-item-u8 (list (cons 'raw property-item-u8) (cons 'formatted (number->string property-item-u8))))
        (cons 'property-item-u16 (list (cons 'raw property-item-u16) (cons 'formatted (number->string property-item-u16))))
        (cons 'property-item-u24 (list (cons 'raw property-item-u24) (cons 'formatted (number->string property-item-u24))))
        (cons 'property-item-u32 (list (cons 'raw property-item-u32) (cons 'formatted (number->string property-item-u32))))
        (cons 'property-item-bytes (list (cons 'raw property-item-bytes) (cons 'formatted (fmt-bytes property-item-bytes))))
        (cons 'aindx (list (cons 'raw aindx) (cons 'formatted (number->string aindx))))
        (cons 'bt-key (list (cons 'raw bt-key) (cons 'formatted (number->string bt-key))))
        (cons 'key-name (list (cons 'raw key-name) (cons 'formatted (utf8->string key-name))))
        (cons 'widget-gc (list (cons 'raw widget-gc) (cons 'formatted (number->string widget-gc))))
        (cons 'bonded (list (cons 'raw bonded) (cons 'formatted (number->string bonded))))
        (cons 'value (list (cons 'raw value) (cons 'formatted (fmt-hex value))))
        (cons 'objectid (list (cons 'raw objectid) (cons 'formatted (fmt-hex objectid))))
        (cons 'method-index (list (cons 'raw method-index) (cons 'formatted (number->string method-index))))
        )))

    (catch (e)
      (err (str "NOE parse error: " e)))))

;; dissect-noe: parse NOE from bytevector
;; Returns (ok fields-alist) or (err message)