;; packet-netlink.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netlink.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netlink.c

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
(def (dissect-netlink buffer)
  "Linux netlink protocol"
  (try
    (let* (
           (attr-type (unwrap (read-u16be buffer 2)))
           (attr-type-nested (unwrap (read-u8 buffer 2)))
           (attr-type-net-byteorder (unwrap (read-u8 buffer 2)))
           (attr-data (unwrap (slice buffer 4 1)))
           (attr-index (unwrap (read-u16be buffer 4)))
           (hdr-seq (unwrap (read-u32be buffer 14)))
           (hdr-len (unwrap (read-u32be buffer 16)))
           (hdr-pid (unwrap (read-u32be buffer 18)))
           (attr-len (unwrap (read-u16be buffer 22)))
           )

      (ok (list
        (cons 'attr-type (list (cons 'raw attr-type) (cons 'formatted (fmt-hex attr-type))))
        (cons 'attr-type-nested (list (cons 'raw attr-type-nested) (cons 'formatted (number->string attr-type-nested))))
        (cons 'attr-type-net-byteorder (list (cons 'raw attr-type-net-byteorder) (cons 'formatted (number->string attr-type-net-byteorder))))
        (cons 'attr-data (list (cons 'raw attr-data) (cons 'formatted (fmt-bytes attr-data))))
        (cons 'attr-index (list (cons 'raw attr-index) (cons 'formatted (number->string attr-index))))
        (cons 'hdr-seq (list (cons 'raw hdr-seq) (cons 'formatted (number->string hdr-seq))))
        (cons 'hdr-len (list (cons 'raw hdr-len) (cons 'formatted (number->string hdr-len))))
        (cons 'hdr-pid (list (cons 'raw hdr-pid) (cons 'formatted (number->string hdr-pid))))
        (cons 'attr-len (list (cons 'raw attr-len) (cons 'formatted (number->string attr-len))))
        )))

    (catch (e)
      (err (str "NETLINK parse error: " e)))))

;; dissect-netlink: parse NETLINK from bytevector
;; Returns (ok fields-alist) or (err message)