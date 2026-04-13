;; packet-iser.c
;; Routines for iSCSI RDMA Extensions dissection
;; Copyright 2014, Mellanox Technologies Ltd.
;; Code by Yan Burman.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/iser.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iser.c

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
(def (dissect-iser buffer)
  "iSCSI Extensions for RDMA"
  (try
    (let* (
           (write-stag (unwrap (read-u32be buffer 4)))
           (write-va (unwrap (read-u64be buffer 8)))
           (read-stag (unwrap (read-u32be buffer 16)))
           (read-va (unwrap (read-u64be buffer 20)))
           (ird (unwrap (read-u16be buffer 22)))
           (flags (unwrap (read-u8 buffer 22)))
           (REJ-f (extract-bits flags 0x0 0))
           (ord (unwrap (read-u16be buffer 24)))
           )

      (ok (list
        (cons 'write-stag (list (cons 'raw write-stag) (cons 'formatted (fmt-hex write-stag))))
        (cons 'write-va (list (cons 'raw write-va) (cons 'formatted (fmt-hex write-va))))
        (cons 'read-stag (list (cons 'raw read-stag) (cons 'formatted (fmt-hex read-stag))))
        (cons 'read-va (list (cons 'raw read-va) (cons 'formatted (fmt-hex read-va))))
        (cons 'ird (list (cons 'raw ird) (cons 'formatted (fmt-hex ird))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'REJ-f (list (cons 'raw REJ-f) (cons 'formatted (if (= REJ-f 0) "Not set" "Set"))))
        (cons 'ord (list (cons 'raw ord) (cons 'formatted (fmt-hex ord))))
        )))

    (catch (e)
      (err (str "ISER parse error: " e)))))

;; dissect-iser: parse ISER from bytevector
;; Returns (ok fields-alist) or (err message)