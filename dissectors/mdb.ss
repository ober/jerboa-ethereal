;;
;; packet-mdb.c
;; Routines for MDB dissection
;; Copyright 2023 Martin Kaiser for PayTec AG (www.paytec.ch)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mdb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mdb.c

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
(def (dissect-mdb buffer)
  "Multi-Drop Bus"
  (try
    (let* (
           (cl-cols (unwrap (read-u8 buffer 0)))
           (cl-rows (unwrap (read-u8 buffer 0)))
           (cl-disp-info (unwrap (read-u8 buffer 0)))
           (cl-max-price (unwrap (read-u32be buffer 2)))
           (cl-min-price (unwrap (read-u32be buffer 6)))
           (cl-item-price (unwrap (read-u32be buffer 6)))
           (cl-item-num (unwrap (read-u32be buffer 8)))
           (cl-manuf-code (unwrap (slice buffer 8 3)))
           (cl-ser-num (unwrap (slice buffer 11 12)))
           (cl-mod-num (unwrap (slice buffer 23 12)))
           (cl-opt-feat (unwrap (read-u32be buffer 37)))
           (cl-feat-lvl (unwrap (read-u8 buffer 37)))
           (cl-scale (unwrap (read-u8 buffer 39)))
           (cl-dec-pl (unwrap (read-u8 buffer 39)))
           (cl-vend-amt (unwrap (read-u32be buffer 39)))
           (cgw-dts-evt-code (unwrap (slice buffer 39 10)))
           (cgw-duration (unwrap (read-u32be buffer 55)))
           (cgw-activity (unwrap (read-u8 buffer 59)))
           (cgw-feat-lvl (unwrap (read-u8 buffer 59)))
           (cgw-scale (unwrap (read-u8 buffer 59)))
           (cgw-dec-pl (unwrap (read-u8 buffer 59)))
           (cgw-manuf-code (unwrap (slice buffer 59 3)))
           (cgw-ser-num (unwrap (slice buffer 62 12)))
           (cgw-mod-num (unwrap (slice buffer 74 12)))
           (cgw-opt-feat (unwrap (read-u32be buffer 88)))
           (cmd (unwrap (read-u8 buffer 88)))
           (data (unwrap (slice buffer 88 1)))
           (chk (unwrap (read-u8 buffer 88)))
           )

      (ok (list
        (cons 'cl-cols (list (cons 'raw cl-cols) (cons 'formatted (number->string cl-cols))))
        (cons 'cl-rows (list (cons 'raw cl-rows) (cons 'formatted (number->string cl-rows))))
        (cons 'cl-disp-info (list (cons 'raw cl-disp-info) (cons 'formatted (fmt-hex cl-disp-info))))
        (cons 'cl-max-price (list (cons 'raw cl-max-price) (cons 'formatted (fmt-hex cl-max-price))))
        (cons 'cl-min-price (list (cons 'raw cl-min-price) (cons 'formatted (fmt-hex cl-min-price))))
        (cons 'cl-item-price (list (cons 'raw cl-item-price) (cons 'formatted (number->string cl-item-price))))
        (cons 'cl-item-num (list (cons 'raw cl-item-num) (cons 'formatted (number->string cl-item-num))))
        (cons 'cl-manuf-code (list (cons 'raw cl-manuf-code) (cons 'formatted (utf8->string cl-manuf-code))))
        (cons 'cl-ser-num (list (cons 'raw cl-ser-num) (cons 'formatted (utf8->string cl-ser-num))))
        (cons 'cl-mod-num (list (cons 'raw cl-mod-num) (cons 'formatted (utf8->string cl-mod-num))))
        (cons 'cl-opt-feat (list (cons 'raw cl-opt-feat) (cons 'formatted (fmt-hex cl-opt-feat))))
        (cons 'cl-feat-lvl (list (cons 'raw cl-feat-lvl) (cons 'formatted (number->string cl-feat-lvl))))
        (cons 'cl-scale (list (cons 'raw cl-scale) (cons 'formatted (number->string cl-scale))))
        (cons 'cl-dec-pl (list (cons 'raw cl-dec-pl) (cons 'formatted (number->string cl-dec-pl))))
        (cons 'cl-vend-amt (list (cons 'raw cl-vend-amt) (cons 'formatted (number->string cl-vend-amt))))
        (cons 'cgw-dts-evt-code (list (cons 'raw cgw-dts-evt-code) (cons 'formatted (utf8->string cgw-dts-evt-code))))
        (cons 'cgw-duration (list (cons 'raw cgw-duration) (cons 'formatted (number->string cgw-duration))))
        (cons 'cgw-activity (list (cons 'raw cgw-activity) (cons 'formatted (if (= cgw-activity 0) "False" "True"))))
        (cons 'cgw-feat-lvl (list (cons 'raw cgw-feat-lvl) (cons 'formatted (number->string cgw-feat-lvl))))
        (cons 'cgw-scale (list (cons 'raw cgw-scale) (cons 'formatted (number->string cgw-scale))))
        (cons 'cgw-dec-pl (list (cons 'raw cgw-dec-pl) (cons 'formatted (number->string cgw-dec-pl))))
        (cons 'cgw-manuf-code (list (cons 'raw cgw-manuf-code) (cons 'formatted (utf8->string cgw-manuf-code))))
        (cons 'cgw-ser-num (list (cons 'raw cgw-ser-num) (cons 'formatted (utf8->string cgw-ser-num))))
        (cons 'cgw-mod-num (list (cons 'raw cgw-mod-num) (cons 'formatted (utf8->string cgw-mod-num))))
        (cons 'cgw-opt-feat (list (cons 'raw cgw-opt-feat) (cons 'formatted (fmt-hex cgw-opt-feat))))
        (cons 'cmd (list (cons 'raw cmd) (cons 'formatted (fmt-hex cmd))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'chk (list (cons 'raw chk) (cons 'formatted (fmt-hex chk))))
        )))

    (catch (e)
      (err (str "MDB parse error: " e)))))

;; dissect-mdb: parse MDB from bytevector
;; Returns (ok fields-alist) or (err message)