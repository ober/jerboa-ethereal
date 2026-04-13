;; packet-zbee-zcl.c
;; Dissector routines for the ZigBee Cluster Library (ZCL)
;; By Fred Fierling <fff@exegin.com>
;; Copyright 2009 Exegin Technologies Limited
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Used Owen Kirby's packet-zbee-aps module as a template. Based
;; on ZigBee Cluster Library Specification document 075123r02ZB
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/zbee-zcl.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zbee_zcl.c

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
(def (dissect-zbee-zcl buffer)
  "ZigBee Cluster Library"
  (try
    (let* (
           (zcl-index (unwrap (read-u16be buffer 0)))
           (zcl-indicator (unwrap (read-u8 buffer 0)))
           (zcl-fcf-mfr-spec (unwrap (read-u8 buffer 0)))
           (zcl-fcf-dir (unwrap (read-u8 buffer 0)))
           (zcl-fcf-disable-default-resp (unwrap (read-u8 buffer 0)))
           (zcl-tran-seqno (unwrap (read-u8 buffer 3)))
           )

      (ok (list
        (cons 'zcl-index (list (cons 'raw zcl-index) (cons 'formatted (number->string zcl-index))))
        (cons 'zcl-indicator (list (cons 'raw zcl-indicator) (cons 'formatted (number->string zcl-indicator))))
        (cons 'zcl-fcf-mfr-spec (list (cons 'raw zcl-fcf-mfr-spec) (cons 'formatted (number->string zcl-fcf-mfr-spec))))
        (cons 'zcl-fcf-dir (list (cons 'raw zcl-fcf-dir) (cons 'formatted (if (= zcl-fcf-dir 0) "False" "True"))))
        (cons 'zcl-fcf-disable-default-resp (list (cons 'raw zcl-fcf-disable-default-resp) (cons 'formatted (number->string zcl-fcf-disable-default-resp))))
        (cons 'zcl-tran-seqno (list (cons 'raw zcl-tran-seqno) (cons 'formatted (number->string zcl-tran-seqno))))
        )))

    (catch (e)
      (err (str "ZBEE-ZCL parse error: " e)))))

;; dissect-zbee-zcl: parse ZBEE-ZCL from bytevector
;; Returns (ok fields-alist) or (err message)