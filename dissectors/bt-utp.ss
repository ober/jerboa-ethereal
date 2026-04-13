;; packet-bt-utp.c
;; Routines for BT-UTP dissection
;; Copyright 2011, Xiao Xiangquan <xiaoxiangquan@gmail.com>
;; Copyright 2021, John Thacker <johnthacker@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bt-utp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bt_utp.c

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
(def (dissect-bt-utp buffer)
  "uTorrent Transport Protocol"
  (try
    (let* (
           (utp-data (unwrap (slice buffer 0 1)))
           (utp-len (unwrap (read-u32be buffer 0)))
           (utp-continuation-to (unwrap (read-u32be buffer 0)))
           (utp-connection-id-v0 (unwrap (read-u32be buffer 0)))
           (utp-timestamp-sec (unwrap (read-u32be buffer 4)))
           (utp-wnd-size-v0 (unwrap (read-u8 buffer 16)))
           (utp-ver (unwrap (read-u8 buffer 27)))
           (utp-connection-id-v1 (unwrap (read-u16be buffer 29)))
           (utp-timestamp-us (unwrap (read-u32be buffer 31)))
           (utp-timestamp-diff-us (unwrap (read-u32be buffer 35)))
           (utp-seq-nr (unwrap (read-u16be buffer 43)))
           (utp-ack-nr (unwrap (read-u16be buffer 45)))
           (utp-stream (unwrap (read-u32be buffer 47)))
           (utp-extension-bitmask (unwrap (slice buffer 49 1)))
           (utp-extension-unknown (unwrap (slice buffer 49 1)))
           )

      (ok (list
        (cons 'utp-data (list (cons 'raw utp-data) (cons 'formatted (fmt-bytes utp-data))))
        (cons 'utp-len (list (cons 'raw utp-len) (cons 'formatted (number->string utp-len))))
        (cons 'utp-continuation-to (list (cons 'raw utp-continuation-to) (cons 'formatted (number->string utp-continuation-to))))
        (cons 'utp-connection-id-v0 (list (cons 'raw utp-connection-id-v0) (cons 'formatted (number->string utp-connection-id-v0))))
        (cons 'utp-timestamp-sec (list (cons 'raw utp-timestamp-sec) (cons 'formatted (number->string utp-timestamp-sec))))
        (cons 'utp-wnd-size-v0 (list (cons 'raw utp-wnd-size-v0) (cons 'formatted (number->string utp-wnd-size-v0))))
        (cons 'utp-ver (list (cons 'raw utp-ver) (cons 'formatted (number->string utp-ver))))
        (cons 'utp-connection-id-v1 (list (cons 'raw utp-connection-id-v1) (cons 'formatted (number->string utp-connection-id-v1))))
        (cons 'utp-timestamp-us (list (cons 'raw utp-timestamp-us) (cons 'formatted (number->string utp-timestamp-us))))
        (cons 'utp-timestamp-diff-us (list (cons 'raw utp-timestamp-diff-us) (cons 'formatted (number->string utp-timestamp-diff-us))))
        (cons 'utp-seq-nr (list (cons 'raw utp-seq-nr) (cons 'formatted (number->string utp-seq-nr))))
        (cons 'utp-ack-nr (list (cons 'raw utp-ack-nr) (cons 'formatted (number->string utp-ack-nr))))
        (cons 'utp-stream (list (cons 'raw utp-stream) (cons 'formatted (number->string utp-stream))))
        (cons 'utp-extension-bitmask (list (cons 'raw utp-extension-bitmask) (cons 'formatted (fmt-bytes utp-extension-bitmask))))
        (cons 'utp-extension-unknown (list (cons 'raw utp-extension-unknown) (cons 'formatted (fmt-bytes utp-extension-unknown))))
        )))

    (catch (e)
      (err (str "BT-UTP parse error: " e)))))

;; dissect-bt-utp: parse BT-UTP from bytevector
;; Returns (ok fields-alist) or (err message)