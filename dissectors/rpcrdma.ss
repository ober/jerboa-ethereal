;; packet-rpcrdma.c
;; Routines for RPC over RDMA dissection (RFC 5666)
;; Copyright 2014-2015, Mellanox Technologies Ltd.
;; Code by Yan Burman.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rpcrdma.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rpcrdma.c
;; RFC 5666

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
(def (dissect-rpcrdma buffer)
  "RPC over RDMA"
  (try
    (let* (
           (xid (unwrap (read-u32be buffer 0)))
           (vers (unwrap (read-u32be buffer 4)))
           (flow-control (unwrap (read-u32be buffer 8)))
           (rdma-align (unwrap (read-u32be buffer 16)))
           (rdma-thresh (unwrap (read-u32be buffer 20)))
           (vers-low (unwrap (read-u32be buffer 28)))
           (vers-high (unwrap (read-u32be buffer 32)))
           (reads-count (unwrap (read-u32be buffer 72)))
           (rdma-handle (unwrap (read-u32be buffer 76)))
           (rdma-length (unwrap (read-u32be buffer 80)))
           (rdma-offset (unwrap (read-u64be buffer 84)))
           (segment-count (unwrap (read-u32be buffer 84)))
           (writes-count (unwrap (read-u32be buffer 88)))
           (reply-count (unwrap (read-u32be buffer 92)))
           (position (unwrap (read-u32be buffer 96)))
           )

      (ok (list
        (cons 'xid (list (cons 'raw xid) (cons 'formatted (fmt-hex xid))))
        (cons 'vers (list (cons 'raw vers) (cons 'formatted (number->string vers))))
        (cons 'flow-control (list (cons 'raw flow-control) (cons 'formatted (number->string flow-control))))
        (cons 'rdma-align (list (cons 'raw rdma-align) (cons 'formatted (number->string rdma-align))))
        (cons 'rdma-thresh (list (cons 'raw rdma-thresh) (cons 'formatted (number->string rdma-thresh))))
        (cons 'vers-low (list (cons 'raw vers-low) (cons 'formatted (number->string vers-low))))
        (cons 'vers-high (list (cons 'raw vers-high) (cons 'formatted (number->string vers-high))))
        (cons 'reads-count (list (cons 'raw reads-count) (cons 'formatted (number->string reads-count))))
        (cons 'rdma-handle (list (cons 'raw rdma-handle) (cons 'formatted (fmt-hex rdma-handle))))
        (cons 'rdma-length (list (cons 'raw rdma-length) (cons 'formatted (number->string rdma-length))))
        (cons 'rdma-offset (list (cons 'raw rdma-offset) (cons 'formatted (fmt-hex rdma-offset))))
        (cons 'segment-count (list (cons 'raw segment-count) (cons 'formatted (number->string segment-count))))
        (cons 'writes-count (list (cons 'raw writes-count) (cons 'formatted (number->string writes-count))))
        (cons 'reply-count (list (cons 'raw reply-count) (cons 'formatted (number->string reply-count))))
        (cons 'position (list (cons 'raw position) (cons 'formatted (number->string position))))
        )))

    (catch (e)
      (err (str "RPCRDMA parse error: " e)))))

;; dissect-rpcrdma: parse RPCRDMA from bytevector
;; Returns (ok fields-alist) or (err message)