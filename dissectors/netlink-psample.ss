;; packet-netlink-psample.c
;; Routines for netlink-psample dissection
;; Based on netlink-net_dm and netlink-generic dissectors
;; Copyright 2021, Mellanox Technologies Ltd.
;; Code by Amit Cohen <amcohen@nvidia.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netlink-psample.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netlink_psample.c

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
(def (dissect-netlink-psample buffer)
  "Linux psample protocol"
  (try
    (let* (
           (iifindex (unwrap (read-u16be buffer 0)))
           (oifindex (unwrap (read-u16be buffer 0)))
           (origsize (unwrap (read-u32be buffer 0)))
           (sample-group (unwrap (read-u32be buffer 0)))
           (group-seq (unwrap (read-u32be buffer 0)))
           (sample-rate (unwrap (read-u32be buffer 0)))
           (group-refcount (unwrap (read-u32be buffer 0)))
           (out-tc (unwrap (read-u16be buffer 0)))
           (out-tc-occ (unwrap (read-u64be buffer 0)))
           (latency (unwrap (read-u64be buffer 0)))
           (proto (unwrap (read-u16be buffer 0)))
           )

      (ok (list
        (cons 'iifindex (list (cons 'raw iifindex) (cons 'formatted (fmt-hex iifindex))))
        (cons 'oifindex (list (cons 'raw oifindex) (cons 'formatted (fmt-hex oifindex))))
        (cons 'origsize (list (cons 'raw origsize) (cons 'formatted (fmt-hex origsize))))
        (cons 'sample-group (list (cons 'raw sample-group) (cons 'formatted (number->string sample-group))))
        (cons 'group-seq (list (cons 'raw group-seq) (cons 'formatted (number->string group-seq))))
        (cons 'sample-rate (list (cons 'raw sample-rate) (cons 'formatted (number->string sample-rate))))
        (cons 'group-refcount (list (cons 'raw group-refcount) (cons 'formatted (fmt-hex group-refcount))))
        (cons 'out-tc (list (cons 'raw out-tc) (cons 'formatted (number->string out-tc))))
        (cons 'out-tc-occ (list (cons 'raw out-tc-occ) (cons 'formatted (number->string out-tc-occ))))
        (cons 'latency (list (cons 'raw latency) (cons 'formatted (number->string latency))))
        (cons 'proto (list (cons 'raw proto) (cons 'formatted (fmt-hex proto))))
        )))

    (catch (e)
      (err (str "NETLINK-PSAMPLE parse error: " e)))))

;; dissect-netlink-psample: parse NETLINK-PSAMPLE from bytevector
;; Returns (ok fields-alist) or (err message)