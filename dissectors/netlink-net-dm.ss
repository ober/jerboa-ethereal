;; packet-netlink-net_dm.c
;; Routines for netlink-net_dm dissection
;; Based on netlink-route and netlink-generic dissectors
;; Copyright 2019, Mellanox Technologies Ltd.
;; Code by Ido Schimmel <idosch@mellanox.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netlink-net-dm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netlink_net_dm.c

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
(def (dissect-netlink-net-dm buffer)
  "Linux net_dm (network drop monitor) protocol"
  (try
    (let* (
           (dm-port-netdev-name (unwrap (slice buffer 0 1)))
           (dm-stats-dropped (unwrap (read-u64be buffer 0)))
           (dm-pc (unwrap (read-u64be buffer 0)))
           (dm-symbol (unwrap (slice buffer 0 1)))
           (dm-proto (unwrap (read-u16be buffer 0)))
           (dm-trunc-len (unwrap (read-u32be buffer 0)))
           (dm-orig-len (unwrap (read-u32be buffer 0)))
           (dm-queue-len (unwrap (read-u32be buffer 0)))
           (dm-hw-trap-group-name (unwrap (slice buffer 0 1)))
           (dm-hw-trap-name (unwrap (slice buffer 0 1)))
           (dm-hw-trap-count (unwrap (read-u32be buffer 0)))
           (dm-flow-action-cookie (unwrap (slice buffer 0 1)))
           (dm-reason (unwrap (slice buffer 0 1)))
           (dm-port-netdev-index (unwrap (read-u32be buffer 8)))
           )

      (ok (list
        (cons 'dm-port-netdev-name (list (cons 'raw dm-port-netdev-name) (cons 'formatted (utf8->string dm-port-netdev-name))))
        (cons 'dm-stats-dropped (list (cons 'raw dm-stats-dropped) (cons 'formatted (number->string dm-stats-dropped))))
        (cons 'dm-pc (list (cons 'raw dm-pc) (cons 'formatted (fmt-hex dm-pc))))
        (cons 'dm-symbol (list (cons 'raw dm-symbol) (cons 'formatted (utf8->string dm-symbol))))
        (cons 'dm-proto (list (cons 'raw dm-proto) (cons 'formatted (fmt-hex dm-proto))))
        (cons 'dm-trunc-len (list (cons 'raw dm-trunc-len) (cons 'formatted (number->string dm-trunc-len))))
        (cons 'dm-orig-len (list (cons 'raw dm-orig-len) (cons 'formatted (number->string dm-orig-len))))
        (cons 'dm-queue-len (list (cons 'raw dm-queue-len) (cons 'formatted (number->string dm-queue-len))))
        (cons 'dm-hw-trap-group-name (list (cons 'raw dm-hw-trap-group-name) (cons 'formatted (utf8->string dm-hw-trap-group-name))))
        (cons 'dm-hw-trap-name (list (cons 'raw dm-hw-trap-name) (cons 'formatted (utf8->string dm-hw-trap-name))))
        (cons 'dm-hw-trap-count (list (cons 'raw dm-hw-trap-count) (cons 'formatted (number->string dm-hw-trap-count))))
        (cons 'dm-flow-action-cookie (list (cons 'raw dm-flow-action-cookie) (cons 'formatted (fmt-bytes dm-flow-action-cookie))))
        (cons 'dm-reason (list (cons 'raw dm-reason) (cons 'formatted (utf8->string dm-reason))))
        (cons 'dm-port-netdev-index (list (cons 'raw dm-port-netdev-index) (cons 'formatted (number->string dm-port-netdev-index))))
        )))

    (catch (e)
      (err (str "NETLINK-NET-DM parse error: " e)))))

;; dissect-netlink-net-dm: parse NETLINK-NET-DM from bytevector
;; Returns (ok fields-alist) or (err message)