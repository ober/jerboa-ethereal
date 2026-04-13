;; packet-netlink-ovs_datapath.c
;; Routines for Open vSwitch datapath netlink protocol dissection
;; Copyright 2026, Red Hat Inc.
;; By Timothy Redaelli <tredaelli@redhat.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netlink-ovs-datapath.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netlink_ovs_datapath.c

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
(def (dissect-netlink-ovs-datapath buffer)
  "Linux ovs_datapath (Open vSwitch Datapath) protocol"
  (try
    (let* (
           (dp-upcall-pid (unwrap (read-u32be buffer 0)))
           (dp-masks-cache-size (unwrap (read-u32be buffer 0)))
           (dp-ifindex (unwrap (read-u32be buffer 0)))
           (dp-dp-ifindex (unwrap (read-u32be buffer 0)))
           (dp-name (unwrap (slice buffer 4 1)))
           )

      (ok (list
        (cons 'dp-upcall-pid (list (cons 'raw dp-upcall-pid) (cons 'formatted (number->string dp-upcall-pid))))
        (cons 'dp-masks-cache-size (list (cons 'raw dp-masks-cache-size) (cons 'formatted (number->string dp-masks-cache-size))))
        (cons 'dp-ifindex (list (cons 'raw dp-ifindex) (cons 'formatted (number->string dp-ifindex))))
        (cons 'dp-dp-ifindex (list (cons 'raw dp-dp-ifindex) (cons 'formatted (number->string dp-dp-ifindex))))
        (cons 'dp-name (list (cons 'raw dp-name) (cons 'formatted (utf8->string dp-name))))
        )))

    (catch (e)
      (err (str "NETLINK-OVS-DATAPATH parse error: " e)))))

;; dissect-netlink-ovs-datapath: parse NETLINK-OVS-DATAPATH from bytevector
;; Returns (ok fields-alist) or (err message)