;; packet-netlink-ovs_vport.c
;; Routines for Open vSwitch virtual port netlink protocol dissection
;; Copyright 2026, Red Hat Inc.
;; By Timothy Redaelli <tredaelli@redhat.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netlink-ovs-vport.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netlink_ovs_vport.c

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
(def (dissect-netlink-ovs-vport buffer)
  "Linux ovs_vport (Open vSwitch Vport) protocol"
  (try
    (let* (
           (vport-tunnel-dst-port (unwrap (read-u16be buffer 0)))
           (vport-upcall-success (unwrap (read-u64be buffer 0)))
           (vport-upcall-fail (unwrap (read-u64be buffer 0)))
           (vport-port-no (unwrap (read-u32be buffer 0)))
           (vport-name (unwrap (slice buffer 0 1)))
           (vport-upcall-pid (unwrap (read-u32be buffer 0)))
           (vport-ifindex (unwrap (read-u32be buffer 0)))
           (vport-netnsid (unwrap (read-u32be buffer 0)))
           (vport-dp-ifindex (unwrap (read-u32be buffer 0)))
           (vport-vxlan-ext-gbp (unwrap (read-u32be buffer 8)))
           )

      (ok (list
        (cons 'vport-tunnel-dst-port (list (cons 'raw vport-tunnel-dst-port) (cons 'formatted (number->string vport-tunnel-dst-port))))
        (cons 'vport-upcall-success (list (cons 'raw vport-upcall-success) (cons 'formatted (number->string vport-upcall-success))))
        (cons 'vport-upcall-fail (list (cons 'raw vport-upcall-fail) (cons 'formatted (number->string vport-upcall-fail))))
        (cons 'vport-port-no (list (cons 'raw vport-port-no) (cons 'formatted (number->string vport-port-no))))
        (cons 'vport-name (list (cons 'raw vport-name) (cons 'formatted (utf8->string vport-name))))
        (cons 'vport-upcall-pid (list (cons 'raw vport-upcall-pid) (cons 'formatted (number->string vport-upcall-pid))))
        (cons 'vport-ifindex (list (cons 'raw vport-ifindex) (cons 'formatted (number->string vport-ifindex))))
        (cons 'vport-netnsid (list (cons 'raw vport-netnsid) (cons 'formatted (number->string vport-netnsid))))
        (cons 'vport-dp-ifindex (list (cons 'raw vport-dp-ifindex) (cons 'formatted (number->string vport-dp-ifindex))))
        (cons 'vport-vxlan-ext-gbp (list (cons 'raw vport-vxlan-ext-gbp) (cons 'formatted (number->string vport-vxlan-ext-gbp))))
        )))

    (catch (e)
      (err (str "NETLINK-OVS-VPORT parse error: " e)))))

;; dissect-netlink-ovs-vport: parse NETLINK-OVS-VPORT from bytevector
;; Returns (ok fields-alist) or (err message)