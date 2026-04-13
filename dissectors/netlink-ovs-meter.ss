;; packet-netlink-ovs_meter.c
;; Routines for Open vSwitch meter netlink protocol dissection
;; Copyright 2026, Red Hat Inc.
;; By Timothy Redaelli <tredaelli@redhat.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netlink-ovs-meter.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netlink_ovs_meter.c

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
(def (dissect-netlink-ovs-meter buffer)
  "Linux ovs_meter (Open vSwitch Meter) protocol"
  (try
    (let* (
           (meter-band-rate (unwrap (read-u32be buffer 0)))
           (meter-band-burst (unwrap (read-u32be buffer 0)))
           (meter-band-stats-n-packets (unwrap (read-u64be buffer 0)))
           (meter-band-stats-n-bytes (unwrap (read-u64be buffer 0)))
           (meter-id (unwrap (read-u32be buffer 0)))
           (meter-stats-n-packets (unwrap (read-u64be buffer 0)))
           (meter-stats-n-bytes (unwrap (read-u64be buffer 0)))
           (meter-used (unwrap (read-u64be buffer 0)))
           (meter-max-meters (unwrap (read-u32be buffer 0)))
           (meter-max-bands (unwrap (read-u32be buffer 0)))
           (meter-dp-ifindex (unwrap (read-u32be buffer 0)))
           )

      (ok (list
        (cons 'meter-band-rate (list (cons 'raw meter-band-rate) (cons 'formatted (number->string meter-band-rate))))
        (cons 'meter-band-burst (list (cons 'raw meter-band-burst) (cons 'formatted (number->string meter-band-burst))))
        (cons 'meter-band-stats-n-packets (list (cons 'raw meter-band-stats-n-packets) (cons 'formatted (number->string meter-band-stats-n-packets))))
        (cons 'meter-band-stats-n-bytes (list (cons 'raw meter-band-stats-n-bytes) (cons 'formatted (number->string meter-band-stats-n-bytes))))
        (cons 'meter-id (list (cons 'raw meter-id) (cons 'formatted (number->string meter-id))))
        (cons 'meter-stats-n-packets (list (cons 'raw meter-stats-n-packets) (cons 'formatted (number->string meter-stats-n-packets))))
        (cons 'meter-stats-n-bytes (list (cons 'raw meter-stats-n-bytes) (cons 'formatted (number->string meter-stats-n-bytes))))
        (cons 'meter-used (list (cons 'raw meter-used) (cons 'formatted (number->string meter-used))))
        (cons 'meter-max-meters (list (cons 'raw meter-max-meters) (cons 'formatted (number->string meter-max-meters))))
        (cons 'meter-max-bands (list (cons 'raw meter-max-bands) (cons 'formatted (number->string meter-max-bands))))
        (cons 'meter-dp-ifindex (list (cons 'raw meter-dp-ifindex) (cons 'formatted (number->string meter-dp-ifindex))))
        )))

    (catch (e)
      (err (str "NETLINK-OVS-METER parse error: " e)))))

;; dissect-netlink-ovs-meter: parse NETLINK-OVS-METER from bytevector
;; Returns (ok fields-alist) or (err message)