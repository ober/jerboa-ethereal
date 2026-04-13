;; packet-dlep.c
;; Routines for DLEP protocol packet disassembly
;;
;; Copyright (C) 2019 Massachusetts Institute of Technology
;;
;; Original code from https://github.com/mit-ll/dlep-wireshark-dissector
;; Original Author: Jeffrey Wildman <jeffrey.wildman@ll.mit.edu>
;;
;; Extended and supplemented by Uli Heilmeier <uh@heilmeier.eu>, 2020
;; Extended by:
;; RFC 8757 Latency Range Extension
;; RFC 8629 Multi-Hop Forwarding Extension
;; RFC 8703 Link Identifier Extension
;; TODO: Decoding of RFC 8651 Control-Plane-Based Pause Extension needs to be implemented
;;
;; SPDX-License-Identifier: MIT
;;
;;

;; jerboa-ethereal/dissectors/dlep.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dlep.c
;; RFC 8757

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
(def (dissect-dlep buffer)
  "Dynamic Link Exchange Protocol"
  (try
    (let* (
           (dataitem-v4conn-flags (unwrap (read-u8 buffer 0)))
           (dataitem-v4conn-addr (unwrap (read-u32be buffer 0)))
           (dataitem-v4conn-port (unwrap (read-u16be buffer 0)))
           (dataitem-v6conn-flags (unwrap (read-u8 buffer 0)))
           (dataitem-v6conn-addr (unwrap (slice buffer 0 16)))
           (dataitem-v6conn-port (unwrap (read-u16be buffer 0)))
           (dataitem-peertype-flags (unwrap (read-u8 buffer 0)))
           (dataitem-peertype-description (unwrap (slice buffer 0 1)))
           (dataitem-heartbeat (unwrap (read-u32be buffer 0)))
           (dataitem-macaddr-eui48 (unwrap (slice buffer 0 6)))
           (dataitem-v4addr-flags (unwrap (read-u8 buffer 0)))
           (dataitem-v4addr-addr (unwrap (read-u32be buffer 0)))
           (dataitem-v6addr-flags (unwrap (read-u8 buffer 0)))
           (dataitem-v6addr-addr (unwrap (slice buffer 0 16)))
           (dataitem-v4subnet-flags (unwrap (read-u8 buffer 0)))
           (dataitem-v4subnet-subnet (unwrap (read-u32be buffer 0)))
           (dataitem-v4subnet-prefixlen (unwrap (read-u8 buffer 0)))
           (dataitem-v6subnet-flags (unwrap (read-u8 buffer 0)))
           (dataitem-v6subnet-subnet (unwrap (slice buffer 0 16)))
           (dataitem-v6subnet-prefixlen (unwrap (read-u8 buffer 0)))
           (dataitem-mdrr (unwrap (read-u64be buffer 0)))
           (dataitem-mdrt (unwrap (read-u64be buffer 0)))
           (dataitem-cdrr (unwrap (read-u64be buffer 0)))
           (dataitem-cdrt (unwrap (read-u64be buffer 0)))
           (dataitem-latency (unwrap (read-u64be buffer 0)))
           (dataitem-resources (unwrap (read-u8 buffer 0)))
           (dataitem-rlqr (unwrap (read-u8 buffer 0)))
           (dataitem-rlqt (unwrap (read-u8 buffer 0)))
           (dataitem-mtu (unwrap (read-u16be buffer 0)))
           (dataitem-hop-count-flags (unwrap (read-u8 buffer 0)))
           (dataitem-hop-count-flags-p (extract-bits dataitem-hop-count-flags 0x0 0))
           (dataitem-hop-count-flags-reserved (extract-bits dataitem-hop-count-flags 0x0 0))
           (dataitem-li-length (unwrap (read-u16be buffer 0)))
           (dataitem-li (unwrap (slice buffer 0 1)))
           (dataitem-max-lat (unwrap (read-u64be buffer 0)))
           (dataitem-status-text (unwrap (slice buffer 1 1)))
           (dataitem-hop-count (unwrap (read-u8 buffer 1)))
           (dataitem-min-lat (unwrap (read-u64be buffer 8)))
           (dataitem-length (unwrap (read-u16be buffer 18)))
           (signal-signature (unwrap (slice buffer 20 4)))
           (signal-length (unwrap (read-u16be buffer 26)))
           (message-length (unwrap (read-u16be buffer 30)))
           )

      (ok (list
        (cons 'dataitem-v4conn-flags (list (cons 'raw dataitem-v4conn-flags) (cons 'formatted (fmt-hex dataitem-v4conn-flags))))
        (cons 'dataitem-v4conn-addr (list (cons 'raw dataitem-v4conn-addr) (cons 'formatted (fmt-ipv4 dataitem-v4conn-addr))))
        (cons 'dataitem-v4conn-port (list (cons 'raw dataitem-v4conn-port) (cons 'formatted (number->string dataitem-v4conn-port))))
        (cons 'dataitem-v6conn-flags (list (cons 'raw dataitem-v6conn-flags) (cons 'formatted (fmt-hex dataitem-v6conn-flags))))
        (cons 'dataitem-v6conn-addr (list (cons 'raw dataitem-v6conn-addr) (cons 'formatted (fmt-ipv6-address dataitem-v6conn-addr))))
        (cons 'dataitem-v6conn-port (list (cons 'raw dataitem-v6conn-port) (cons 'formatted (number->string dataitem-v6conn-port))))
        (cons 'dataitem-peertype-flags (list (cons 'raw dataitem-peertype-flags) (cons 'formatted (fmt-hex dataitem-peertype-flags))))
        (cons 'dataitem-peertype-description (list (cons 'raw dataitem-peertype-description) (cons 'formatted (utf8->string dataitem-peertype-description))))
        (cons 'dataitem-heartbeat (list (cons 'raw dataitem-heartbeat) (cons 'formatted (number->string dataitem-heartbeat))))
        (cons 'dataitem-macaddr-eui48 (list (cons 'raw dataitem-macaddr-eui48) (cons 'formatted (fmt-mac dataitem-macaddr-eui48))))
        (cons 'dataitem-v4addr-flags (list (cons 'raw dataitem-v4addr-flags) (cons 'formatted (fmt-hex dataitem-v4addr-flags))))
        (cons 'dataitem-v4addr-addr (list (cons 'raw dataitem-v4addr-addr) (cons 'formatted (fmt-ipv4 dataitem-v4addr-addr))))
        (cons 'dataitem-v6addr-flags (list (cons 'raw dataitem-v6addr-flags) (cons 'formatted (fmt-hex dataitem-v6addr-flags))))
        (cons 'dataitem-v6addr-addr (list (cons 'raw dataitem-v6addr-addr) (cons 'formatted (fmt-ipv6-address dataitem-v6addr-addr))))
        (cons 'dataitem-v4subnet-flags (list (cons 'raw dataitem-v4subnet-flags) (cons 'formatted (fmt-hex dataitem-v4subnet-flags))))
        (cons 'dataitem-v4subnet-subnet (list (cons 'raw dataitem-v4subnet-subnet) (cons 'formatted (fmt-ipv4 dataitem-v4subnet-subnet))))
        (cons 'dataitem-v4subnet-prefixlen (list (cons 'raw dataitem-v4subnet-prefixlen) (cons 'formatted (number->string dataitem-v4subnet-prefixlen))))
        (cons 'dataitem-v6subnet-flags (list (cons 'raw dataitem-v6subnet-flags) (cons 'formatted (fmt-hex dataitem-v6subnet-flags))))
        (cons 'dataitem-v6subnet-subnet (list (cons 'raw dataitem-v6subnet-subnet) (cons 'formatted (fmt-ipv6-address dataitem-v6subnet-subnet))))
        (cons 'dataitem-v6subnet-prefixlen (list (cons 'raw dataitem-v6subnet-prefixlen) (cons 'formatted (number->string dataitem-v6subnet-prefixlen))))
        (cons 'dataitem-mdrr (list (cons 'raw dataitem-mdrr) (cons 'formatted (number->string dataitem-mdrr))))
        (cons 'dataitem-mdrt (list (cons 'raw dataitem-mdrt) (cons 'formatted (number->string dataitem-mdrt))))
        (cons 'dataitem-cdrr (list (cons 'raw dataitem-cdrr) (cons 'formatted (number->string dataitem-cdrr))))
        (cons 'dataitem-cdrt (list (cons 'raw dataitem-cdrt) (cons 'formatted (number->string dataitem-cdrt))))
        (cons 'dataitem-latency (list (cons 'raw dataitem-latency) (cons 'formatted (number->string dataitem-latency))))
        (cons 'dataitem-resources (list (cons 'raw dataitem-resources) (cons 'formatted (number->string dataitem-resources))))
        (cons 'dataitem-rlqr (list (cons 'raw dataitem-rlqr) (cons 'formatted (number->string dataitem-rlqr))))
        (cons 'dataitem-rlqt (list (cons 'raw dataitem-rlqt) (cons 'formatted (number->string dataitem-rlqt))))
        (cons 'dataitem-mtu (list (cons 'raw dataitem-mtu) (cons 'formatted (number->string dataitem-mtu))))
        (cons 'dataitem-hop-count-flags (list (cons 'raw dataitem-hop-count-flags) (cons 'formatted (fmt-hex dataitem-hop-count-flags))))
        (cons 'dataitem-hop-count-flags-p (list (cons 'raw dataitem-hop-count-flags-p) (cons 'formatted (if (= dataitem-hop-count-flags-p 0) "Not set" "Set"))))
        (cons 'dataitem-hop-count-flags-reserved (list (cons 'raw dataitem-hop-count-flags-reserved) (cons 'formatted (if (= dataitem-hop-count-flags-reserved 0) "Not set" "Set"))))
        (cons 'dataitem-li-length (list (cons 'raw dataitem-li-length) (cons 'formatted (number->string dataitem-li-length))))
        (cons 'dataitem-li (list (cons 'raw dataitem-li) (cons 'formatted (fmt-bytes dataitem-li))))
        (cons 'dataitem-max-lat (list (cons 'raw dataitem-max-lat) (cons 'formatted (number->string dataitem-max-lat))))
        (cons 'dataitem-status-text (list (cons 'raw dataitem-status-text) (cons 'formatted (utf8->string dataitem-status-text))))
        (cons 'dataitem-hop-count (list (cons 'raw dataitem-hop-count) (cons 'formatted (number->string dataitem-hop-count))))
        (cons 'dataitem-min-lat (list (cons 'raw dataitem-min-lat) (cons 'formatted (number->string dataitem-min-lat))))
        (cons 'dataitem-length (list (cons 'raw dataitem-length) (cons 'formatted (number->string dataitem-length))))
        (cons 'signal-signature (list (cons 'raw signal-signature) (cons 'formatted (utf8->string signal-signature))))
        (cons 'signal-length (list (cons 'raw signal-length) (cons 'formatted (number->string signal-length))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        )))

    (catch (e)
      (err (str "DLEP parse error: " e)))))

;; dissect-dlep: parse DLEP from bytevector
;; Returns (ok fields-alist) or (err message)