;; packet-netlink-route.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netlink-route.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netlink_route.c

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
(def (dissect-netlink-route buffer)
  "Linux rtnetlink (route netlink) protocol"
  (try
    (let* (
           (route-ifi-index (unwrap (read-u32be buffer 4)))
           (route-ifi-flags-iff-up (unwrap (read-u8 buffer 8)))
           (route-ifi-flags-iff-broadcast (unwrap (read-u8 buffer 8)))
           (route-ifi-change (unwrap (read-u32be buffer 12)))
           (route-ifla-ifname (unwrap (slice buffer 16 1)))
           (route-ifla-mtu (unwrap (read-u32be buffer 16)))
           (route-ifla-txqlen (unwrap (read-u32be buffer 16)))
           (route-ifla-promiscuity (unwrap (read-u32be buffer 16)))
           (route-ifla-txqnum (unwrap (read-u32be buffer 16)))
           (route-ifla-rxqnum (unwrap (read-u32be buffer 16)))
           (route-ifla-group (unwrap (read-u32be buffer 16)))
           (route-ifla-gso-maxsegs (unwrap (read-u32be buffer 16)))
           (route-ifla-gso-maxsize (unwrap (read-u32be buffer 16)))
           (route-ifla-carrier (unwrap (read-u8 buffer 16)))
           (route-ifla-carrier-changes (unwrap (read-u32be buffer 16)))
           (route-ifla-qdisc (unwrap (slice buffer 16 1)))
           (route-ifla-map-memstart (unwrap (read-u64be buffer 16)))
           (route-ifla-map-memend (unwrap (read-u64be buffer 16)))
           (route-ifla-map-baseaddr (unwrap (read-u64be buffer 16)))
           (route-ifla-map-irq (unwrap (read-u16be buffer 16)))
           (route-ifla-map-dma (unwrap (read-u8 buffer 16)))
           (route-ifla-map-port (unwrap (read-u8 buffer 16)))
           (route-ifla-carrier-up-count (unwrap (read-u32be buffer 16)))
           (route-ifla-carrier-down-count (unwrap (read-u32be buffer 16)))
           (route-ifla-min-mtu (unwrap (read-u32be buffer 16)))
           (route-ifla-max-mtu (unwrap (read-u32be buffer 16)))
           (route-ifa-prefixlen (unwrap (read-u8 buffer 17)))
           (route-ifa-scope (unwrap (read-u8 buffer 19)))
           (route-ifa-index (unwrap (read-u32be buffer 20)))
           (route-ifa-label (unwrap (slice buffer 24 1)))
           (route-ifa-addr4 (unwrap (read-u32be buffer 24)))
           (route-ifa-addr6 (unwrap (slice buffer 24 16)))
           (route-rt-dst-len (unwrap (read-u8 buffer 25)))
           (route-rt-src-len (unwrap (read-u8 buffer 26)))
           (route-rt-tos (unwrap (read-u8 buffer 27)))
           (route-rt-table (unwrap (read-u8 buffer 28)))
           (route-rt-flags (unwrap (read-u32be buffer 32)))
           (route-rta-iif (unwrap (read-u32be buffer 36)))
           (route-rta-oif (unwrap (read-u32be buffer 36)))
           (route-nd-index (unwrap (read-u32be buffer 40)))
           (route-nd-flags (unwrap (read-u8 buffer 46)))
           (route-nd-type (unwrap (read-u8 buffer 47)))
           (route-ifi-family (unwrap (read-u8 buffer 48)))
           )

      (ok (list
        (cons 'route-ifi-index (list (cons 'raw route-ifi-index) (cons 'formatted (number->string route-ifi-index))))
        (cons 'route-ifi-flags-iff-up (list (cons 'raw route-ifi-flags-iff-up) (cons 'formatted (if (= route-ifi-flags-iff-up 0) "False" "True"))))
        (cons 'route-ifi-flags-iff-broadcast (list (cons 'raw route-ifi-flags-iff-broadcast) (cons 'formatted (if (= route-ifi-flags-iff-broadcast 0) "False" "True"))))
        (cons 'route-ifi-change (list (cons 'raw route-ifi-change) (cons 'formatted (number->string route-ifi-change))))
        (cons 'route-ifla-ifname (list (cons 'raw route-ifla-ifname) (cons 'formatted (utf8->string route-ifla-ifname))))
        (cons 'route-ifla-mtu (list (cons 'raw route-ifla-mtu) (cons 'formatted (number->string route-ifla-mtu))))
        (cons 'route-ifla-txqlen (list (cons 'raw route-ifla-txqlen) (cons 'formatted (number->string route-ifla-txqlen))))
        (cons 'route-ifla-promiscuity (list (cons 'raw route-ifla-promiscuity) (cons 'formatted (number->string route-ifla-promiscuity))))
        (cons 'route-ifla-txqnum (list (cons 'raw route-ifla-txqnum) (cons 'formatted (number->string route-ifla-txqnum))))
        (cons 'route-ifla-rxqnum (list (cons 'raw route-ifla-rxqnum) (cons 'formatted (number->string route-ifla-rxqnum))))
        (cons 'route-ifla-group (list (cons 'raw route-ifla-group) (cons 'formatted (number->string route-ifla-group))))
        (cons 'route-ifla-gso-maxsegs (list (cons 'raw route-ifla-gso-maxsegs) (cons 'formatted (number->string route-ifla-gso-maxsegs))))
        (cons 'route-ifla-gso-maxsize (list (cons 'raw route-ifla-gso-maxsize) (cons 'formatted (number->string route-ifla-gso-maxsize))))
        (cons 'route-ifla-carrier (list (cons 'raw route-ifla-carrier) (cons 'formatted (if (= route-ifla-carrier 0) "False" "True"))))
        (cons 'route-ifla-carrier-changes (list (cons 'raw route-ifla-carrier-changes) (cons 'formatted (number->string route-ifla-carrier-changes))))
        (cons 'route-ifla-qdisc (list (cons 'raw route-ifla-qdisc) (cons 'formatted (utf8->string route-ifla-qdisc))))
        (cons 'route-ifla-map-memstart (list (cons 'raw route-ifla-map-memstart) (cons 'formatted (fmt-hex route-ifla-map-memstart))))
        (cons 'route-ifla-map-memend (list (cons 'raw route-ifla-map-memend) (cons 'formatted (fmt-hex route-ifla-map-memend))))
        (cons 'route-ifla-map-baseaddr (list (cons 'raw route-ifla-map-baseaddr) (cons 'formatted (fmt-hex route-ifla-map-baseaddr))))
        (cons 'route-ifla-map-irq (list (cons 'raw route-ifla-map-irq) (cons 'formatted (number->string route-ifla-map-irq))))
        (cons 'route-ifla-map-dma (list (cons 'raw route-ifla-map-dma) (cons 'formatted (number->string route-ifla-map-dma))))
        (cons 'route-ifla-map-port (list (cons 'raw route-ifla-map-port) (cons 'formatted (number->string route-ifla-map-port))))
        (cons 'route-ifla-carrier-up-count (list (cons 'raw route-ifla-carrier-up-count) (cons 'formatted (number->string route-ifla-carrier-up-count))))
        (cons 'route-ifla-carrier-down-count (list (cons 'raw route-ifla-carrier-down-count) (cons 'formatted (number->string route-ifla-carrier-down-count))))
        (cons 'route-ifla-min-mtu (list (cons 'raw route-ifla-min-mtu) (cons 'formatted (number->string route-ifla-min-mtu))))
        (cons 'route-ifla-max-mtu (list (cons 'raw route-ifla-max-mtu) (cons 'formatted (number->string route-ifla-max-mtu))))
        (cons 'route-ifa-prefixlen (list (cons 'raw route-ifa-prefixlen) (cons 'formatted (number->string route-ifa-prefixlen))))
        (cons 'route-ifa-scope (list (cons 'raw route-ifa-scope) (cons 'formatted (number->string route-ifa-scope))))
        (cons 'route-ifa-index (list (cons 'raw route-ifa-index) (cons 'formatted (number->string route-ifa-index))))
        (cons 'route-ifa-label (list (cons 'raw route-ifa-label) (cons 'formatted (utf8->string route-ifa-label))))
        (cons 'route-ifa-addr4 (list (cons 'raw route-ifa-addr4) (cons 'formatted (fmt-ipv4 route-ifa-addr4))))
        (cons 'route-ifa-addr6 (list (cons 'raw route-ifa-addr6) (cons 'formatted (fmt-ipv6-address route-ifa-addr6))))
        (cons 'route-rt-dst-len (list (cons 'raw route-rt-dst-len) (cons 'formatted (number->string route-rt-dst-len))))
        (cons 'route-rt-src-len (list (cons 'raw route-rt-src-len) (cons 'formatted (number->string route-rt-src-len))))
        (cons 'route-rt-tos (list (cons 'raw route-rt-tos) (cons 'formatted (fmt-hex route-rt-tos))))
        (cons 'route-rt-table (list (cons 'raw route-rt-table) (cons 'formatted (number->string route-rt-table))))
        (cons 'route-rt-flags (list (cons 'raw route-rt-flags) (cons 'formatted (fmt-hex route-rt-flags))))
        (cons 'route-rta-iif (list (cons 'raw route-rta-iif) (cons 'formatted (number->string route-rta-iif))))
        (cons 'route-rta-oif (list (cons 'raw route-rta-oif) (cons 'formatted (number->string route-rta-oif))))
        (cons 'route-nd-index (list (cons 'raw route-nd-index) (cons 'formatted (number->string route-nd-index))))
        (cons 'route-nd-flags (list (cons 'raw route-nd-flags) (cons 'formatted (fmt-hex route-nd-flags))))
        (cons 'route-nd-type (list (cons 'raw route-nd-type) (cons 'formatted (fmt-hex route-nd-type))))
        (cons 'route-ifi-family (list (cons 'raw route-ifi-family) (cons 'formatted (number->string route-ifi-family))))
        )))

    (catch (e)
      (err (str "NETLINK-ROUTE parse error: " e)))))

;; dissect-netlink-route: parse NETLINK-ROUTE from bytevector
;; Returns (ok fields-alist) or (err message)