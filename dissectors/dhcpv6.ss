;; packet-dhcpv6.c
;; Routines for DHCPv6 packet disassembly
;; Copyright 2004, Nicolas DICHTEL - 6WIND - <nicolas.dichtel@6wind.com>
;; Jun-ichiro itojun Hagino <itojun@iijlab.net>
;; IItom Tsutomu MIENO <iitom@utouto.com>
;; SHIRASAKI Yasuhiro <yasuhiro@gnome.gr.jp>
;; Tony Lindstrom <tony.lindstrom@ericsson.com>
;; Copyright 2012, Jerome LAFORGE <jerome.laforge@gmail.com>
;;
;; The information used comes from:
;; RFC1034 (DOMAIN NAMES - CONCEPTS AND FACILITIES)
;; RFC1035 (DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION)
;; RFC1535 (A Security Problem with DNS) [clear definition of Partial names]
;; RFC2181 (Clarifications to the DNS Specification)
;; RFC3319 (SIP options)
;; RFC3633 (Prefix options) replaces draft-ietf-dhc-dhcpv6-opt-lifetime-00
;; RFC3646 (DNS Configuration options for DHCP for IPv6 (DHCPv6))
;; RFC3898 (NIS options)
;; RFC4075 (SNTP - Configuration Option for DHCPv6)
;; - replaces "draft-ietf-dhc-dhcpv6-opt-timeconfig-03"
;; RFC4242 (Information Refresh Time Option)
;; RFC4280 (Broadcast and Multicast Control Servers Options)
;; RFC4649 (Remote ID option)
;; RFC4704 (DHCPv6 Client FQDN Option)
;; RFC5007 (DHCPv6 Leasequery)
;; RFC5417 (CAPWAP Access Controller DHCP Option)
;; RFC5460 (DHCPv6 Bulk Leasequery)
;; RFC5678 (DHCP Options for IEEE 802.21 Mobility Services (MoS) Discovery)
;; RFC5908 (Network Time Protocol (NTP) Server Option)
;; RFC5970 (DHCPv6 Options for Network Boot)
;; RFC6334 (Dual-Stack Lite Option)
;; RFC6422 (Relay-Supplied DHCP Options)
;; RFC6603 (Prefix Exclude Option)
;; RFC6607 (Virtual Subnet Selection Options for DHCPv4 and DHCPv6)
;; RFC6610 (DHCP Options for Home Information Discovery in Mobile IPv6 (MIPv6))
;; RFC6939 (Client Link-Layer Address Option in DHCPv6)
;; RFC7037 (RADIUS Option for the DHCPv6 Relay Agent)
;; RFC7598 (Configuration of Softwire Address and Port-Mapped Clients)
;; RFC8415 (Dynamic Host Configuration Protocol for IPv6 (DHCPv6))
;; RFC8520 (Manufacturer Usage Descriptions) replaces "draft-ietf-opsawg-mud-02"
;; RFC8947 (Link-Layer Address Assignment Mechanism for DHCPv6)
;; RFC9463 (Discovery of Network-designated Resolvers - DoT, DoH, DoQ)
;; RFC9527 (DHCPv6 Options for the Homenet Naming Authority)
;; RFC9686 (Registering self-generated addresses)
;; draft-ietf-dhc-rfc8415bis-12 (Dynamic Host Configuration Protocol for IPv6 (DHCPv6))
;; Submitted to IESG for Publication - replace references in comments after publication
;; CL-SP-CANN-DHCP-Reg-I15-180509 (CableLabs' DHCP Options Registry) latest
;;
;; Note that protocol constants are still subject to change, based on IANA
;; assignment decisions.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dhcpv6.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dhcpv6.c
;; RFC 1034

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
(def (dissect-dhcpv6 buffer)
  "DHCPv6"
  (try
    (let* (
           (domain-field-len-exceeded (unwrap (read-u8 buffer 0)))
           (root-only-domain-name (unwrap (slice buffer 0 1)))
           (bulk-leasequery-size (unwrap (read-u16be buffer 0)))
           (bulk-leasequery-reserved (unwrap (read-u8 buffer 3)))
           (bulk-leasequery-trans-id (unwrap (read-u16be buffer 4)))
           (non-dns-encoded-name (unwrap (read-u8 buffer 6)))
           )

      (ok (list
        (cons 'domain-field-len-exceeded (list (cons 'raw domain-field-len-exceeded) (cons 'formatted (number->string domain-field-len-exceeded))))
        (cons 'root-only-domain-name (list (cons 'raw root-only-domain-name) (cons 'formatted (utf8->string root-only-domain-name))))
        (cons 'bulk-leasequery-size (list (cons 'raw bulk-leasequery-size) (cons 'formatted (number->string bulk-leasequery-size))))
        (cons 'bulk-leasequery-reserved (list (cons 'raw bulk-leasequery-reserved) (cons 'formatted (number->string bulk-leasequery-reserved))))
        (cons 'bulk-leasequery-trans-id (list (cons 'raw bulk-leasequery-trans-id) (cons 'formatted (number->string bulk-leasequery-trans-id))))
        (cons 'non-dns-encoded-name (list (cons 'raw non-dns-encoded-name) (cons 'formatted (number->string non-dns-encoded-name))))
        )))

    (catch (e)
      (err (str "DHCPV6 parse error: " e)))))

;; dissect-dhcpv6: parse DHCPV6 from bytevector
;; Returns (ok fields-alist) or (err message)