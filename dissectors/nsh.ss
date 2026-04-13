;; packet-nsh.c
;; Routines for Network Service Header
;;
;; RFC8300
;; Author: Vanson Lim <vlim@cisco.com>
;; (c) Copyright 2020, Cisco Systems Inc.
;;
;; draft-ietf-sfc-nsh-01
;; Author: Chidambaram Arunachalam <carunach@cisco.com>
;; Copyright 2016, ciscoSystems Inc.
;;
;; (c) Copyright 2016, Sumit Kumar Jha <sjha3@ncsu.edu>
;; Support for VXLAN GPE encapsulation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nsh.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nsh.c
;; RFC 8300

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
(def (dissect-nsh buffer)
  "Network Service Header"
  (try
    (let* (
           (bbf-interface-id (unwrap (slice buffer 0 8)))
           (bbf-network-instance (unwrap (slice buffer 0 1)))
           (bbf-mac (unwrap (slice buffer 0 6)))
           (bbf-logical-port-id (unwrap (slice buffer 0 1)))
           (bbf-logical-port-id-str (unwrap (slice buffer 0 1)))
           (tlv-policy-id (unwrap (slice buffer 0 1)))
           (tlv-source-group (unwrap (slice buffer 0 4)))
           (tlv-ingress-network-source-iface (unwrap (slice buffer 0 1)))
           (tlv-ingress-network-node-info (unwrap (slice buffer 0 1)))
           (tlv-tenant-id (unwrap (slice buffer 0 1)))
           (context-header (unwrap (slice buffer 0 4)))
           (metadata-class (unwrap (read-u16be buffer 0)))
           (metadata-type (unwrap (read-u8 buffer 0)))
           (metadata-length (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u16be buffer 0)))
           (oam (unwrap (read-u16be buffer 0)))
           (critical-metadata (unwrap (read-u16be buffer 0)))
           (ttl (unwrap (read-u16be buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           (md-type (unwrap (read-u8 buffer 0)))
           (service-pathID (unwrap (read-u24be buffer 0)))
           (service-index (unwrap (read-u8 buffer 0)))
           (tlv-mpls-entropy-label (unwrap (read-u24be buffer 1)))
           (tlv-ipv6-flow-id (unwrap (read-u24be buffer 1)))
           (tlv-forwarding-context-vni (unwrap (read-u24be buffer 1)))
           (tlv-forwarding-context-mpls-vpn-label (unwrap (read-u24be buffer 1)))
           (tlv-forwarding-context-cvlan (unwrap (read-u24be buffer 1)))
           (tlv-forwarding-context-svlan (unwrap (read-u24be buffer 1)))
           (tlv-forwarding-context-vlan (unwrap (read-u16be buffer 1)))
           (tlv-dest-group (unwrap (slice buffer 4 4)))
           (tlv-forwarding-context-session-id (unwrap (read-u32be buffer 4)))
           )

      (ok (list
        (cons 'bbf-interface-id (list (cons 'raw bbf-interface-id) (cons 'formatted (fmt-bytes bbf-interface-id))))
        (cons 'bbf-network-instance (list (cons 'raw bbf-network-instance) (cons 'formatted (utf8->string bbf-network-instance))))
        (cons 'bbf-mac (list (cons 'raw bbf-mac) (cons 'formatted (fmt-mac bbf-mac))))
        (cons 'bbf-logical-port-id (list (cons 'raw bbf-logical-port-id) (cons 'formatted (fmt-bytes bbf-logical-port-id))))
        (cons 'bbf-logical-port-id-str (list (cons 'raw bbf-logical-port-id-str) (cons 'formatted (utf8->string bbf-logical-port-id-str))))
        (cons 'tlv-policy-id (list (cons 'raw tlv-policy-id) (cons 'formatted (fmt-bytes tlv-policy-id))))
        (cons 'tlv-source-group (list (cons 'raw tlv-source-group) (cons 'formatted (fmt-bytes tlv-source-group))))
        (cons 'tlv-ingress-network-source-iface (list (cons 'raw tlv-ingress-network-source-iface) (cons 'formatted (fmt-bytes tlv-ingress-network-source-iface))))
        (cons 'tlv-ingress-network-node-info (list (cons 'raw tlv-ingress-network-node-info) (cons 'formatted (fmt-bytes tlv-ingress-network-node-info))))
        (cons 'tlv-tenant-id (list (cons 'raw tlv-tenant-id) (cons 'formatted (fmt-bytes tlv-tenant-id))))
        (cons 'context-header (list (cons 'raw context-header) (cons 'formatted (fmt-bytes context-header))))
        (cons 'metadata-class (list (cons 'raw metadata-class) (cons 'formatted (number->string metadata-class))))
        (cons 'metadata-type (list (cons 'raw metadata-type) (cons 'formatted (number->string metadata-type))))
        (cons 'metadata-length (list (cons 'raw metadata-length) (cons 'formatted (fmt-hex metadata-length))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'oam (list (cons 'raw oam) (cons 'formatted (number->string oam))))
        (cons 'critical-metadata (list (cons 'raw critical-metadata) (cons 'formatted (number->string critical-metadata))))
        (cons 'ttl (list (cons 'raw ttl) (cons 'formatted (fmt-hex ttl))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'md-type (list (cons 'raw md-type) (cons 'formatted (number->string md-type))))
        (cons 'service-pathID (list (cons 'raw service-pathID) (cons 'formatted (number->string service-pathID))))
        (cons 'service-index (list (cons 'raw service-index) (cons 'formatted (number->string service-index))))
        (cons 'tlv-mpls-entropy-label (list (cons 'raw tlv-mpls-entropy-label) (cons 'formatted (number->string tlv-mpls-entropy-label))))
        (cons 'tlv-ipv6-flow-id (list (cons 'raw tlv-ipv6-flow-id) (cons 'formatted (number->string tlv-ipv6-flow-id))))
        (cons 'tlv-forwarding-context-vni (list (cons 'raw tlv-forwarding-context-vni) (cons 'formatted (number->string tlv-forwarding-context-vni))))
        (cons 'tlv-forwarding-context-mpls-vpn-label (list (cons 'raw tlv-forwarding-context-mpls-vpn-label) (cons 'formatted (number->string tlv-forwarding-context-mpls-vpn-label))))
        (cons 'tlv-forwarding-context-cvlan (list (cons 'raw tlv-forwarding-context-cvlan) (cons 'formatted (number->string tlv-forwarding-context-cvlan))))
        (cons 'tlv-forwarding-context-svlan (list (cons 'raw tlv-forwarding-context-svlan) (cons 'formatted (number->string tlv-forwarding-context-svlan))))
        (cons 'tlv-forwarding-context-vlan (list (cons 'raw tlv-forwarding-context-vlan) (cons 'formatted (number->string tlv-forwarding-context-vlan))))
        (cons 'tlv-dest-group (list (cons 'raw tlv-dest-group) (cons 'formatted (fmt-bytes tlv-dest-group))))
        (cons 'tlv-forwarding-context-session-id (list (cons 'raw tlv-forwarding-context-session-id) (cons 'formatted (number->string tlv-forwarding-context-session-id))))
        )))

    (catch (e)
      (err (str "NSH parse error: " e)))))

;; dissect-nsh: parse NSH from bytevector
;; Returns (ok fields-alist) or (err message)