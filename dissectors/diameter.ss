;; packet-diameter.c
;; Routines for Diameter packet disassembly
;;
;; Copyright (c) 2001 by David Frascone <dave@frascone.com>
;; Copyright (c) 2007 by Luis E. Garcia Ontanon <luis@ontanon.org>
;;
;; Support for Request-Answer tracking and Tapping
;; introduced by Abhik Sarkar
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References:
;;
;; RFC 3588, "Diameter Base Protocol" (now RFC 6733)
;; draft-ietf-aaa-diameter-mobileip-16, "Diameter Mobile IPv4 Application"
;; (now RFC 4004)
;; draft-ietf-aaa-diameter-nasreq-14, "Diameter Network Access Server
;; Application" (now RFC 4005)
;; drafts/draft-ietf-aaa-diameter-cc-03, "Diameter Credit-Control
;; Application" (now RFC 4006)
;; draft-ietf-aaa-diameter-sip-app-01, "Diameter Session Initiation
;; Protocol (SIP) Application" (now RFC 4740)
;; RFC 5779, "Diameter Proxy Mobile IPv6: Mobile Access Gateway and
;; Local Mobility Anchor Interaction with Diameter Server"
;; 3GPP TS 29.273, V15.2.0
;; http://www.ietf.org/html.charters/aaa-charter.html
;; http://www.iana.org/assignments/radius-types
;; http://www.iana.org/assignments/address-family-numbers
;; http://www.iana.org/assignments/enterprise-numbers
;; http://www.iana.org/assignments/aaa-parameters
;;

;; jerboa-ethereal/dissectors/diameter.ss
;; Auto-generated from wireshark/epan/dissectors/packet-diameter.c
;; RFC 3588

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
(def (dissect-diameter buffer)
  "Diameter Protocol"
  (try
    (let* (
           (3gpp-mip6-feature-vector (unwrap (read-u64be buffer 0)))
           (3gpp-mip6-feature-vector-assign-local-ip (extract-bits 3gpp-mip6-feature-vector 0x80000000000 43))
           (3gpp-mip6-feature-vector-mip4-supported (extract-bits 3gpp-mip6-feature-vector 0x100000000000 44))
           (3gpp-mip6-feature-vector-optimized-idle-mode-mobility (extract-bits 3gpp-mip6-feature-vector 0x200000000000 45))
           (3gpp-mip6-feature-vector-gtpv2-supported (extract-bits 3gpp-mip6-feature-vector 0x400000000000 46))
           (mip6-feature-vector (unwrap (read-u64be buffer 0)))
           (mip6-feature-vector-mip6-integrated (extract-bits mip6-feature-vector 0x1 0))
           (mip6-feature-vector-local-home-agent-assignment (extract-bits mip6-feature-vector 0x2 1))
           (mip6-feature-vector-pmip6-supported (extract-bits mip6-feature-vector 0x10000000000 40))
           (mip6-feature-vector-ip4-hoa-supported (extract-bits mip6-feature-vector 0x20000000000 41))
           (mip6-feature-vector-local-mag-routing-supported (extract-bits mip6-feature-vector 0x40000000000 42))
           (version (unwrap (read-u8 buffer 0)))
           (avp-data-wrong-length (unwrap (slice buffer 0 1)))
           (user-equipment-info-mac (unwrap (slice buffer 0 6)))
           (user-equipment-info-imeisv (unwrap (slice buffer 0 1)))
           (result-code-mscc-level (unwrap (read-u32be buffer 0)))
           (result-code-cmd-level (unwrap (read-u32be buffer 0)))
           (ipv6-prefix-reserved (unwrap (read-u8 buffer 0)))
           (other-vendor-exp-res (unwrap (read-u32be buffer 0)))
           (avp (unwrap (slice buffer 0 1)))
           (avp-code (unwrap (read-u32be buffer 0)))
           (length (unwrap (read-u24be buffer 1)))
           (ipv6-prefix-length (unwrap (read-u8 buffer 1)))
           (ipv6-prefix-ipv6 (unwrap (slice buffer 2 16)))
           (ipv6-prefix-bytes (unwrap (slice buffer 2 1)))
           (avp-flags (unwrap (read-u8 buffer 4)))
           (avp-flags-vendor-specific (extract-bits avp-flags 0x0 0))
           (avp-flags-mandatory (extract-bits avp-flags 0x0 0))
           (avp-flags-protected (extract-bits avp-flags 0x0 0))
           (avp-flags-reserved3 (extract-bits avp-flags 0x0 0))
           (avp-flags-reserved4 (extract-bits avp-flags 0x0 0))
           (avp-flags-reserved5 (extract-bits avp-flags 0x0 0))
           (avp-flags-reserved6 (extract-bits avp-flags 0x0 0))
           (avp-flags-reserved7 (extract-bits avp-flags 0x0 0))
           (avp-len (unwrap (read-u24be buffer 5)))
           (hopbyhopid (unwrap (read-u32be buffer 12)))
           (avp-pad (unwrap (slice buffer 12 1)))
           (endtoendid (unwrap (read-u32be buffer 16)))
           )

      (ok (list
        (cons '3gpp-mip6-feature-vector (list (cons 'raw 3gpp-mip6-feature-vector) (cons 'formatted (fmt-hex 3gpp-mip6-feature-vector))))
        (cons '3gpp-mip6-feature-vector-assign-local-ip (list (cons 'raw 3gpp-mip6-feature-vector-assign-local-ip) (cons 'formatted (if (= 3gpp-mip6-feature-vector-assign-local-ip 0) "Not set" "Set"))))
        (cons '3gpp-mip6-feature-vector-mip4-supported (list (cons 'raw 3gpp-mip6-feature-vector-mip4-supported) (cons 'formatted (if (= 3gpp-mip6-feature-vector-mip4-supported 0) "Not set" "Set"))))
        (cons '3gpp-mip6-feature-vector-optimized-idle-mode-mobility (list (cons 'raw 3gpp-mip6-feature-vector-optimized-idle-mode-mobility) (cons 'formatted (if (= 3gpp-mip6-feature-vector-optimized-idle-mode-mobility 0) "Not set" "Set"))))
        (cons '3gpp-mip6-feature-vector-gtpv2-supported (list (cons 'raw 3gpp-mip6-feature-vector-gtpv2-supported) (cons 'formatted (if (= 3gpp-mip6-feature-vector-gtpv2-supported 0) "Not set" "Set"))))
        (cons 'mip6-feature-vector (list (cons 'raw mip6-feature-vector) (cons 'formatted (fmt-hex mip6-feature-vector))))
        (cons 'mip6-feature-vector-mip6-integrated (list (cons 'raw mip6-feature-vector-mip6-integrated) (cons 'formatted (if (= mip6-feature-vector-mip6-integrated 0) "Not set" "Set"))))
        (cons 'mip6-feature-vector-local-home-agent-assignment (list (cons 'raw mip6-feature-vector-local-home-agent-assignment) (cons 'formatted (if (= mip6-feature-vector-local-home-agent-assignment 0) "Not set" "Set"))))
        (cons 'mip6-feature-vector-pmip6-supported (list (cons 'raw mip6-feature-vector-pmip6-supported) (cons 'formatted (if (= mip6-feature-vector-pmip6-supported 0) "Not set" "Set"))))
        (cons 'mip6-feature-vector-ip4-hoa-supported (list (cons 'raw mip6-feature-vector-ip4-hoa-supported) (cons 'formatted (if (= mip6-feature-vector-ip4-hoa-supported 0) "Not set" "Set"))))
        (cons 'mip6-feature-vector-local-mag-routing-supported (list (cons 'raw mip6-feature-vector-local-mag-routing-supported) (cons 'formatted (if (= mip6-feature-vector-local-mag-routing-supported 0) "Not set" "Set"))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'avp-data-wrong-length (list (cons 'raw avp-data-wrong-length) (cons 'formatted (fmt-bytes avp-data-wrong-length))))
        (cons 'user-equipment-info-mac (list (cons 'raw user-equipment-info-mac) (cons 'formatted (fmt-mac user-equipment-info-mac))))
        (cons 'user-equipment-info-imeisv (list (cons 'raw user-equipment-info-imeisv) (cons 'formatted (utf8->string user-equipment-info-imeisv))))
        (cons 'result-code-mscc-level (list (cons 'raw result-code-mscc-level) (cons 'formatted (number->string result-code-mscc-level))))
        (cons 'result-code-cmd-level (list (cons 'raw result-code-cmd-level) (cons 'formatted (number->string result-code-cmd-level))))
        (cons 'ipv6-prefix-reserved (list (cons 'raw ipv6-prefix-reserved) (cons 'formatted (fmt-hex ipv6-prefix-reserved))))
        (cons 'other-vendor-exp-res (list (cons 'raw other-vendor-exp-res) (cons 'formatted (number->string other-vendor-exp-res))))
        (cons 'avp (list (cons 'raw avp) (cons 'formatted (fmt-bytes avp))))
        (cons 'avp-code (list (cons 'raw avp-code) (cons 'formatted (number->string avp-code))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'ipv6-prefix-length (list (cons 'raw ipv6-prefix-length) (cons 'formatted (number->string ipv6-prefix-length))))
        (cons 'ipv6-prefix-ipv6 (list (cons 'raw ipv6-prefix-ipv6) (cons 'formatted (fmt-ipv6-address ipv6-prefix-ipv6))))
        (cons 'ipv6-prefix-bytes (list (cons 'raw ipv6-prefix-bytes) (cons 'formatted (fmt-bytes ipv6-prefix-bytes))))
        (cons 'avp-flags (list (cons 'raw avp-flags) (cons 'formatted (fmt-hex avp-flags))))
        (cons 'avp-flags-vendor-specific (list (cons 'raw avp-flags-vendor-specific) (cons 'formatted (if (= avp-flags-vendor-specific 0) "Not set" "Set"))))
        (cons 'avp-flags-mandatory (list (cons 'raw avp-flags-mandatory) (cons 'formatted (if (= avp-flags-mandatory 0) "Not set" "Set"))))
        (cons 'avp-flags-protected (list (cons 'raw avp-flags-protected) (cons 'formatted (if (= avp-flags-protected 0) "Not set" "Set"))))
        (cons 'avp-flags-reserved3 (list (cons 'raw avp-flags-reserved3) (cons 'formatted (if (= avp-flags-reserved3 0) "Not set" "Set"))))
        (cons 'avp-flags-reserved4 (list (cons 'raw avp-flags-reserved4) (cons 'formatted (if (= avp-flags-reserved4 0) "Not set" "Set"))))
        (cons 'avp-flags-reserved5 (list (cons 'raw avp-flags-reserved5) (cons 'formatted (if (= avp-flags-reserved5 0) "Not set" "Set"))))
        (cons 'avp-flags-reserved6 (list (cons 'raw avp-flags-reserved6) (cons 'formatted (if (= avp-flags-reserved6 0) "Not set" "Set"))))
        (cons 'avp-flags-reserved7 (list (cons 'raw avp-flags-reserved7) (cons 'formatted (if (= avp-flags-reserved7 0) "Not set" "Set"))))
        (cons 'avp-len (list (cons 'raw avp-len) (cons 'formatted (number->string avp-len))))
        (cons 'hopbyhopid (list (cons 'raw hopbyhopid) (cons 'formatted (fmt-hex hopbyhopid))))
        (cons 'avp-pad (list (cons 'raw avp-pad) (cons 'formatted (fmt-bytes avp-pad))))
        (cons 'endtoendid (list (cons 'raw endtoendid) (cons 'formatted (fmt-hex endtoendid))))
        )))

    (catch (e)
      (err (str "DIAMETER parse error: " e)))))

;; dissect-diameter: parse DIAMETER from bytevector
;; Returns (ok fields-alist) or (err message)