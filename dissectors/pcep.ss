;; packet-pcep.c
;; Routines for PCEP packet disassembly
;; draft-ietf-pce-pcep-09
;; draft-ietf-pce-pcep-xro-02
;; See also RFC 4655, RFC 4657, RFC 5520, RFC 5521, RFC 5440 and RFC 5541
;;
;; (c) Copyright 2007 Silvia Cristina Tejedor <silviacristina.tejedor@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Added support of "A Set of Monitoring Tools for Path Computation Element
;; (PCE)-Based Architecture" (RFC 5886)
;; (c) Copyright 2012 Svetoslav Duhovnikov <duhovnikov[AT]gmail.com>
;;
;; Added support of "PCEP Extensions for Stateful PCE"
;; (draft-ietf-pce-stateful-pce-09) and
;; "PCEP Extensions for PCE-initiated LSP Setup in a Stateful PCE Model"
;; (draft-ietf-pce-pce-initiated-lsp-01) and
;; "Optimizations of Label Switched Path State Synchronization Procedures for a Stateful PCE"
;; (draft-ietf-pce-stateful-sync-optimizations-01)
;; (c) Copyright 2014 Simon Zhong <szhong[AT]juniper.net>
;;
;; Added support of "PCEP Extensions for Segment Routing"
;; (draft-ietf-pce-segment-routing-03) and
;; "Conveying path setup type in PCEP messages"
;; (draft-ietf-pce-lsp-setup-type-02)
;; (c) Copyright 2015 Francesco Fondelli <francesco.fondelli[AT]gmail.com>
;;
;; Added support of "Extensions to the Path Computation Element Communication Protocol (PCEP)
;; for Point-to-Multipoint Traffic Engineering Label Switched Paths" (RFC 6006)
;; (c) Copyright 2015 Francesco Paolucci <fr.paolucci[AT].sssup.it>,
;; Oscar Gonzalez de Dios <oscar.gonzalezdedios@telefonica.com>,
;; ICT EU PACE Project, www.ict-pace.net
;;
;; Added support of "PCEP Extensions for Establishing Relationships
;; Between Sets of LSPs" (draft-ietf-pce-association-group-00)
;; (c) Copyright 2015 Francesco Fondelli <francesco.fondelli[AT]gmail.com>
;;
;; Added support of "Conveying Vendor-Specific Constraints in the
;; Path Computation Element Communication Protocol" (RFC 7470)
;; Completed support of RFC 6006
;; Added support of "PCE-Based Computation Procedure to Compute Shortest
;; Constrained Point-to-Multipoint (P2MP) Inter-Domain Traffic Engineering
;; Label Switched Paths" (RFC 7334)
;; (c) Copyright 2016 Simon Zhong <szhong[AT]juniper.net>
;;
;; Added support of "Extensions to the Path Computation Element Communication Protocol (PCEP)
;; to compute service aware Label Switched Path (LSP)." (draft-ietf-pce-pcep-service-aware-13)
;; Updated support of "PCEP Extensions for Segment Routing" (draft-ietf-pce-segment-routing-08)
;; (c) Copyright 2017 Simon Zhong <szhong[AT]juniper.net>
;; Updated support from draft-ietf-pce-segment-routing-08 to RFC 8664  "PCEP Extensions for Segment Routing"
;; Added support of draft-ietf-pce-segment-routing-policy-cp-05 "PCEP extension to support Segment Routing Policy Candidate Paths"
;; (c) Copyright 2021 Oscar Gonzalez de Dios <oscar.gonzalezdedios[AT]telefonica.com>
;;

;; jerboa-ethereal/dissectors/pcep.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pcep.c
;; RFC 4655

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
(def (dissect-pcep buffer)
  "Path Computation Element communication Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (flags (unwrap (read-u8 buffer 0)))
           (hdr-msg-flags-reserved (unwrap (read-u8 buffer 0)))
           (message-length (unwrap (read-u16be buffer 0)))
           (op-conf-assoc-range-reserved (unwrap (slice buffer 4 2)))
           (op-conf-assoc-range-assoc-type (unwrap (read-u16be buffer 6)))
           (op-conf-assoc-range-start-assoc (unwrap (read-u16be buffer 8)))
           (op-conf-assoc-range-range (unwrap (read-u16be buffer 10)))
           (subobj-ipv4-length (unwrap (read-u8 buffer 12)))
           (subobj-ipv4-ipv4 (unwrap (read-u32be buffer 12)))
           (subobj-ipv4-prefix-length (unwrap (read-u8 buffer 12)))
           (subobj-ipv4-padding (unwrap (read-u8 buffer 12)))
           (subobj-ipv4-flags (unwrap (read-u8 buffer 12)))
           (subobj-flags-lpa (unwrap (read-u8 buffer 12)))
           (subobj-flags-lpu (unwrap (read-u8 buffer 12)))
           (subobj-iro-ipv4-l (unwrap (read-u8 buffer 12)))
           (subobj-ipv4-x (unwrap (read-u8 buffer 12)))
           (subobj-ipv6-length (unwrap (read-u8 buffer 12)))
           (subobj-ipv6-ipv6 (unwrap (slice buffer 12 16)))
           (subobj-ipv6-prefix-length (unwrap (read-u8 buffer 12)))
           (subobj-ipv6-padding (unwrap (read-u8 buffer 12)))
           (subobj-ipv6-flags (unwrap (read-u8 buffer 12)))
           (subobj-iro-ipv6-l (unwrap (read-u8 buffer 12)))
           (subobj-ipv6-x (unwrap (read-u8 buffer 12)))
           (subobj-label-control-length (unwrap (read-u8 buffer 12)))
           (subobj-label-control-reserved (unwrap (read-u8 buffer 12)))
           (subobj-label-control-c-type (unwrap (read-u8 buffer 12)))
           (subobj-label-control-label (unwrap (slice buffer 12 1)))
           (subobj-label-control-flags (unwrap (read-u8 buffer 12)))
           (subobj-label-flags-gl (unwrap (read-u8 buffer 12)))
           (subobj-sr-length (unwrap (read-u8 buffer 12)))
           (subobj-sr-flags (unwrap (read-u16be buffer 12)))
           (subobj-sr-flags-m (extract-bits subobj-sr-flags 0x0 0))
           (subobj-sr-flags-c (extract-bits subobj-sr-flags 0x0 0))
           (subobj-sr-flags-s (extract-bits subobj-sr-flags 0x0 0))
           (subobj-sr-flags-f (extract-bits subobj-sr-flags 0x0 0))
           (subobj-sr-sid (unwrap (read-u32be buffer 12)))
           (subobj-sr-sid-label (unwrap (read-u32be buffer 12)))
           (subobj-sr-sid-tc (unwrap (read-u32be buffer 12)))
           (subobj-sr-sid-s (unwrap (read-u32be buffer 12)))
           (subobj-sr-sid-ttl (unwrap (read-u32be buffer 12)))
           (subobj-srv6-length (unwrap (read-u8 buffer 12)))
           (subobj-srv6-flags (unwrap (read-u16be buffer 12)))
           (subobj-srv6-flags-s (extract-bits subobj-srv6-flags 0x0 0))
           (subobj-srv6-flags-f (extract-bits subobj-srv6-flags 0x0 0))
           (subobj-srv6-flags-t (extract-bits subobj-srv6-flags 0x0 0))
           (subobj-srv6-flags-v (extract-bits subobj-srv6-flags 0x0 0))
           (subobj-srv6-reserved (unwrap (read-u16be buffer 12)))
           (subobj-srv6-sid (unwrap (slice buffer 12 16)))
           (subobj-unnumb-interfaceID-length (unwrap (read-u8 buffer 12)))
           (subobj-unnumb-interfaceID-reserved (unwrap (read-u16be buffer 12)))
           (subobj-unnumb-interfaceID-flags (unwrap (read-u16be buffer 12)))
           (rp-flags-reserved (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-c (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-f (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-n (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-e (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-m (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-d (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-p (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-s (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-v (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-o (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-b (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-r (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (rp-flags-pri (extract-bits subobj-unnumb-interfaceID-flags 0x0 0))
           (subobj-unnumb-interfaceID-reserved-rrobj (unwrap (read-u16be buffer 12)))
           (subobj-iro-unnumb-interfaceID-l (unwrap (read-u8 buffer 12)))
           (subobj-unnumb-interfaceID-x (unwrap (read-u8 buffer 12)))
           (subobj-unnumb-interfaceID-reserved-xroobj (unwrap (read-u8 buffer 12)))
           (subobj-unnumb-interfaceID-router-id (unwrap (read-u32be buffer 12)))
           (subobj-unnumb-interfaceID-interface-id (unwrap (read-u32be buffer 12)))
           (subobj-autonomous-sys-num-x (unwrap (read-u8 buffer 12)))
           (subobj-autonomous-sys-num-length (unwrap (read-u8 buffer 12)))
           (subobj-autonomous-sys-num-reserved (unwrap (read-u8 buffer 12)))
           (subobj-autonomous-sys-num-optional-as-number-high-octets (unwrap (read-u16be buffer 12)))
           (subobj-autonomous-sys-num-as-number (unwrap (read-u16be buffer 12)))
           (subobj-iro-autonomous-sys-num-l (unwrap (read-u8 buffer 12)))
           (subobj-srlg-x (unwrap (read-u8 buffer 12)))
           (subobj-srlg-length (unwrap (read-u8 buffer 12)))
           (subobj-srlg-id (unwrap (read-u32be buffer 12)))
           (subobj-srlg-reserved (unwrap (read-u8 buffer 12)))
           (subobj-exrs-type (unwrap (read-u8 buffer 12)))
           (subobj-exrs-length (unwrap (read-u8 buffer 12)))
           (subobj-exrs-reserved (unwrap (read-u16be buffer 12)))
           (subobj-pksv4-length (unwrap (read-u8 buffer 16)))
           (subobj-pksv4-path-key (unwrap (read-u16be buffer 16)))
           (subobj-pksv4-pce-id (unwrap (read-u32be buffer 16)))
           (subobj-pksv6-length (unwrap (read-u8 buffer 16)))
           (subobj-pksv6-path-key (unwrap (read-u16be buffer 16)))
           (subobj-pksv6-pce-id (unwrap (slice buffer 16 4)))
           (object-type (unwrap (read-u8 buffer 16)))
           (hdr-obj-flags (unwrap (read-u8 buffer 16)))
           (hdr-obj-flags-i (extract-bits hdr-obj-flags 0x0 0))
           (hdr-obj-flags-p (extract-bits hdr-obj-flags 0x0 0))
           (hdr-obj-flags-reserved (extract-bits hdr-obj-flags 0x0 0))
           (object-length (unwrap (read-u16be buffer 16)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'hdr-msg-flags-reserved (list (cons 'raw hdr-msg-flags-reserved) (cons 'formatted (if (= hdr-msg-flags-reserved 0) "False" "True"))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'op-conf-assoc-range-reserved (list (cons 'raw op-conf-assoc-range-reserved) (cons 'formatted (fmt-bytes op-conf-assoc-range-reserved))))
        (cons 'op-conf-assoc-range-assoc-type (list (cons 'raw op-conf-assoc-range-assoc-type) (cons 'formatted (number->string op-conf-assoc-range-assoc-type))))
        (cons 'op-conf-assoc-range-start-assoc (list (cons 'raw op-conf-assoc-range-start-assoc) (cons 'formatted (number->string op-conf-assoc-range-start-assoc))))
        (cons 'op-conf-assoc-range-range (list (cons 'raw op-conf-assoc-range-range) (cons 'formatted (number->string op-conf-assoc-range-range))))
        (cons 'subobj-ipv4-length (list (cons 'raw subobj-ipv4-length) (cons 'formatted (number->string subobj-ipv4-length))))
        (cons 'subobj-ipv4-ipv4 (list (cons 'raw subobj-ipv4-ipv4) (cons 'formatted (fmt-ipv4 subobj-ipv4-ipv4))))
        (cons 'subobj-ipv4-prefix-length (list (cons 'raw subobj-ipv4-prefix-length) (cons 'formatted (number->string subobj-ipv4-prefix-length))))
        (cons 'subobj-ipv4-padding (list (cons 'raw subobj-ipv4-padding) (cons 'formatted (fmt-hex subobj-ipv4-padding))))
        (cons 'subobj-ipv4-flags (list (cons 'raw subobj-ipv4-flags) (cons 'formatted (fmt-hex subobj-ipv4-flags))))
        (cons 'subobj-flags-lpa (list (cons 'raw subobj-flags-lpa) (cons 'formatted (if (= subobj-flags-lpa 0) "False" "True"))))
        (cons 'subobj-flags-lpu (list (cons 'raw subobj-flags-lpu) (cons 'formatted (if (= subobj-flags-lpu 0) "False" "True"))))
        (cons 'subobj-iro-ipv4-l (list (cons 'raw subobj-iro-ipv4-l) (cons 'formatted (fmt-hex subobj-iro-ipv4-l))))
        (cons 'subobj-ipv4-x (list (cons 'raw subobj-ipv4-x) (cons 'formatted (fmt-hex subobj-ipv4-x))))
        (cons 'subobj-ipv6-length (list (cons 'raw subobj-ipv6-length) (cons 'formatted (number->string subobj-ipv6-length))))
        (cons 'subobj-ipv6-ipv6 (list (cons 'raw subobj-ipv6-ipv6) (cons 'formatted (fmt-ipv6-address subobj-ipv6-ipv6))))
        (cons 'subobj-ipv6-prefix-length (list (cons 'raw subobj-ipv6-prefix-length) (cons 'formatted (number->string subobj-ipv6-prefix-length))))
        (cons 'subobj-ipv6-padding (list (cons 'raw subobj-ipv6-padding) (cons 'formatted (fmt-hex subobj-ipv6-padding))))
        (cons 'subobj-ipv6-flags (list (cons 'raw subobj-ipv6-flags) (cons 'formatted (fmt-hex subobj-ipv6-flags))))
        (cons 'subobj-iro-ipv6-l (list (cons 'raw subobj-iro-ipv6-l) (cons 'formatted (fmt-hex subobj-iro-ipv6-l))))
        (cons 'subobj-ipv6-x (list (cons 'raw subobj-ipv6-x) (cons 'formatted (fmt-hex subobj-ipv6-x))))
        (cons 'subobj-label-control-length (list (cons 'raw subobj-label-control-length) (cons 'formatted (number->string subobj-label-control-length))))
        (cons 'subobj-label-control-reserved (list (cons 'raw subobj-label-control-reserved) (cons 'formatted (number->string subobj-label-control-reserved))))
        (cons 'subobj-label-control-c-type (list (cons 'raw subobj-label-control-c-type) (cons 'formatted (number->string subobj-label-control-c-type))))
        (cons 'subobj-label-control-label (list (cons 'raw subobj-label-control-label) (cons 'formatted (fmt-bytes subobj-label-control-label))))
        (cons 'subobj-label-control-flags (list (cons 'raw subobj-label-control-flags) (cons 'formatted (fmt-hex subobj-label-control-flags))))
        (cons 'subobj-label-flags-gl (list (cons 'raw subobj-label-flags-gl) (cons 'formatted (if (= subobj-label-flags-gl 0) "False" "True"))))
        (cons 'subobj-sr-length (list (cons 'raw subobj-sr-length) (cons 'formatted (number->string subobj-sr-length))))
        (cons 'subobj-sr-flags (list (cons 'raw subobj-sr-flags) (cons 'formatted (fmt-hex subobj-sr-flags))))
        (cons 'subobj-sr-flags-m (list (cons 'raw subobj-sr-flags-m) (cons 'formatted (if (= subobj-sr-flags-m 0) "Not set" "Set"))))
        (cons 'subobj-sr-flags-c (list (cons 'raw subobj-sr-flags-c) (cons 'formatted (if (= subobj-sr-flags-c 0) "Not set" "Set"))))
        (cons 'subobj-sr-flags-s (list (cons 'raw subobj-sr-flags-s) (cons 'formatted (if (= subobj-sr-flags-s 0) "Not set" "Set"))))
        (cons 'subobj-sr-flags-f (list (cons 'raw subobj-sr-flags-f) (cons 'formatted (if (= subobj-sr-flags-f 0) "Not set" "Set"))))
        (cons 'subobj-sr-sid (list (cons 'raw subobj-sr-sid) (cons 'formatted (number->string subobj-sr-sid))))
        (cons 'subobj-sr-sid-label (list (cons 'raw subobj-sr-sid-label) (cons 'formatted (number->string subobj-sr-sid-label))))
        (cons 'subobj-sr-sid-tc (list (cons 'raw subobj-sr-sid-tc) (cons 'formatted (number->string subobj-sr-sid-tc))))
        (cons 'subobj-sr-sid-s (list (cons 'raw subobj-sr-sid-s) (cons 'formatted (number->string subobj-sr-sid-s))))
        (cons 'subobj-sr-sid-ttl (list (cons 'raw subobj-sr-sid-ttl) (cons 'formatted (number->string subobj-sr-sid-ttl))))
        (cons 'subobj-srv6-length (list (cons 'raw subobj-srv6-length) (cons 'formatted (number->string subobj-srv6-length))))
        (cons 'subobj-srv6-flags (list (cons 'raw subobj-srv6-flags) (cons 'formatted (fmt-hex subobj-srv6-flags))))
        (cons 'subobj-srv6-flags-s (list (cons 'raw subobj-srv6-flags-s) (cons 'formatted (if (= subobj-srv6-flags-s 0) "Not set" "Set"))))
        (cons 'subobj-srv6-flags-f (list (cons 'raw subobj-srv6-flags-f) (cons 'formatted (if (= subobj-srv6-flags-f 0) "Not set" "Set"))))
        (cons 'subobj-srv6-flags-t (list (cons 'raw subobj-srv6-flags-t) (cons 'formatted (if (= subobj-srv6-flags-t 0) "Not set" "Set"))))
        (cons 'subobj-srv6-flags-v (list (cons 'raw subobj-srv6-flags-v) (cons 'formatted (if (= subobj-srv6-flags-v 0) "Not set" "Set"))))
        (cons 'subobj-srv6-reserved (list (cons 'raw subobj-srv6-reserved) (cons 'formatted (fmt-hex subobj-srv6-reserved))))
        (cons 'subobj-srv6-sid (list (cons 'raw subobj-srv6-sid) (cons 'formatted (fmt-ipv6-address subobj-srv6-sid))))
        (cons 'subobj-unnumb-interfaceID-length (list (cons 'raw subobj-unnumb-interfaceID-length) (cons 'formatted (number->string subobj-unnumb-interfaceID-length))))
        (cons 'subobj-unnumb-interfaceID-reserved (list (cons 'raw subobj-unnumb-interfaceID-reserved) (cons 'formatted (fmt-hex subobj-unnumb-interfaceID-reserved))))
        (cons 'subobj-unnumb-interfaceID-flags (list (cons 'raw subobj-unnumb-interfaceID-flags) (cons 'formatted (fmt-hex subobj-unnumb-interfaceID-flags))))
        (cons 'rp-flags-reserved (list (cons 'raw rp-flags-reserved) (cons 'formatted (if (= rp-flags-reserved 0) "Not set" "Set"))))
        (cons 'rp-flags-c (list (cons 'raw rp-flags-c) (cons 'formatted (if (= rp-flags-c 0) "Not set" "Set"))))
        (cons 'rp-flags-f (list (cons 'raw rp-flags-f) (cons 'formatted (if (= rp-flags-f 0) "Not set" "Set"))))
        (cons 'rp-flags-n (list (cons 'raw rp-flags-n) (cons 'formatted (if (= rp-flags-n 0) "Not set" "Set"))))
        (cons 'rp-flags-e (list (cons 'raw rp-flags-e) (cons 'formatted (if (= rp-flags-e 0) "Not set" "Set"))))
        (cons 'rp-flags-m (list (cons 'raw rp-flags-m) (cons 'formatted (if (= rp-flags-m 0) "Not set" "Set"))))
        (cons 'rp-flags-d (list (cons 'raw rp-flags-d) (cons 'formatted (if (= rp-flags-d 0) "Not set" "Set"))))
        (cons 'rp-flags-p (list (cons 'raw rp-flags-p) (cons 'formatted (if (= rp-flags-p 0) "Not set" "Set"))))
        (cons 'rp-flags-s (list (cons 'raw rp-flags-s) (cons 'formatted (if (= rp-flags-s 0) "Not set" "Set"))))
        (cons 'rp-flags-v (list (cons 'raw rp-flags-v) (cons 'formatted (if (= rp-flags-v 0) "Not set" "Set"))))
        (cons 'rp-flags-o (list (cons 'raw rp-flags-o) (cons 'formatted (if (= rp-flags-o 0) "Not set" "Set"))))
        (cons 'rp-flags-b (list (cons 'raw rp-flags-b) (cons 'formatted (if (= rp-flags-b 0) "Not set" "Set"))))
        (cons 'rp-flags-r (list (cons 'raw rp-flags-r) (cons 'formatted (if (= rp-flags-r 0) "Not set" "Set"))))
        (cons 'rp-flags-pri (list (cons 'raw rp-flags-pri) (cons 'formatted (if (= rp-flags-pri 0) "Not set" "Set"))))
        (cons 'subobj-unnumb-interfaceID-reserved-rrobj (list (cons 'raw subobj-unnumb-interfaceID-reserved-rrobj) (cons 'formatted (fmt-hex subobj-unnumb-interfaceID-reserved-rrobj))))
        (cons 'subobj-iro-unnumb-interfaceID-l (list (cons 'raw subobj-iro-unnumb-interfaceID-l) (cons 'formatted (fmt-hex subobj-iro-unnumb-interfaceID-l))))
        (cons 'subobj-unnumb-interfaceID-x (list (cons 'raw subobj-unnumb-interfaceID-x) (cons 'formatted (fmt-hex subobj-unnumb-interfaceID-x))))
        (cons 'subobj-unnumb-interfaceID-reserved-xroobj (list (cons 'raw subobj-unnumb-interfaceID-reserved-xroobj) (cons 'formatted (fmt-hex subobj-unnumb-interfaceID-reserved-xroobj))))
        (cons 'subobj-unnumb-interfaceID-router-id (list (cons 'raw subobj-unnumb-interfaceID-router-id) (cons 'formatted (fmt-ipv4 subobj-unnumb-interfaceID-router-id))))
        (cons 'subobj-unnumb-interfaceID-interface-id (list (cons 'raw subobj-unnumb-interfaceID-interface-id) (cons 'formatted (number->string subobj-unnumb-interfaceID-interface-id))))
        (cons 'subobj-autonomous-sys-num-x (list (cons 'raw subobj-autonomous-sys-num-x) (cons 'formatted (fmt-hex subobj-autonomous-sys-num-x))))
        (cons 'subobj-autonomous-sys-num-length (list (cons 'raw subobj-autonomous-sys-num-length) (cons 'formatted (number->string subobj-autonomous-sys-num-length))))
        (cons 'subobj-autonomous-sys-num-reserved (list (cons 'raw subobj-autonomous-sys-num-reserved) (cons 'formatted (fmt-hex subobj-autonomous-sys-num-reserved))))
        (cons 'subobj-autonomous-sys-num-optional-as-number-high-octets (list (cons 'raw subobj-autonomous-sys-num-optional-as-number-high-octets) (cons 'formatted (fmt-hex subobj-autonomous-sys-num-optional-as-number-high-octets))))
        (cons 'subobj-autonomous-sys-num-as-number (list (cons 'raw subobj-autonomous-sys-num-as-number) (cons 'formatted (fmt-hex subobj-autonomous-sys-num-as-number))))
        (cons 'subobj-iro-autonomous-sys-num-l (list (cons 'raw subobj-iro-autonomous-sys-num-l) (cons 'formatted (fmt-hex subobj-iro-autonomous-sys-num-l))))
        (cons 'subobj-srlg-x (list (cons 'raw subobj-srlg-x) (cons 'formatted (fmt-hex subobj-srlg-x))))
        (cons 'subobj-srlg-length (list (cons 'raw subobj-srlg-length) (cons 'formatted (number->string subobj-srlg-length))))
        (cons 'subobj-srlg-id (list (cons 'raw subobj-srlg-id) (cons 'formatted (fmt-hex subobj-srlg-id))))
        (cons 'subobj-srlg-reserved (list (cons 'raw subobj-srlg-reserved) (cons 'formatted (fmt-hex subobj-srlg-reserved))))
        (cons 'subobj-exrs-type (list (cons 'raw subobj-exrs-type) (cons 'formatted (number->string subobj-exrs-type))))
        (cons 'subobj-exrs-length (list (cons 'raw subobj-exrs-length) (cons 'formatted (number->string subobj-exrs-length))))
        (cons 'subobj-exrs-reserved (list (cons 'raw subobj-exrs-reserved) (cons 'formatted (fmt-hex subobj-exrs-reserved))))
        (cons 'subobj-pksv4-length (list (cons 'raw subobj-pksv4-length) (cons 'formatted (number->string subobj-pksv4-length))))
        (cons 'subobj-pksv4-path-key (list (cons 'raw subobj-pksv4-path-key) (cons 'formatted (number->string subobj-pksv4-path-key))))
        (cons 'subobj-pksv4-pce-id (list (cons 'raw subobj-pksv4-pce-id) (cons 'formatted (fmt-ipv4 subobj-pksv4-pce-id))))
        (cons 'subobj-pksv6-length (list (cons 'raw subobj-pksv6-length) (cons 'formatted (number->string subobj-pksv6-length))))
        (cons 'subobj-pksv6-path-key (list (cons 'raw subobj-pksv6-path-key) (cons 'formatted (number->string subobj-pksv6-path-key))))
        (cons 'subobj-pksv6-pce-id (list (cons 'raw subobj-pksv6-pce-id) (cons 'formatted (fmt-ipv6-address subobj-pksv6-pce-id))))
        (cons 'object-type (list (cons 'raw object-type) (cons 'formatted (number->string object-type))))
        (cons 'hdr-obj-flags (list (cons 'raw hdr-obj-flags) (cons 'formatted (fmt-hex hdr-obj-flags))))
        (cons 'hdr-obj-flags-i (list (cons 'raw hdr-obj-flags-i) (cons 'formatted (if (= hdr-obj-flags-i 0) "Not set" "Set"))))
        (cons 'hdr-obj-flags-p (list (cons 'raw hdr-obj-flags-p) (cons 'formatted (if (= hdr-obj-flags-p 0) "Not set" "Set"))))
        (cons 'hdr-obj-flags-reserved (list (cons 'raw hdr-obj-flags-reserved) (cons 'formatted (if (= hdr-obj-flags-reserved 0) "Not set" "Set"))))
        (cons 'object-length (list (cons 'raw object-length) (cons 'formatted (number->string object-length))))
        )))

    (catch (e)
      (err (str "PCEP parse error: " e)))))

;; dissect-pcep: parse PCEP from bytevector
;; Returns (ok fields-alist) or (err message)