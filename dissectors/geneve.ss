;; packet-geneve.c
;; Routines for Geneve - Generic Network Virtualization Encapsulation
;; https://tools.ietf.org/html/rfc8926
;;
;; Copyright (c) 2024 cPacket Networks, Inc. All Rights Reserved.
;; Author: Martin Greenberg <mgreenberg@cpacket.com>
;;
;; Copyright (c) 2014 VMware, Inc. All Rights Reserved.
;; Author: Jesse Gross <jesse@nicira.com>
;;
;; Copyright 2021, Atul Sharma <asharm37@ncsu.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/geneve.ss
;; Auto-generated from wireshark/epan/dissectors/packet-geneve.c

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
(def (dissect-geneve buffer)
  "Generic Network Virtualization Encapsulation"
  (try
    (let* (
           (option (unwrap (slice buffer 0 1)))
           (version (unwrap (read-u8 buffer 0)))
           (flags (unwrap (read-u8 buffer 1)))
           (flag-oam (extract-bits flags 0x80 7))
           (flag-critical (extract-bits flags 0x40 6))
           (flag-reserved (extract-bits flags 0x3F 0))
           (option-type (unwrap (read-u8 buffer 2)))
           (option-type-critical (unwrap (read-u8 buffer 2)))
           (option-flags (unwrap (read-u8 buffer 3)))
           (option-flags-reserved (unwrap (read-u8 buffer 3)))
           (opt-gcp-direction (unwrap (read-u8 buffer 4)))
           (opt-gcp-reserved (unwrap (read-u8 buffer 4)))
           (opt-gcp-endpoint (unwrap (slice buffer 4 1)))
           (opt-gcp-profile (unwrap (read-u64be buffer 4)))
           (opt-cilium-service-ipv4 (unwrap (read-u32be buffer 4)))
           (vni (unwrap (read-u24be buffer 4)))
           (reserved (unwrap (read-u8 buffer 7)))
           (opt-cilium-service-ipv6 (unwrap (slice buffer 10 16)))
           (opt-cilium-service-port (unwrap (read-u16be buffer 26)))
           (opt-cilium-service-pad (unwrap (slice buffer 28 2)))
           (opt-cpkt-seqnum (unwrap (read-u32be buffer 28)))
           (opt-cpkt-origlen (unwrap (read-u16be buffer 32)))
           (opt-cpkt-reserved (unwrap (read-u8 buffer 34)))
           (opt-cpkt-version (unwrap (read-u8 buffer 35)))
           (opt-cpkt-ts-sec (unwrap (slice buffer 36 6)))
           (opt-cpkt-ts-nsec (unwrap (read-u32be buffer 42)))
           (opt-cpkt-ts-fracns (unwrap (read-u16be buffer 46)))
           (opt-cpkt-devid (unwrap (read-u16be buffer 48)))
           (opt-cpkt-portid (unwrap (read-u16be buffer 50)))
           (opt-unknown-data (unwrap (slice buffer 50 1)))
           (options (unwrap (slice buffer 50 1)))
           )

      (ok (list
        (cons 'option (list (cons 'raw option) (cons 'formatted (fmt-bytes option))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flag-oam (list (cons 'raw flag-oam) (cons 'formatted (if (= flag-oam 0) "Not set" "Set"))))
        (cons 'flag-critical (list (cons 'raw flag-critical) (cons 'formatted (if (= flag-critical 0) "Not set" "Set"))))
        (cons 'flag-reserved (list (cons 'raw flag-reserved) (cons 'formatted (if (= flag-reserved 0) "Not set" "Set"))))
        (cons 'option-type (list (cons 'raw option-type) (cons 'formatted (fmt-hex option-type))))
        (cons 'option-type-critical (list (cons 'raw option-type-critical) (cons 'formatted (number->string option-type-critical))))
        (cons 'option-flags (list (cons 'raw option-flags) (cons 'formatted (fmt-hex option-flags))))
        (cons 'option-flags-reserved (list (cons 'raw option-flags-reserved) (cons 'formatted (number->string option-flags-reserved))))
        (cons 'opt-gcp-direction (list (cons 'raw opt-gcp-direction) (cons 'formatted (if (= opt-gcp-direction 0) "False" "True"))))
        (cons 'opt-gcp-reserved (list (cons 'raw opt-gcp-reserved) (cons 'formatted (number->string opt-gcp-reserved))))
        (cons 'opt-gcp-endpoint (list (cons 'raw opt-gcp-endpoint) (cons 'formatted (fmt-bytes opt-gcp-endpoint))))
        (cons 'opt-gcp-profile (list (cons 'raw opt-gcp-profile) (cons 'formatted (number->string opt-gcp-profile))))
        (cons 'opt-cilium-service-ipv4 (list (cons 'raw opt-cilium-service-ipv4) (cons 'formatted (fmt-ipv4 opt-cilium-service-ipv4))))
        (cons 'vni (list (cons 'raw vni) (cons 'formatted (fmt-hex vni))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'opt-cilium-service-ipv6 (list (cons 'raw opt-cilium-service-ipv6) (cons 'formatted (fmt-ipv6-address opt-cilium-service-ipv6))))
        (cons 'opt-cilium-service-port (list (cons 'raw opt-cilium-service-port) (cons 'formatted (number->string opt-cilium-service-port))))
        (cons 'opt-cilium-service-pad (list (cons 'raw opt-cilium-service-pad) (cons 'formatted (fmt-bytes opt-cilium-service-pad))))
        (cons 'opt-cpkt-seqnum (list (cons 'raw opt-cpkt-seqnum) (cons 'formatted (number->string opt-cpkt-seqnum))))
        (cons 'opt-cpkt-origlen (list (cons 'raw opt-cpkt-origlen) (cons 'formatted (number->string opt-cpkt-origlen))))
        (cons 'opt-cpkt-reserved (list (cons 'raw opt-cpkt-reserved) (cons 'formatted (fmt-hex opt-cpkt-reserved))))
        (cons 'opt-cpkt-version (list (cons 'raw opt-cpkt-version) (cons 'formatted (number->string opt-cpkt-version))))
        (cons 'opt-cpkt-ts-sec (list (cons 'raw opt-cpkt-ts-sec) (cons 'formatted (number->string opt-cpkt-ts-sec))))
        (cons 'opt-cpkt-ts-nsec (list (cons 'raw opt-cpkt-ts-nsec) (cons 'formatted (number->string opt-cpkt-ts-nsec))))
        (cons 'opt-cpkt-ts-fracns (list (cons 'raw opt-cpkt-ts-fracns) (cons 'formatted (number->string opt-cpkt-ts-fracns))))
        (cons 'opt-cpkt-devid (list (cons 'raw opt-cpkt-devid) (cons 'formatted (number->string opt-cpkt-devid))))
        (cons 'opt-cpkt-portid (list (cons 'raw opt-cpkt-portid) (cons 'formatted (number->string opt-cpkt-portid))))
        (cons 'opt-unknown-data (list (cons 'raw opt-unknown-data) (cons 'formatted (fmt-bytes opt-unknown-data))))
        (cons 'options (list (cons 'raw options) (cons 'formatted (fmt-bytes options))))
        )))

    (catch (e)
      (err (str "GENEVE parse error: " e)))))

;; dissect-geneve: parse GENEVE from bytevector
;; Returns (ok fields-alist) or (err message)