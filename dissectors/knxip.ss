;; packet-knxip.c
;; Routines for KNXnet/IP dissection
;; By Jan Kessler <kessler@ise.de>
;; Copyright 2004, Jan Kessler <kessler@ise.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/knxip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-knxip.c

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
(def (dissect-knxip buffer)
  "KNX/IP"
  (try
    (let* (
           (header-length (unwrap (read-u8 buffer 0)))
           (reserved (unwrap (read-u8 buffer 0)))
           (protocol-version (unwrap (read-u8 buffer 1)))
           (total-length (unwrap (read-u16be buffer 4)))
           (port (unwrap (read-u16be buffer 4)))
           (seq-counter (unwrap (read-u8 buffer 6)))
           (tunnel-feature (unwrap (read-u8 buffer 6)))
           (routing-loss (unwrap (read-u16be buffer 6)))
           (busy-control (unwrap (read-u16be buffer 10)))
           (selector (unwrap (read-u8 buffer 12)))
           (device-status (unwrap (read-u8 buffer 18)))
           (program-mode (extract-bits device-status 0x1 0))
           (project-id (unwrap (read-u16be buffer 20)))
           (project-number (unwrap (read-u16be buffer 20)))
           (installation-number (unwrap (read-u16be buffer 20)))
           (serial-number (unwrap (slice buffer 22 6)))
           (multicast-address (unwrap (read-u32be buffer 28)))
           (mac-address (unwrap (slice buffer 32 6)))
           (friendly-name (unwrap (slice buffer 38 30)))
           (service-version (unwrap (read-u8 buffer 68)))
           (ip-caps (unwrap (read-u8 buffer 82)))
           (ip-caps-auto (extract-bits ip-caps 0x4 2))
           (ip-caps-dhcp (extract-bits ip-caps 0x2 1))
           (ip-caps-bootp (extract-bits ip-caps 0x1 0))
           (ip-address (unwrap (read-u32be buffer 82)))
           (ip-subnet (unwrap (read-u32be buffer 86)))
           (ip-gateway (unwrap (read-u32be buffer 90)))
           (ip-dhcp (unwrap (read-u32be buffer 94)))
           (ip-assign (unwrap (read-u8 buffer 98)))
           (ip-assign-auto (extract-bits ip-assign 0x8 3))
           (ip-assign-dhcp (extract-bits ip-assign 0x4 2))
           (ip-assign-bootp (extract-bits ip-assign 0x2 1))
           (ip-assign-manual (extract-bits ip-assign 0x1 0))
           (security-version (unwrap (read-u8 buffer 102)))
           (medium-status (unwrap (read-u8 buffer 109)))
           (max-apdu-length (unwrap (read-u16be buffer 109)))
           (mask-version (unwrap (read-u16be buffer 111)))
           (manufacturer-code (unwrap (read-u16be buffer 113)))
           (srp-mandatory (unwrap (read-u8 buffer 115)))
           (srp-type (unwrap (read-u8 buffer 115)))
           (reset-command (unwrap (read-u8 buffer 115)))
           (tag (unwrap (read-u16be buffer 143)))
           (session (unwrap (read-u16be buffer 161)))
           (user (unwrap (read-u8 buffer 179)))
           (hf-bytes (unwrap (slice buffer 179 1)))
           (channel (unwrap (read-u8 buffer 195)))
           )

      (ok (list
        (cons 'header-length (list (cons 'raw header-length) (cons 'formatted (number->string header-length))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'protocol-version (list (cons 'raw protocol-version) (cons 'formatted (fmt-hex protocol-version))))
        (cons 'total-length (list (cons 'raw total-length) (cons 'formatted (number->string total-length))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'seq-counter (list (cons 'raw seq-counter) (cons 'formatted (number->string seq-counter))))
        (cons 'tunnel-feature (list (cons 'raw tunnel-feature) (cons 'formatted (fmt-hex tunnel-feature))))
        (cons 'routing-loss (list (cons 'raw routing-loss) (cons 'formatted (number->string routing-loss))))
        (cons 'busy-control (list (cons 'raw busy-control) (cons 'formatted (fmt-hex busy-control))))
        (cons 'selector (list (cons 'raw selector) (cons 'formatted (fmt-hex selector))))
        (cons 'device-status (list (cons 'raw device-status) (cons 'formatted (fmt-hex device-status))))
        (cons 'program-mode (list (cons 'raw program-mode) (cons 'formatted (if (= program-mode 0) "Not set" "Set"))))
        (cons 'project-id (list (cons 'raw project-id) (cons 'formatted (fmt-hex project-id))))
        (cons 'project-number (list (cons 'raw project-number) (cons 'formatted (number->string project-number))))
        (cons 'installation-number (list (cons 'raw installation-number) (cons 'formatted (number->string installation-number))))
        (cons 'serial-number (list (cons 'raw serial-number) (cons 'formatted (fmt-hex serial-number))))
        (cons 'multicast-address (list (cons 'raw multicast-address) (cons 'formatted (fmt-ipv4 multicast-address))))
        (cons 'mac-address (list (cons 'raw mac-address) (cons 'formatted (fmt-mac mac-address))))
        (cons 'friendly-name (list (cons 'raw friendly-name) (cons 'formatted (utf8->string friendly-name))))
        (cons 'service-version (list (cons 'raw service-version) (cons 'formatted (fmt-hex service-version))))
        (cons 'ip-caps (list (cons 'raw ip-caps) (cons 'formatted (fmt-hex ip-caps))))
        (cons 'ip-caps-auto (list (cons 'raw ip-caps-auto) (cons 'formatted (if (= ip-caps-auto 0) "Not set" "Set"))))
        (cons 'ip-caps-dhcp (list (cons 'raw ip-caps-dhcp) (cons 'formatted (if (= ip-caps-dhcp 0) "Not set" "Set"))))
        (cons 'ip-caps-bootp (list (cons 'raw ip-caps-bootp) (cons 'formatted (if (= ip-caps-bootp 0) "Not set" "Set"))))
        (cons 'ip-address (list (cons 'raw ip-address) (cons 'formatted (fmt-ipv4 ip-address))))
        (cons 'ip-subnet (list (cons 'raw ip-subnet) (cons 'formatted (fmt-ipv4 ip-subnet))))
        (cons 'ip-gateway (list (cons 'raw ip-gateway) (cons 'formatted (fmt-ipv4 ip-gateway))))
        (cons 'ip-dhcp (list (cons 'raw ip-dhcp) (cons 'formatted (fmt-ipv4 ip-dhcp))))
        (cons 'ip-assign (list (cons 'raw ip-assign) (cons 'formatted (fmt-hex ip-assign))))
        (cons 'ip-assign-auto (list (cons 'raw ip-assign-auto) (cons 'formatted (if (= ip-assign-auto 0) "Not set" "Set"))))
        (cons 'ip-assign-dhcp (list (cons 'raw ip-assign-dhcp) (cons 'formatted (if (= ip-assign-dhcp 0) "Not set" "Set"))))
        (cons 'ip-assign-bootp (list (cons 'raw ip-assign-bootp) (cons 'formatted (if (= ip-assign-bootp 0) "Not set" "Set"))))
        (cons 'ip-assign-manual (list (cons 'raw ip-assign-manual) (cons 'formatted (if (= ip-assign-manual 0) "Not set" "Set"))))
        (cons 'security-version (list (cons 'raw security-version) (cons 'formatted (fmt-hex security-version))))
        (cons 'medium-status (list (cons 'raw medium-status) (cons 'formatted (fmt-hex medium-status))))
        (cons 'max-apdu-length (list (cons 'raw max-apdu-length) (cons 'formatted (number->string max-apdu-length))))
        (cons 'mask-version (list (cons 'raw mask-version) (cons 'formatted (fmt-hex mask-version))))
        (cons 'manufacturer-code (list (cons 'raw manufacturer-code) (cons 'formatted (fmt-hex manufacturer-code))))
        (cons 'srp-mandatory (list (cons 'raw srp-mandatory) (cons 'formatted (number->string srp-mandatory))))
        (cons 'srp-type (list (cons 'raw srp-type) (cons 'formatted (fmt-hex srp-type))))
        (cons 'reset-command (list (cons 'raw reset-command) (cons 'formatted (fmt-hex reset-command))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (fmt-hex tag))))
        (cons 'session (list (cons 'raw session) (cons 'formatted (fmt-hex session))))
        (cons 'user (list (cons 'raw user) (cons 'formatted (number->string user))))
        (cons 'hf-bytes (list (cons 'raw hf-bytes) (cons 'formatted (fmt-bytes hf-bytes))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (fmt-hex channel))))
        )))

    (catch (e)
      (err (str "KNXIP parse error: " e)))))

;; dissect-knxip: parse KNXIP from bytevector
;; Returns (ok fields-alist) or (err message)