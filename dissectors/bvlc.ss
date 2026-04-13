;; packet-bvlc.c
;; Routines for BACnet/IP (BVLL, BVLC) dissection
;; Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from README.developer,v 1.23
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bvlc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bvlc.c

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
(def (dissect-bvlc buffer)
  "BACnet Virtual Link Control"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 0)))
           (control (unwrap (read-u8 buffer 0)))
           (control-data-option (extract-bits control 0x0 0))
           (control-destination-option (extract-bits control 0x0 0))
           (control-destination-address (extract-bits control 0x0 0))
           (control-origin-address (extract-bits control 0x0 0))
           (control-reserved (extract-bits control 0x0 0))
           (msg-id (unwrap (read-u16be buffer 0)))
           (virt-source (unwrap (read-u24be buffer 2)))
           (orig-vmac (unwrap (slice buffer 2 6)))
           (bdt-ip (unwrap (read-u32be buffer 4)))
           (virt-dest (unwrap (read-u24be buffer 7)))
           (bdt-port (unwrap (read-u16be buffer 8)))
           (dest-vmac (unwrap (slice buffer 8 6)))
           (bdt-mask (unwrap (slice buffer 10 4)))
           (header-marker (unwrap (read-u8 buffer 14)))
           (result-data (unwrap (slice buffer 18 1)))
           (uris (unwrap (slice buffer 18 1)))
           (fdt-ttl (unwrap (read-u16be buffer 22)))
           (fdt-timeout (unwrap (read-u16be buffer 24)))
           (fdt-ip (unwrap (read-u32be buffer 26)))
           (orig-source-addr (unwrap (slice buffer 31 16)))
           (fwd-ip (unwrap (read-u32be buffer 32)))
           (fwd-port (unwrap (read-u16be buffer 36)))
           (orig-source-port (unwrap (read-u16be buffer 47)))
           (connect-vmac (unwrap (slice buffer 48 6)))
           (reg-ttl (unwrap (read-u16be buffer 49)))
           (fdt-ipv6 (unwrap (slice buffer 51 16)))
           (connect-uuid (unwrap (slice buffer 54 16)))
           (fdt-port (unwrap (read-u16be buffer 67)))
           (max-bvlc-length (unwrap (read-u16be buffer 70)))
           (max-npdu-length (unwrap (read-u16be buffer 72)))
           (vendor-id (unwrap (read-u16be buffer 74)))
           (proprietary-opt-type (unwrap (read-u8 buffer 76)))
           (proprietary-data (unwrap (slice buffer 76 1)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'control (list (cons 'raw control) (cons 'formatted (fmt-hex control))))
        (cons 'control-data-option (list (cons 'raw control-data-option) (cons 'formatted (if (= control-data-option 0) "Data Options field is absent." "Data Options field is present."))))
        (cons 'control-destination-option (list (cons 'raw control-destination-option) (cons 'formatted (if (= control-destination-option 0) "Destination Options field is absent." "Destination Options field is present."))))
        (cons 'control-destination-address (list (cons 'raw control-destination-address) (cons 'formatted (if (= control-destination-address 0) "Destination Virtual Address is absent." "Destination Virtual Address is present."))))
        (cons 'control-origin-address (list (cons 'raw control-origin-address) (cons 'formatted (if (= control-origin-address 0) "Originating Virtual Address is absent." "Originating Virtual Address is present."))))
        (cons 'control-reserved (list (cons 'raw control-reserved) (cons 'formatted (if (= control-reserved 0) "Shall be zero and is zero." "Shall be zero, but is not."))))
        (cons 'msg-id (list (cons 'raw msg-id) (cons 'formatted (number->string msg-id))))
        (cons 'virt-source (list (cons 'raw virt-source) (cons 'formatted (number->string virt-source))))
        (cons 'orig-vmac (list (cons 'raw orig-vmac) (cons 'formatted (fmt-bytes orig-vmac))))
        (cons 'bdt-ip (list (cons 'raw bdt-ip) (cons 'formatted (fmt-ipv4 bdt-ip))))
        (cons 'virt-dest (list (cons 'raw virt-dest) (cons 'formatted (number->string virt-dest))))
        (cons 'bdt-port (list (cons 'raw bdt-port) (cons 'formatted (number->string bdt-port))))
        (cons 'dest-vmac (list (cons 'raw dest-vmac) (cons 'formatted (fmt-bytes dest-vmac))))
        (cons 'bdt-mask (list (cons 'raw bdt-mask) (cons 'formatted (fmt-bytes bdt-mask))))
        (cons 'header-marker (list (cons 'raw header-marker) (cons 'formatted (fmt-hex header-marker))))
        (cons 'result-data (list (cons 'raw result-data) (cons 'formatted (fmt-bytes result-data))))
        (cons 'uris (list (cons 'raw uris) (cons 'formatted (fmt-bytes uris))))
        (cons 'fdt-ttl (list (cons 'raw fdt-ttl) (cons 'formatted (number->string fdt-ttl))))
        (cons 'fdt-timeout (list (cons 'raw fdt-timeout) (cons 'formatted (number->string fdt-timeout))))
        (cons 'fdt-ip (list (cons 'raw fdt-ip) (cons 'formatted (fmt-ipv4 fdt-ip))))
        (cons 'orig-source-addr (list (cons 'raw orig-source-addr) (cons 'formatted (fmt-ipv6-address orig-source-addr))))
        (cons 'fwd-ip (list (cons 'raw fwd-ip) (cons 'formatted (fmt-ipv4 fwd-ip))))
        (cons 'fwd-port (list (cons 'raw fwd-port) (cons 'formatted (number->string fwd-port))))
        (cons 'orig-source-port (list (cons 'raw orig-source-port) (cons 'formatted (number->string orig-source-port))))
        (cons 'connect-vmac (list (cons 'raw connect-vmac) (cons 'formatted (fmt-bytes connect-vmac))))
        (cons 'reg-ttl (list (cons 'raw reg-ttl) (cons 'formatted (number->string reg-ttl))))
        (cons 'fdt-ipv6 (list (cons 'raw fdt-ipv6) (cons 'formatted (fmt-ipv6-address fdt-ipv6))))
        (cons 'connect-uuid (list (cons 'raw connect-uuid) (cons 'formatted (fmt-bytes connect-uuid))))
        (cons 'fdt-port (list (cons 'raw fdt-port) (cons 'formatted (number->string fdt-port))))
        (cons 'max-bvlc-length (list (cons 'raw max-bvlc-length) (cons 'formatted (number->string max-bvlc-length))))
        (cons 'max-npdu-length (list (cons 'raw max-npdu-length) (cons 'formatted (number->string max-npdu-length))))
        (cons 'vendor-id (list (cons 'raw vendor-id) (cons 'formatted (fmt-hex vendor-id))))
        (cons 'proprietary-opt-type (list (cons 'raw proprietary-opt-type) (cons 'formatted (fmt-hex proprietary-opt-type))))
        (cons 'proprietary-data (list (cons 'raw proprietary-data) (cons 'formatted (fmt-bytes proprietary-data))))
        )))

    (catch (e)
      (err (str "BVLC parse error: " e)))))

;; dissect-bvlc: parse BVLC from bytevector
;; Returns (ok fields-alist) or (err message)