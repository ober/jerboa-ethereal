;; packet-ncsi.c
;;
;; Extends NCSI dissection based on DMTF Document Identifier: DSP0222 Version: 1.2.0_2b
;; Copyright 2019-2021, Caleb Chiu <caleb.chiu@macnica.com>
;;
;; Routines for NCSI dissection
;; Copyright 2017-2019, Jeremy Kerr <jk@ozlabs.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ncsi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ncsi.c

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
(def (dissect-ncsi buffer)
  "NCSI"
  (try
    (let* (
           (mc-id (unwrap (read-u8 buffer 0)))
           (revision (unwrap (read-u8 buffer 1)))
           (iid (unwrap (read-u8 buffer 3)))
           (type (unwrap (read-u8 buffer 4)))
           (chan (unwrap (read-u8 buffer 5)))
           (pkg (extract-bits chan 0xE0 5))
           (plen (unwrap (read-u8 buffer 7)))
           (bf (unwrap (read-u32be buffer 16)))
           (sm-mac (unwrap (slice buffer 16 6)))
           (aene-mc (unwrap (read-u8 buffer 19)))
           (dc-ald (unwrap (read-u8 buffer 19)))
           (sp-hwarb (unwrap (read-u8 buffer 19)))
           (ver (unwrap (slice buffer 20 8)))
           (sm-macno (unwrap (read-u8 buffer 22)))
           (sm-e (unwrap (read-u8 buffer 23)))
           (mlnx-rbt (unwrap (slice buffer 24 6)))
           (fw-name (unwrap (slice buffer 28 12)))
           (mlnx-ifm (unwrap (read-u8 buffer 30)))
           (mlnx-ifm-v4en (extract-bits mlnx-ifm 0x1 0))
           (mlnx-ifm-v6len (extract-bits mlnx-ifm 0x1 0))
           (mlnx-ifm-v6gen (extract-bits mlnx-ifm 0x1 0))
           (mlnx-sms (unwrap (read-u8 buffer 30)))
           (mlnx-sms-rbt (extract-bits mlnx-sms 0x1 0))
           (mlnx-sms-smbus (extract-bits mlnx-sms 0x1 0))
           (mlnx-sms-pcie (extract-bits mlnx-sms 0x1 0))
           (mlnx-sms-rbts (extract-bits mlnx-sms 0x1 0))
           (mlnx-sms-smbuss (extract-bits mlnx-sms 0x1 0))
           (mlnx-sms-pcies (extract-bits mlnx-sms 0x1 0))
           (mlnx-beid (unwrap (read-u8 buffer 31)))
           (mlnx-bidx (unwrap (read-u8 buffer 32)))
           (mlnx-gama-mac (unwrap (slice buffer 32 6)))
           (mlnx-baddr (unwrap (read-u8 buffer 33)))
           (mlnx-peid (unwrap (read-u8 buffer 34)))
           (mlnx-pidx (unwrap (read-u8 buffer 35)))
           (mlnx-paddr (unwrap (read-u16be buffer 36)))
           (fw-ver (unwrap (slice buffer 40 4)))
           (mlnx-v4addr (unwrap (read-u32be buffer 40)))
           (pci-did (unwrap (slice buffer 44 2)))
           (mlnx-v6local (unwrap (slice buffer 44 16)))
           (pci-vid (unwrap (slice buffer 46 2)))
           (pci-ssid (unwrap (slice buffer 48 4)))
           (mlnx-v6gbl (unwrap (slice buffer 60 16)))
           )

      (ok (list
        (cons 'mc-id (list (cons 'raw mc-id) (cons 'formatted (fmt-hex mc-id))))
        (cons 'revision (list (cons 'raw revision) (cons 'formatted (fmt-hex revision))))
        (cons 'iid (list (cons 'raw iid) (cons 'formatted (fmt-hex iid))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (fmt-hex type))))
        (cons 'chan (list (cons 'raw chan) (cons 'formatted (fmt-hex chan))))
        (cons 'pkg (list (cons 'raw pkg) (cons 'formatted (if (= pkg 0) "Not set" "Set"))))
        (cons 'plen (list (cons 'raw plen) (cons 'formatted (fmt-hex plen))))
        (cons 'bf (list (cons 'raw bf) (cons 'formatted (fmt-hex bf))))
        (cons 'sm-mac (list (cons 'raw sm-mac) (cons 'formatted (fmt-mac sm-mac))))
        (cons 'aene-mc (list (cons 'raw aene-mc) (cons 'formatted (fmt-hex aene-mc))))
        (cons 'dc-ald (list (cons 'raw dc-ald) (cons 'formatted (fmt-hex dc-ald))))
        (cons 'sp-hwarb (list (cons 'raw sp-hwarb) (cons 'formatted (fmt-hex sp-hwarb))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (utf8->string ver))))
        (cons 'sm-macno (list (cons 'raw sm-macno) (cons 'formatted (fmt-hex sm-macno))))
        (cons 'sm-e (list (cons 'raw sm-e) (cons 'formatted (if (= sm-e 0) "False" "True"))))
        (cons 'mlnx-rbt (list (cons 'raw mlnx-rbt) (cons 'formatted (fmt-mac mlnx-rbt))))
        (cons 'fw-name (list (cons 'raw fw-name) (cons 'formatted (utf8->string fw-name))))
        (cons 'mlnx-ifm (list (cons 'raw mlnx-ifm) (cons 'formatted (fmt-hex mlnx-ifm))))
        (cons 'mlnx-ifm-v4en (list (cons 'raw mlnx-ifm-v4en) (cons 'formatted (if (= mlnx-ifm-v4en 0) "Not set" "Set"))))
        (cons 'mlnx-ifm-v6len (list (cons 'raw mlnx-ifm-v6len) (cons 'formatted (if (= mlnx-ifm-v6len 0) "Not set" "Set"))))
        (cons 'mlnx-ifm-v6gen (list (cons 'raw mlnx-ifm-v6gen) (cons 'formatted (if (= mlnx-ifm-v6gen 0) "Not set" "Set"))))
        (cons 'mlnx-sms (list (cons 'raw mlnx-sms) (cons 'formatted (fmt-hex mlnx-sms))))
        (cons 'mlnx-sms-rbt (list (cons 'raw mlnx-sms-rbt) (cons 'formatted (if (= mlnx-sms-rbt 0) "Not set" "Set"))))
        (cons 'mlnx-sms-smbus (list (cons 'raw mlnx-sms-smbus) (cons 'formatted (if (= mlnx-sms-smbus 0) "Not set" "Set"))))
        (cons 'mlnx-sms-pcie (list (cons 'raw mlnx-sms-pcie) (cons 'formatted (if (= mlnx-sms-pcie 0) "Not set" "Set"))))
        (cons 'mlnx-sms-rbts (list (cons 'raw mlnx-sms-rbts) (cons 'formatted (if (= mlnx-sms-rbts 0) "Not set" "Set"))))
        (cons 'mlnx-sms-smbuss (list (cons 'raw mlnx-sms-smbuss) (cons 'formatted (if (= mlnx-sms-smbuss 0) "Not set" "Set"))))
        (cons 'mlnx-sms-pcies (list (cons 'raw mlnx-sms-pcies) (cons 'formatted (if (= mlnx-sms-pcies 0) "Not set" "Set"))))
        (cons 'mlnx-beid (list (cons 'raw mlnx-beid) (cons 'formatted (fmt-hex mlnx-beid))))
        (cons 'mlnx-bidx (list (cons 'raw mlnx-bidx) (cons 'formatted (fmt-hex mlnx-bidx))))
        (cons 'mlnx-gama-mac (list (cons 'raw mlnx-gama-mac) (cons 'formatted (fmt-mac mlnx-gama-mac))))
        (cons 'mlnx-baddr (list (cons 'raw mlnx-baddr) (cons 'formatted (fmt-hex mlnx-baddr))))
        (cons 'mlnx-peid (list (cons 'raw mlnx-peid) (cons 'formatted (fmt-hex mlnx-peid))))
        (cons 'mlnx-pidx (list (cons 'raw mlnx-pidx) (cons 'formatted (fmt-hex mlnx-pidx))))
        (cons 'mlnx-paddr (list (cons 'raw mlnx-paddr) (cons 'formatted (fmt-hex mlnx-paddr))))
        (cons 'fw-ver (list (cons 'raw fw-ver) (cons 'formatted (utf8->string fw-ver))))
        (cons 'mlnx-v4addr (list (cons 'raw mlnx-v4addr) (cons 'formatted (fmt-ipv4 mlnx-v4addr))))
        (cons 'pci-did (list (cons 'raw pci-did) (cons 'formatted (utf8->string pci-did))))
        (cons 'mlnx-v6local (list (cons 'raw mlnx-v6local) (cons 'formatted (fmt-ipv6-address mlnx-v6local))))
        (cons 'pci-vid (list (cons 'raw pci-vid) (cons 'formatted (utf8->string pci-vid))))
        (cons 'pci-ssid (list (cons 'raw pci-ssid) (cons 'formatted (utf8->string pci-ssid))))
        (cons 'mlnx-v6gbl (list (cons 'raw mlnx-v6gbl) (cons 'formatted (fmt-ipv6-address mlnx-v6gbl))))
        )))

    (catch (e)
      (err (str "NCSI parse error: " e)))))

;; dissect-ncsi: parse NCSI from bytevector
;; Returns (ok fields-alist) or (err message)