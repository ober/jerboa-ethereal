;; packet-juniper.c
;; Routines for Juniper Networks, Inc. packet disassembly
;; Copyright 2005 Hannes Gredler <hannes@juniper.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/juniper.ss
;; Auto-generated from wireshark/epan/dissectors/packet-juniper.c

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
(def (dissect-juniper buffer)
  "Juniper"
  (try
    (let* (
           (magic (unwrap (read-u24be buffer 0)))
           (unknown-data (unwrap (slice buffer 0 4)))
           (aspic-cookie (unwrap (read-u64be buffer 0)))
           (lspic-cookie (unwrap (read-u32be buffer 0)))
           (atm1-cookie (unwrap (read-u32be buffer 0)))
           (atm2-cookie (unwrap (read-u64be buffer 0)))
           (encap-type (unwrap (read-u8 buffer 0)))
           (vlan (unwrap (read-u16be buffer 0)))
           (vn-host-ip (unwrap (read-u32be buffer 0)))
           (vn-flags (unwrap (read-u32be buffer 0)))
           (vn-flag-direction (extract-bits vn-flags 0x0 0))
           (vn-flag-mirror (extract-bits vn-flags 0x0 0))
           (vn-flag-reject (extract-bits vn-flags 0x0 0))
           (vn-flag-pass (extract-bits vn-flags 0x0 0))
           (vn-flag-log (extract-bits vn-flags 0x0 0))
           (vn-flag-deny (extract-bits vn-flags 0x0 0))
           (vn-flag-drop (extract-bits vn-flags 0x0 0))
           (vn-flag-alert (extract-bits vn-flags 0x0 0))
           (vn-src (unwrap (slice buffer 0 1)))
           (vn-dst (unwrap (slice buffer 0 1)))
           (st-eth-dst (unwrap (slice buffer 0 6)))
           (mlpic-cookie (unwrap (read-u16be buffer 2)))
           (cookie-len (unwrap (read-u32be buffer 2)))
           (ext-total-len (unwrap (read-u16be buffer 4)))
           (st-eth-src (unwrap (slice buffer 6 6)))
           (st-ip-len (unwrap (read-u8 buffer 14)))
           (st-esp-spi (unwrap (read-u32be buffer 14)))
           (st-esp-seq (unwrap (read-u32be buffer 18)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        (cons 'unknown-data (list (cons 'raw unknown-data) (cons 'formatted (fmt-bytes unknown-data))))
        (cons 'aspic-cookie (list (cons 'raw aspic-cookie) (cons 'formatted (fmt-hex aspic-cookie))))
        (cons 'lspic-cookie (list (cons 'raw lspic-cookie) (cons 'formatted (fmt-hex lspic-cookie))))
        (cons 'atm1-cookie (list (cons 'raw atm1-cookie) (cons 'formatted (fmt-hex atm1-cookie))))
        (cons 'atm2-cookie (list (cons 'raw atm2-cookie) (cons 'formatted (fmt-hex atm2-cookie))))
        (cons 'encap-type (list (cons 'raw encap-type) (cons 'formatted (number->string encap-type))))
        (cons 'vlan (list (cons 'raw vlan) (cons 'formatted (number->string vlan))))
        (cons 'vn-host-ip (list (cons 'raw vn-host-ip) (cons 'formatted (fmt-ipv4 vn-host-ip))))
        (cons 'vn-flags (list (cons 'raw vn-flags) (cons 'formatted (fmt-hex vn-flags))))
        (cons 'vn-flag-direction (list (cons 'raw vn-flag-direction) (cons 'formatted (if (= vn-flag-direction 0) "Not set" "Set"))))
        (cons 'vn-flag-mirror (list (cons 'raw vn-flag-mirror) (cons 'formatted (if (= vn-flag-mirror 0) "Not set" "Set"))))
        (cons 'vn-flag-reject (list (cons 'raw vn-flag-reject) (cons 'formatted (if (= vn-flag-reject 0) "Not set" "Set"))))
        (cons 'vn-flag-pass (list (cons 'raw vn-flag-pass) (cons 'formatted (if (= vn-flag-pass 0) "Not set" "Set"))))
        (cons 'vn-flag-log (list (cons 'raw vn-flag-log) (cons 'formatted (if (= vn-flag-log 0) "Not set" "Set"))))
        (cons 'vn-flag-deny (list (cons 'raw vn-flag-deny) (cons 'formatted (if (= vn-flag-deny 0) "Not set" "Set"))))
        (cons 'vn-flag-drop (list (cons 'raw vn-flag-drop) (cons 'formatted (if (= vn-flag-drop 0) "Not set" "Set"))))
        (cons 'vn-flag-alert (list (cons 'raw vn-flag-alert) (cons 'formatted (if (= vn-flag-alert 0) "Not set" "Set"))))
        (cons 'vn-src (list (cons 'raw vn-src) (cons 'formatted (utf8->string vn-src))))
        (cons 'vn-dst (list (cons 'raw vn-dst) (cons 'formatted (utf8->string vn-dst))))
        (cons 'st-eth-dst (list (cons 'raw st-eth-dst) (cons 'formatted (fmt-mac st-eth-dst))))
        (cons 'mlpic-cookie (list (cons 'raw mlpic-cookie) (cons 'formatted (fmt-hex mlpic-cookie))))
        (cons 'cookie-len (list (cons 'raw cookie-len) (cons 'formatted (number->string cookie-len))))
        (cons 'ext-total-len (list (cons 'raw ext-total-len) (cons 'formatted (number->string ext-total-len))))
        (cons 'st-eth-src (list (cons 'raw st-eth-src) (cons 'formatted (fmt-mac st-eth-src))))
        (cons 'st-ip-len (list (cons 'raw st-ip-len) (cons 'formatted (number->string st-ip-len))))
        (cons 'st-esp-spi (list (cons 'raw st-esp-spi) (cons 'formatted (number->string st-esp-spi))))
        (cons 'st-esp-seq (list (cons 'raw st-esp-seq) (cons 'formatted (number->string st-esp-seq))))
        )))

    (catch (e)
      (err (str "JUNIPER parse error: " e)))))

;; dissect-juniper: parse JUNIPER from bytevector
;; Returns (ok fields-alist) or (err message)