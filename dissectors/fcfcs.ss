;; packet-fcfcs.c
;; Routines for FC Fabric Configuration Server
;; Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fcfcs.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fcfcs.c

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
(def (dissect-fcfcs buffer)
  "FC Fabric Configuration Server"
  (try
    (let* (
           (vendor (unwrap (read-u8 buffer 0)))
           (maxres-size (unwrap (read-u16be buffer 0)))
           (iedomainid (unwrap (read-u8 buffer 16)))
           (num-mgmt-addresses (unwrap (read-u32be buffer 16)))
           (list-length (unwrap (read-u8 buffer 16)))
           (vendorname (unwrap (slice buffer 16 1)))
           (vendor-specific-information (unwrap (slice buffer 16 1)))
           (num-port-entries (unwrap (read-u32be buffer 16)))
           (physportnum (unwrap (slice buffer 16 4)))
           (num-attached-port-entries (unwrap (read-u32be buffer 16)))
           (num-mgmt-address-entries (unwrap (read-u32be buffer 16)))
           (num-platform-name-entries (unwrap (read-u32be buffer 16)))
           (numcap (unwrap (read-u32be buffer 16)))
           (platformname-len (unwrap (read-u8 buffer 20)))
           (platformname (unwrap (slice buffer 20 1)))
           (mgmt-subtype (unwrap (read-u8 buffer 20)))
           (vnd-capmask (unwrap (read-u24be buffer 20)))
           (num-platform-node-name-entries (unwrap (read-u32be buffer 536)))
           (num-ie-entries (unwrap (read-u32be buffer 540)))
           )

      (ok (list
        (cons 'vendor (list (cons 'raw vendor) (cons 'formatted (fmt-hex vendor))))
        (cons 'maxres-size (list (cons 'raw maxres-size) (cons 'formatted (number->string maxres-size))))
        (cons 'iedomainid (list (cons 'raw iedomainid) (cons 'formatted (fmt-hex iedomainid))))
        (cons 'num-mgmt-addresses (list (cons 'raw num-mgmt-addresses) (cons 'formatted (number->string num-mgmt-addresses))))
        (cons 'list-length (list (cons 'raw list-length) (cons 'formatted (number->string list-length))))
        (cons 'vendorname (list (cons 'raw vendorname) (cons 'formatted (utf8->string vendorname))))
        (cons 'vendor-specific-information (list (cons 'raw vendor-specific-information) (cons 'formatted (utf8->string vendor-specific-information))))
        (cons 'num-port-entries (list (cons 'raw num-port-entries) (cons 'formatted (number->string num-port-entries))))
        (cons 'physportnum (list (cons 'raw physportnum) (cons 'formatted (fmt-bytes physportnum))))
        (cons 'num-attached-port-entries (list (cons 'raw num-attached-port-entries) (cons 'formatted (number->string num-attached-port-entries))))
        (cons 'num-mgmt-address-entries (list (cons 'raw num-mgmt-address-entries) (cons 'formatted (number->string num-mgmt-address-entries))))
        (cons 'num-platform-name-entries (list (cons 'raw num-platform-name-entries) (cons 'formatted (number->string num-platform-name-entries))))
        (cons 'numcap (list (cons 'raw numcap) (cons 'formatted (number->string numcap))))
        (cons 'platformname-len (list (cons 'raw platformname-len) (cons 'formatted (number->string platformname-len))))
        (cons 'platformname (list (cons 'raw platformname) (cons 'formatted (fmt-bytes platformname))))
        (cons 'mgmt-subtype (list (cons 'raw mgmt-subtype) (cons 'formatted (fmt-hex mgmt-subtype))))
        (cons 'vnd-capmask (list (cons 'raw vnd-capmask) (cons 'formatted (fmt-hex vnd-capmask))))
        (cons 'num-platform-node-name-entries (list (cons 'raw num-platform-node-name-entries) (cons 'formatted (number->string num-platform-node-name-entries))))
        (cons 'num-ie-entries (list (cons 'raw num-ie-entries) (cons 'formatted (number->string num-ie-entries))))
        )))

    (catch (e)
      (err (str "FCFCS parse error: " e)))))

;; dissect-fcfcs: parse FCFCS from bytevector
;; Returns (ok fields-alist) or (err message)