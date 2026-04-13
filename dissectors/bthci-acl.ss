;; packet-bthci_acl.c
;; Routines for the Bluetooth ACL dissection
;; Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
;; - from: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
;; Copyright 2006, Ronnie Sahlberg
;; - refactored for Wireshark checkin
;; Copyright 2014, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bthci-acl.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bthci_acl.c

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
(def (dissect-bthci-acl buffer)
  "Bluetooth HCI ACL Packet"
  (try
    (let* (
           (acl-mode-last-change-in-frame (unwrap (read-u32be buffer 0)))
           (acl-role-last-change-in-frame (unwrap (read-u32be buffer 0)))
           (acl-dst-name (unwrap (slice buffer 0 1)))
           (acl-dst-bd-addr (unwrap (slice buffer 0 6)))
           (acl-src-name (unwrap (slice buffer 0 1)))
           (acl-src-bd-addr (unwrap (slice buffer 0 6)))
           (acl-disconnect-in (unwrap (read-u32be buffer 0)))
           (acl-connect-in (unwrap (read-u32be buffer 0)))
           (acl-continuation-to (unwrap (read-u32be buffer 0)))
           (acl-reassembled-in (unwrap (read-u32be buffer 0)))
           (acl-chandle (unwrap (read-u16be buffer 0)))
           (acl-length (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'acl-mode-last-change-in-frame (list (cons 'raw acl-mode-last-change-in-frame) (cons 'formatted (number->string acl-mode-last-change-in-frame))))
        (cons 'acl-role-last-change-in-frame (list (cons 'raw acl-role-last-change-in-frame) (cons 'formatted (number->string acl-role-last-change-in-frame))))
        (cons 'acl-dst-name (list (cons 'raw acl-dst-name) (cons 'formatted (utf8->string acl-dst-name))))
        (cons 'acl-dst-bd-addr (list (cons 'raw acl-dst-bd-addr) (cons 'formatted (fmt-mac acl-dst-bd-addr))))
        (cons 'acl-src-name (list (cons 'raw acl-src-name) (cons 'formatted (utf8->string acl-src-name))))
        (cons 'acl-src-bd-addr (list (cons 'raw acl-src-bd-addr) (cons 'formatted (fmt-mac acl-src-bd-addr))))
        (cons 'acl-disconnect-in (list (cons 'raw acl-disconnect-in) (cons 'formatted (number->string acl-disconnect-in))))
        (cons 'acl-connect-in (list (cons 'raw acl-connect-in) (cons 'formatted (number->string acl-connect-in))))
        (cons 'acl-continuation-to (list (cons 'raw acl-continuation-to) (cons 'formatted (number->string acl-continuation-to))))
        (cons 'acl-reassembled-in (list (cons 'raw acl-reassembled-in) (cons 'formatted (number->string acl-reassembled-in))))
        (cons 'acl-chandle (list (cons 'raw acl-chandle) (cons 'formatted (fmt-hex acl-chandle))))
        (cons 'acl-length (list (cons 'raw acl-length) (cons 'formatted (number->string acl-length))))
        )))

    (catch (e)
      (err (str "BTHCI-ACL parse error: " e)))))

;; dissect-bthci-acl: parse BTHCI-ACL from bytevector
;; Returns (ok fields-alist) or (err message)