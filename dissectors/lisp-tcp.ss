;; packet-lisp-tcp.c
;; Routines for Locator/ID Separation Protocol (LISP) TCP Control Message dissection
;; Copyright 2014, 2018 Lorand Jakab <ljakab@ac.upc.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lisp-tcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lisp_tcp.c

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
(def (dissect-lisp-tcp buffer)
  "Locator/ID Separation Protocol (Reliable Transport)"
  (try
    (let* (
           (tcp-message-eid-prefix-length (unwrap (read-u8 buffer 0)))
           (tcp-message-length (unwrap (read-u16be buffer 2)))
           (tcp-message-eid-ipv4 (unwrap (read-u32be buffer 3)))
           (tcp-message-eid-ipv6 (unwrap (slice buffer 3 16)))
           (tcp-message-eid-mac (unwrap (slice buffer 3 6)))
           (tcp-message-eid-dn (unwrap (slice buffer 3 1)))
           (tcp-message-err-code (unwrap (read-u8 buffer 3)))
           (tcp-message-err-reserved (unwrap (read-u24be buffer 4)))
           (tcp-message-id (unwrap (read-u32be buffer 4)))
           (tcp-message-err-offending-msg-type (unwrap (read-u16be buffer 7)))
           (tcp-message-data (unwrap (slice buffer 8 1)))
           (tcp-message-end-marker (unwrap (read-u32be buffer 8)))
           (tcp-message-err-offending-msg-len (unwrap (read-u16be buffer 9)))
           (tcp-message-err-offending-msg-id (unwrap (read-u32be buffer 11)))
           (tcp-message-err-offending-msg-data (unwrap (slice buffer 15 1)))
           (tcp-message-registration-reject-res (unwrap (read-u16be buffer 16)))
           (tcp-message-registration-refresh-flags-rejected (unwrap (read-u8 buffer 19)))
           (tcp-message-registration-refresh-res (unwrap (read-u16be buffer 19)))
           (tcp-message-xtr-id (unwrap (slice buffer 21 1)))
           (tcp-message-iid (unwrap (read-u32be buffer 23)))
           (tcp-message-sid (unwrap (read-u32be buffer 27)))
           (tcp-message-site-id (unwrap (slice buffer 32 1)))
           (tcp-message-rloc-ipv4 (unwrap (read-u32be buffer 42)))
           (tcp-message-rloc-ipv6 (unwrap (slice buffer 42 16)))
           (tcp-message-rid (unwrap (read-u32be buffer 42)))
           )

      (ok (list
        (cons 'tcp-message-eid-prefix-length (list (cons 'raw tcp-message-eid-prefix-length) (cons 'formatted (number->string tcp-message-eid-prefix-length))))
        (cons 'tcp-message-length (list (cons 'raw tcp-message-length) (cons 'formatted (number->string tcp-message-length))))
        (cons 'tcp-message-eid-ipv4 (list (cons 'raw tcp-message-eid-ipv4) (cons 'formatted (fmt-ipv4 tcp-message-eid-ipv4))))
        (cons 'tcp-message-eid-ipv6 (list (cons 'raw tcp-message-eid-ipv6) (cons 'formatted (fmt-ipv6-address tcp-message-eid-ipv6))))
        (cons 'tcp-message-eid-mac (list (cons 'raw tcp-message-eid-mac) (cons 'formatted (fmt-mac tcp-message-eid-mac))))
        (cons 'tcp-message-eid-dn (list (cons 'raw tcp-message-eid-dn) (cons 'formatted (utf8->string tcp-message-eid-dn))))
        (cons 'tcp-message-err-code (list (cons 'raw tcp-message-err-code) (cons 'formatted (number->string tcp-message-err-code))))
        (cons 'tcp-message-err-reserved (list (cons 'raw tcp-message-err-reserved) (cons 'formatted (fmt-hex tcp-message-err-reserved))))
        (cons 'tcp-message-id (list (cons 'raw tcp-message-id) (cons 'formatted (number->string tcp-message-id))))
        (cons 'tcp-message-err-offending-msg-type (list (cons 'raw tcp-message-err-offending-msg-type) (cons 'formatted (number->string tcp-message-err-offending-msg-type))))
        (cons 'tcp-message-data (list (cons 'raw tcp-message-data) (cons 'formatted (fmt-bytes tcp-message-data))))
        (cons 'tcp-message-end-marker (list (cons 'raw tcp-message-end-marker) (cons 'formatted (fmt-hex tcp-message-end-marker))))
        (cons 'tcp-message-err-offending-msg-len (list (cons 'raw tcp-message-err-offending-msg-len) (cons 'formatted (number->string tcp-message-err-offending-msg-len))))
        (cons 'tcp-message-err-offending-msg-id (list (cons 'raw tcp-message-err-offending-msg-id) (cons 'formatted (number->string tcp-message-err-offending-msg-id))))
        (cons 'tcp-message-err-offending-msg-data (list (cons 'raw tcp-message-err-offending-msg-data) (cons 'formatted (fmt-bytes tcp-message-err-offending-msg-data))))
        (cons 'tcp-message-registration-reject-res (list (cons 'raw tcp-message-registration-reject-res) (cons 'formatted (fmt-hex tcp-message-registration-reject-res))))
        (cons 'tcp-message-registration-refresh-flags-rejected (list (cons 'raw tcp-message-registration-refresh-flags-rejected) (cons 'formatted (if (= tcp-message-registration-refresh-flags-rejected 0) "False" "True"))))
        (cons 'tcp-message-registration-refresh-res (list (cons 'raw tcp-message-registration-refresh-res) (cons 'formatted (fmt-hex tcp-message-registration-refresh-res))))
        (cons 'tcp-message-xtr-id (list (cons 'raw tcp-message-xtr-id) (cons 'formatted (fmt-bytes tcp-message-xtr-id))))
        (cons 'tcp-message-iid (list (cons 'raw tcp-message-iid) (cons 'formatted (number->string tcp-message-iid))))
        (cons 'tcp-message-sid (list (cons 'raw tcp-message-sid) (cons 'formatted (number->string tcp-message-sid))))
        (cons 'tcp-message-site-id (list (cons 'raw tcp-message-site-id) (cons 'formatted (fmt-bytes tcp-message-site-id))))
        (cons 'tcp-message-rloc-ipv4 (list (cons 'raw tcp-message-rloc-ipv4) (cons 'formatted (fmt-ipv4 tcp-message-rloc-ipv4))))
        (cons 'tcp-message-rloc-ipv6 (list (cons 'raw tcp-message-rloc-ipv6) (cons 'formatted (fmt-ipv6-address tcp-message-rloc-ipv6))))
        (cons 'tcp-message-rid (list (cons 'raw tcp-message-rid) (cons 'formatted (number->string tcp-message-rid))))
        )))

    (catch (e)
      (err (str "LISP-TCP parse error: " e)))))

;; dissect-lisp-tcp: parse LISP-TCP from bytevector
;; Returns (ok fields-alist) or (err message)