;; packet-sap.c
;; Routines for sap packet dissection
;; RFC 2974
;;
;; Heikki Vatiainen <hessu@cs.tut.fi>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-tftp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sap.c
;; RFC 2974

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
(def (dissect-sap buffer)
  "Session Announcement Protocol"
  (try
    (let* (
           (flags-a (unwrap (read-u8 buffer 0)))
           (flags-r (unwrap (read-u8 buffer 0)))
           (flags-t (unwrap (read-u8 buffer 0)))
           (flags-e (unwrap (read-u8 buffer 0)))
           (flags-c (unwrap (read-u8 buffer 0)))
           (auth-len (unwrap (read-u8 buffer 0)))
           (message-identifier-hash (unwrap (read-u16be buffer 0)))
           (originating-source-ipv6 (unwrap (slice buffer 2 16)))
           (originating-source-ipv4 (unwrap (read-u32be buffer 2)))
           (flags (unwrap (read-u8 buffer 2)))
           (flags-p (unwrap (read-u8 buffer 2)))
           (auth-subheader (unwrap (slice buffer 2 1)))
           (payload-type (unwrap (slice buffer 2 1)))
           )

      (ok (list
        (cons 'flags-a (list (cons 'raw flags-a) (cons 'formatted (if (= flags-a 0) "IPv4" "IPv6"))))
        (cons 'flags-r (list (cons 'raw flags-r) (cons 'formatted (if (= flags-r 0) "False" "True"))))
        (cons 'flags-t (list (cons 'raw flags-t) (cons 'formatted (if (= flags-t 0) "Announcement" "Deletion"))))
        (cons 'flags-e (list (cons 'raw flags-e) (cons 'formatted (if (= flags-e 0) "Payload not encrypted" "Payload encrypted"))))
        (cons 'flags-c (list (cons 'raw flags-c) (cons 'formatted (if (= flags-c 0) "Payload not compressed" "Payload compressed"))))
        (cons 'auth-len (list (cons 'raw auth-len) (cons 'formatted (number->string auth-len))))
        (cons 'message-identifier-hash (list (cons 'raw message-identifier-hash) (cons 'formatted (fmt-hex message-identifier-hash))))
        (cons 'originating-source-ipv6 (list (cons 'raw originating-source-ipv6) (cons 'formatted (fmt-ipv6-address originating-source-ipv6))))
        (cons 'originating-source-ipv4 (list (cons 'raw originating-source-ipv4) (cons 'formatted (fmt-ipv4 originating-source-ipv4))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-p (list (cons 'raw flags-p) (cons 'formatted (if (= flags-p 0) "No padding required for the authentication subheader" "Authentication subheader padded to 32 bits"))))
        (cons 'auth-subheader (list (cons 'raw auth-subheader) (cons 'formatted (fmt-bytes auth-subheader))))
        (cons 'payload-type (list (cons 'raw payload-type) (cons 'formatted (utf8->string payload-type))))
        )))

    (catch (e)
      (err (str "SAP parse error: " e)))))

;; dissect-sap: parse SAP from bytevector
;; Returns (ok fields-alist) or (err message)