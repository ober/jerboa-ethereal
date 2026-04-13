;; packet-icmp.c
;; Routines for ICMP - Internet Control Message Protocol
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Monday, June 27, 2005
;; Support for the ICMP extensions for MPLS
;; (https://tools.ietf.org/html/draft-ietf-mpls-icmp-02
;; which has been replaced by rfcs 4884 and 4950)
;; by   Maria-Luiza Crivat <luizacri@gmail.com>
;; &    Brice Augustin <bricecotte@gmail.com>
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Added support for ICMP extensions RFC 4884 and RFC 5837
;; (c) 2011 Gaurav Tungatkar <gstungat@ncsu.edu>
;;

;; jerboa-ethereal/dissectors/icmp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-icmp.c
;; RFC 4884

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
(def (dissect-icmp buffer)
  "Internet Control Message Protocol"
  (try
    (let* (
           (code (unwrap (read-u8 buffer 1)))
           (redir-gw (unwrap (read-u32be buffer 4)))
           (pointer (unwrap (read-u32be buffer 4)))
           (num-addrs (unwrap (read-u8 buffer 4)))
           (unused (unwrap (slice buffer 4 1)))
           (ident-le (unwrap (read-u16be buffer 4)))
           (ident (unwrap (read-u16be buffer 4)))
           (addr-entry-size (unwrap (read-u8 buffer 5)))
           (length-original-datagram (unwrap (read-u8 buffer 5)))
           (length (unwrap (read-u8 buffer 5)))
           (ext-echo-seq-num (unwrap (read-u8 buffer 6)))
           (lifetime (unwrap (read-u16be buffer 6)))
           (mtu (unwrap (read-u16be buffer 6)))
           (seq-num-le (unwrap (read-u16be buffer 6)))
           (seq-num (unwrap (read-u16be buffer 6)))
           (ext-echo-rsp-ipv6 (unwrap (read-u8 buffer 7)))
           (ext-echo-rsp-ipv4 (unwrap (read-u8 buffer 7)))
           (ext-echo-rsp-active (unwrap (read-u8 buffer 7)))
           (ext-echo-rsp-reserved (unwrap (read-u8 buffer 7)))
           (ext-echo-req-local (unwrap (read-u8 buffer 7)))
           (ext-echo-req-reserved (unwrap (read-u8 buffer 7)))
           (address-mask (unwrap (read-u32be buffer 8)))
           (originate-timestamp (unwrap (read-u32be buffer 8)))
           (data (unwrap (slice buffer 8 1)))
           (receive-timestamp (unwrap (read-u32be buffer 12)))
           (transmit-timestamp (unwrap (read-u32be buffer 16)))
           )

      (ok (list
        (cons 'code (list (cons 'raw code) (cons 'formatted (number->string code))))
        (cons 'redir-gw (list (cons 'raw redir-gw) (cons 'formatted (fmt-ipv4 redir-gw))))
        (cons 'pointer (list (cons 'raw pointer) (cons 'formatted (number->string pointer))))
        (cons 'num-addrs (list (cons 'raw num-addrs) (cons 'formatted (number->string num-addrs))))
        (cons 'unused (list (cons 'raw unused) (cons 'formatted (fmt-bytes unused))))
        (cons 'ident-le (list (cons 'raw ident-le) (cons 'formatted (number->string ident-le))))
        (cons 'ident (list (cons 'raw ident) (cons 'formatted (number->string ident))))
        (cons 'addr-entry-size (list (cons 'raw addr-entry-size) (cons 'formatted (number->string addr-entry-size))))
        (cons 'length-original-datagram (list (cons 'raw length-original-datagram) (cons 'formatted (number->string length-original-datagram))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'ext-echo-seq-num (list (cons 'raw ext-echo-seq-num) (cons 'formatted (number->string ext-echo-seq-num))))
        (cons 'lifetime (list (cons 'raw lifetime) (cons 'formatted (number->string lifetime))))
        (cons 'mtu (list (cons 'raw mtu) (cons 'formatted (number->string mtu))))
        (cons 'seq-num-le (list (cons 'raw seq-num-le) (cons 'formatted (number->string seq-num-le))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (number->string seq-num))))
        (cons 'ext-echo-rsp-ipv6 (list (cons 'raw ext-echo-rsp-ipv6) (cons 'formatted (if (= ext-echo-rsp-ipv6 0) "False" "True"))))
        (cons 'ext-echo-rsp-ipv4 (list (cons 'raw ext-echo-rsp-ipv4) (cons 'formatted (if (= ext-echo-rsp-ipv4 0) "False" "True"))))
        (cons 'ext-echo-rsp-active (list (cons 'raw ext-echo-rsp-active) (cons 'formatted (if (= ext-echo-rsp-active 0) "False" "True"))))
        (cons 'ext-echo-rsp-reserved (list (cons 'raw ext-echo-rsp-reserved) (cons 'formatted (fmt-hex ext-echo-rsp-reserved))))
        (cons 'ext-echo-req-local (list (cons 'raw ext-echo-req-local) (cons 'formatted (if (= ext-echo-req-local 0) "False" "True"))))
        (cons 'ext-echo-req-reserved (list (cons 'raw ext-echo-req-reserved) (cons 'formatted (fmt-hex ext-echo-req-reserved))))
        (cons 'address-mask (list (cons 'raw address-mask) (cons 'formatted (fmt-ipv4 address-mask))))
        (cons 'originate-timestamp (list (cons 'raw originate-timestamp) (cons 'formatted (number->string originate-timestamp))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'receive-timestamp (list (cons 'raw receive-timestamp) (cons 'formatted (number->string receive-timestamp))))
        (cons 'transmit-timestamp (list (cons 'raw transmit-timestamp) (cons 'formatted (number->string transmit-timestamp))))
        )))

    (catch (e)
      (err (str "ICMP parse error: " e)))))

;; dissect-icmp: parse ICMP from bytevector
;; Returns (ok fields-alist) or (err message)