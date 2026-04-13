;; packet-acn.c
;; Routines for ACN packet disassembly
;;
;; Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
;; Copyright (c) 2006 by Electronic Theatre Controls, Inc.
;; Bill Florac <bflorac@etcconnect.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/acn.ss
;; Auto-generated from wireshark/epan/dissectors/packet-acn.c

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
(def (dissect-acn buffer)
  "Architecture for Control Networks"
  (try
    (let* (
           (protocol-id (unwrap (read-u8 buffer 0)))
           (major-version (unwrap (read-u8 buffer 0)))
           (minor-version (unwrap (read-u8 buffer 0)))
           (ept-data-vector-protocol-id (unwrap (read-u16be buffer 2)))
           (broker-client-ept-protocol-protocol-id (unwrap (read-u16be buffer 2)))
           (command-tftp (unwrap (read-u32be buffer 8)))
           (member-id (unwrap (read-u16be buffer 29)))
           (cid (unwrap (slice buffer 31 16)))
           (channel-number (unwrap (read-u16be buffer 47)))
           (command-ip-address (unwrap (read-u32be buffer 48)))
           (reciprocal-channel (unwrap (read-u16be buffer 49)))
           (command-subnet-mask (unwrap (read-u32be buffer 52)))
           (command-gateway (unwrap (read-u32be buffer 56)))
           (expiry (unwrap (read-u16be buffer 56)))
           (nak-outbound-flag (unwrap (read-u8 buffer 57)))
           (nak-holdoff (unwrap (read-u16be buffer 58)))
           (nak-modulus (unwrap (read-u16be buffer 60)))
           (nak-max-wait (unwrap (read-u16be buffer 62)))
           (ipv4 (unwrap (read-u32be buffer 68)))
           (ipv6 (unwrap (slice buffer 75 16)))
           (command-cid (unwrap (slice buffer 76 16)))
           (command-beacon-duration (unwrap (read-u32be buffer 92)))
           (port (unwrap (read-u16be buffer 92)))
           (dmp-adt-x (unwrap (read-u8 buffer 94)))
           (reply-ip-address (unwrap (read-u32be buffer 125)))
           (reply-subnet-mask (unwrap (read-u32be buffer 129)))
           (reply-gateway (unwrap (read-u32be buffer 133)))
           (reply-tftp (unwrap (read-u32be buffer 137)))
           (reply-cid (unwrap (slice buffer 141 16)))
           (reply-dcid (unwrap (slice buffer 157 16)))
           (data (unwrap (slice buffer 165 1)))
           (data16 (unwrap (read-u16be buffer 165)))
           (data24 (unwrap (read-u24be buffer 165)))
           (data32 (unwrap (read-u32be buffer 165)))
           (data8 (unwrap (read-u8 buffer 167)))
           (reply-version (unwrap (slice buffer 175 7)))
           (broker-connect-client-scope (unwrap (slice buffer 491 63)))
           (broker-connect-e133-version (unwrap (read-u16be buffer 554)))
           (broker-connect-search-domain (unwrap (slice buffer 556 231)))
           (broker-connect-connection-flags (unwrap (read-u8 buffer 787)))
           (broker-connect-connection-flags-incremental-updates (unwrap (read-u8 buffer 787)))
           (broker-connect-reply-e133-version (unwrap (read-u16be buffer 790)))
           (broker-client-entry-update-connection-flags (unwrap (read-u8 buffer 792)))
           (broker-client-entry-update-connection-flags-incremental-updates (unwrap (read-u8 buffer 792)))
           (broker-redirect-ipv4-address (unwrap (read-u32be buffer 793)))
           (broker-redirect-ipv4-tcp-port (unwrap (read-u16be buffer 797)))
           (broker-redirect-ipv6-address (unwrap (slice buffer 797 16)))
           (broker-redirect-ipv6-tcp-port (unwrap (read-u16be buffer 813)))
           )

      (ok (list
        (cons 'protocol-id (list (cons 'raw protocol-id) (cons 'formatted (number->string protocol-id))))
        (cons 'major-version (list (cons 'raw major-version) (cons 'formatted (number->string major-version))))
        (cons 'minor-version (list (cons 'raw minor-version) (cons 'formatted (number->string minor-version))))
        (cons 'ept-data-vector-protocol-id (list (cons 'raw ept-data-vector-protocol-id) (cons 'formatted (fmt-hex ept-data-vector-protocol-id))))
        (cons 'broker-client-ept-protocol-protocol-id (list (cons 'raw broker-client-ept-protocol-protocol-id) (cons 'formatted (fmt-hex broker-client-ept-protocol-protocol-id))))
        (cons 'command-tftp (list (cons 'raw command-tftp) (cons 'formatted (fmt-ipv4 command-tftp))))
        (cons 'member-id (list (cons 'raw member-id) (cons 'formatted (number->string member-id))))
        (cons 'cid (list (cons 'raw cid) (cons 'formatted (fmt-bytes cid))))
        (cons 'channel-number (list (cons 'raw channel-number) (cons 'formatted (number->string channel-number))))
        (cons 'command-ip-address (list (cons 'raw command-ip-address) (cons 'formatted (fmt-ipv4 command-ip-address))))
        (cons 'reciprocal-channel (list (cons 'raw reciprocal-channel) (cons 'formatted (number->string reciprocal-channel))))
        (cons 'command-subnet-mask (list (cons 'raw command-subnet-mask) (cons 'formatted (fmt-ipv4 command-subnet-mask))))
        (cons 'command-gateway (list (cons 'raw command-gateway) (cons 'formatted (fmt-ipv4 command-gateway))))
        (cons 'expiry (list (cons 'raw expiry) (cons 'formatted (number->string expiry))))
        (cons 'nak-outbound-flag (list (cons 'raw nak-outbound-flag) (cons 'formatted (number->string nak-outbound-flag))))
        (cons 'nak-holdoff (list (cons 'raw nak-holdoff) (cons 'formatted (number->string nak-holdoff))))
        (cons 'nak-modulus (list (cons 'raw nak-modulus) (cons 'formatted (number->string nak-modulus))))
        (cons 'nak-max-wait (list (cons 'raw nak-max-wait) (cons 'formatted (number->string nak-max-wait))))
        (cons 'ipv4 (list (cons 'raw ipv4) (cons 'formatted (fmt-ipv4 ipv4))))
        (cons 'ipv6 (list (cons 'raw ipv6) (cons 'formatted (fmt-ipv6-address ipv6))))
        (cons 'command-cid (list (cons 'raw command-cid) (cons 'formatted (fmt-bytes command-cid))))
        (cons 'command-beacon-duration (list (cons 'raw command-beacon-duration) (cons 'formatted (number->string command-beacon-duration))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'dmp-adt-x (list (cons 'raw dmp-adt-x) (cons 'formatted (number->string dmp-adt-x))))
        (cons 'reply-ip-address (list (cons 'raw reply-ip-address) (cons 'formatted (fmt-ipv4 reply-ip-address))))
        (cons 'reply-subnet-mask (list (cons 'raw reply-subnet-mask) (cons 'formatted (fmt-ipv4 reply-subnet-mask))))
        (cons 'reply-gateway (list (cons 'raw reply-gateway) (cons 'formatted (fmt-ipv4 reply-gateway))))
        (cons 'reply-tftp (list (cons 'raw reply-tftp) (cons 'formatted (fmt-ipv4 reply-tftp))))
        (cons 'reply-cid (list (cons 'raw reply-cid) (cons 'formatted (fmt-bytes reply-cid))))
        (cons 'reply-dcid (list (cons 'raw reply-dcid) (cons 'formatted (fmt-bytes reply-dcid))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'data16 (list (cons 'raw data16) (cons 'formatted (number->string data16))))
        (cons 'data24 (list (cons 'raw data24) (cons 'formatted (number->string data24))))
        (cons 'data32 (list (cons 'raw data32) (cons 'formatted (number->string data32))))
        (cons 'data8 (list (cons 'raw data8) (cons 'formatted (number->string data8))))
        (cons 'reply-version (list (cons 'raw reply-version) (cons 'formatted (utf8->string reply-version))))
        (cons 'broker-connect-client-scope (list (cons 'raw broker-connect-client-scope) (cons 'formatted (utf8->string broker-connect-client-scope))))
        (cons 'broker-connect-e133-version (list (cons 'raw broker-connect-e133-version) (cons 'formatted (number->string broker-connect-e133-version))))
        (cons 'broker-connect-search-domain (list (cons 'raw broker-connect-search-domain) (cons 'formatted (utf8->string broker-connect-search-domain))))
        (cons 'broker-connect-connection-flags (list (cons 'raw broker-connect-connection-flags) (cons 'formatted (fmt-hex broker-connect-connection-flags))))
        (cons 'broker-connect-connection-flags-incremental-updates (list (cons 'raw broker-connect-connection-flags-incremental-updates) (cons 'formatted (number->string broker-connect-connection-flags-incremental-updates))))
        (cons 'broker-connect-reply-e133-version (list (cons 'raw broker-connect-reply-e133-version) (cons 'formatted (number->string broker-connect-reply-e133-version))))
        (cons 'broker-client-entry-update-connection-flags (list (cons 'raw broker-client-entry-update-connection-flags) (cons 'formatted (fmt-hex broker-client-entry-update-connection-flags))))
        (cons 'broker-client-entry-update-connection-flags-incremental-updates (list (cons 'raw broker-client-entry-update-connection-flags-incremental-updates) (cons 'formatted (number->string broker-client-entry-update-connection-flags-incremental-updates))))
        (cons 'broker-redirect-ipv4-address (list (cons 'raw broker-redirect-ipv4-address) (cons 'formatted (fmt-ipv4 broker-redirect-ipv4-address))))
        (cons 'broker-redirect-ipv4-tcp-port (list (cons 'raw broker-redirect-ipv4-tcp-port) (cons 'formatted (fmt-port broker-redirect-ipv4-tcp-port))))
        (cons 'broker-redirect-ipv6-address (list (cons 'raw broker-redirect-ipv6-address) (cons 'formatted (fmt-ipv6-address broker-redirect-ipv6-address))))
        (cons 'broker-redirect-ipv6-tcp-port (list (cons 'raw broker-redirect-ipv6-tcp-port) (cons 'formatted (fmt-port broker-redirect-ipv6-tcp-port))))
        )))

    (catch (e)
      (err (str "ACN parse error: " e)))))

;; dissect-acn: parse ACN from bytevector
;; Returns (ok fields-alist) or (err message)