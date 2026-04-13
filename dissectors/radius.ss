;; packet-radius.c
;;
;; Routines for RADIUS packet disassembly
;; Copyright 1999 Johan Feyaerts
;; Changed 03/12/2003 Rui Carmo (http://the.taoofmac.com - added all 3GPP VSAs, some parsing)
;; Changed 07/2005 Luis Ontanon <luis@ontanon.org> - use FreeRADIUS' dictionary
;; Changed 10/2006 Alejandro Vaquero <alejandrovaquero@yahoo.com> - add Conversations support
;; Changed 08/2015 Didier Arenzana <darenzana@yahoo.fr> - add response authenticator validation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References:
;;
;; RFC 2865 - Remote Authentication Dial In User Service (RADIUS)
;; RFC 2866 - RADIUS Accounting
;; RFC 2867 - RADIUS Accounting Modifications for Tunnel Protocol Support
;; RFC 2868 - RADIUS Attributes for Tunnel Protocol Support
;; RFC 2869 - RADIUS Extensions
;; RFC 3162 - RADIUS and IPv6
;; RFC 3576 - Dynamic Authorization Extensions to RADIUS
;; RFC 6929 - Remote Authentication Dial-In User Service (RADIUS) Protocol Extensions
;;
;; See also
;;
;; http://www.iana.org/assignments/radius-types
;;
;; and see
;;
;; http://freeradius.org/radiusd/man/dictionary.html
;;
;; for the dictionary file syntax.
;;

;; jerboa-ethereal/dissectors/radius.ss
;; Auto-generated from wireshark/epan/dissectors/packet-radius.c
;; RFC 2865

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
(def (dissect-radius buffer)
  "RADIUS Protocol"
  (try
    (let* (
           (rsp-dup (unwrap (read-u32be buffer 0)))
           (rsp (unwrap (read-u8 buffer 0)))
           (req-dup (unwrap (read-u32be buffer 0)))
           (dup (unwrap (read-u32be buffer 0)))
           (req (unwrap (read-u8 buffer 0)))
           (egress-vlanid (unwrap (read-u32be buffer 0)))
           (egress-vlanid-pad (unwrap (read-u32be buffer 0)))
           (cosine-vpi (unwrap (read-u16be buffer 0)))
           (ascend-data-filter (unwrap (slice buffer 0 1)))
           (login-ip-host (unwrap (read-u32be buffer 0)))
           (framed-ip-address (unwrap (read-u32be buffer 0)))
           (chap-ident (unwrap (read-u8 buffer 0)))
           (chap-password (unwrap (slice buffer 0 1)))
           (3gpp-ms-tmime-zone (unwrap (slice buffer 0 2)))
           (id (unwrap (read-u8 buffer 1)))
           (egress-vlan-name (unwrap (slice buffer 1 1)))
           (chap-string (unwrap (slice buffer 1 16)))
           (length (unwrap (read-u16be buffer 2)))
           (cosine-vci (unwrap (read-u16be buffer 2)))
           (avp (unwrap (slice buffer 2 1)))
           (ascend-data-filter-spare (unwrap (read-u8 buffer 3)))
           (authenticator-invalid (unwrap (read-u8 buffer 4)))
           (authenticator-valid (unwrap (read-u8 buffer 4)))
           (authenticator (unwrap (slice buffer 4 1)))
           (ascend-data-filter-src-ipv6 (unwrap (slice buffer 4 16)))
           (ascend-data-filter-dst-ipv6 (unwrap (slice buffer 20 16)))
           (vsa-fragment (unwrap (slice buffer 26 1)))
           (eap-fragment (unwrap (slice buffer 26 1)))
           (message-authenticator-valid (unwrap (read-u8 buffer 26)))
           (message-authenticator-invalid (unwrap (read-u8 buffer 26)))
           (ascend-data-filter-src-ipv4 (unwrap (read-u32be buffer 36)))
           (ascend-data-filter-dst-ipv4 (unwrap (read-u32be buffer 40)))
           (ascend-data-filter-src-ip-prefix (unwrap (read-u8 buffer 44)))
           (ascend-data-filter-dst-ip-prefix (unwrap (read-u8 buffer 45)))
           (ascend-data-filter-established (unwrap (read-u8 buffer 47)))
           (ascend-data-filter-src-port (unwrap (read-u16be buffer 48)))
           (ascend-data-filter-dst-port (unwrap (read-u16be buffer 50)))
           (ascend-data-filter-reserved (unwrap (read-u16be buffer 54)))
           )

      (ok (list
        (cons 'rsp-dup (list (cons 'raw rsp-dup) (cons 'formatted (number->string rsp-dup))))
        (cons 'rsp (list (cons 'raw rsp) (cons 'formatted (number->string rsp))))
        (cons 'req-dup (list (cons 'raw req-dup) (cons 'formatted (number->string req-dup))))
        (cons 'dup (list (cons 'raw dup) (cons 'formatted (number->string dup))))
        (cons 'req (list (cons 'raw req) (cons 'formatted (number->string req))))
        (cons 'egress-vlanid (list (cons 'raw egress-vlanid) (cons 'formatted (number->string egress-vlanid))))
        (cons 'egress-vlanid-pad (list (cons 'raw egress-vlanid-pad) (cons 'formatted (fmt-hex egress-vlanid-pad))))
        (cons 'cosine-vpi (list (cons 'raw cosine-vpi) (cons 'formatted (number->string cosine-vpi))))
        (cons 'ascend-data-filter (list (cons 'raw ascend-data-filter) (cons 'formatted (fmt-bytes ascend-data-filter))))
        (cons 'login-ip-host (list (cons 'raw login-ip-host) (cons 'formatted (fmt-ipv4 login-ip-host))))
        (cons 'framed-ip-address (list (cons 'raw framed-ip-address) (cons 'formatted (fmt-ipv4 framed-ip-address))))
        (cons 'chap-ident (list (cons 'raw chap-ident) (cons 'formatted (fmt-hex chap-ident))))
        (cons 'chap-password (list (cons 'raw chap-password) (cons 'formatted (fmt-bytes chap-password))))
        (cons '3gpp-ms-tmime-zone (list (cons 'raw 3gpp-ms-tmime-zone) (cons 'formatted (fmt-bytes 3gpp-ms-tmime-zone))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'egress-vlan-name (list (cons 'raw egress-vlan-name) (cons 'formatted (utf8->string egress-vlan-name))))
        (cons 'chap-string (list (cons 'raw chap-string) (cons 'formatted (fmt-bytes chap-string))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'cosine-vci (list (cons 'raw cosine-vci) (cons 'formatted (number->string cosine-vci))))
        (cons 'avp (list (cons 'raw avp) (cons 'formatted (fmt-bytes avp))))
        (cons 'ascend-data-filter-spare (list (cons 'raw ascend-data-filter-spare) (cons 'formatted (number->string ascend-data-filter-spare))))
        (cons 'authenticator-invalid (list (cons 'raw authenticator-invalid) (cons 'formatted (number->string authenticator-invalid))))
        (cons 'authenticator-valid (list (cons 'raw authenticator-valid) (cons 'formatted (number->string authenticator-valid))))
        (cons 'authenticator (list (cons 'raw authenticator) (cons 'formatted (fmt-bytes authenticator))))
        (cons 'ascend-data-filter-src-ipv6 (list (cons 'raw ascend-data-filter-src-ipv6) (cons 'formatted (fmt-ipv6-address ascend-data-filter-src-ipv6))))
        (cons 'ascend-data-filter-dst-ipv6 (list (cons 'raw ascend-data-filter-dst-ipv6) (cons 'formatted (fmt-ipv6-address ascend-data-filter-dst-ipv6))))
        (cons 'vsa-fragment (list (cons 'raw vsa-fragment) (cons 'formatted (fmt-bytes vsa-fragment))))
        (cons 'eap-fragment (list (cons 'raw eap-fragment) (cons 'formatted (fmt-bytes eap-fragment))))
        (cons 'message-authenticator-valid (list (cons 'raw message-authenticator-valid) (cons 'formatted (number->string message-authenticator-valid))))
        (cons 'message-authenticator-invalid (list (cons 'raw message-authenticator-invalid) (cons 'formatted (number->string message-authenticator-invalid))))
        (cons 'ascend-data-filter-src-ipv4 (list (cons 'raw ascend-data-filter-src-ipv4) (cons 'formatted (fmt-ipv4 ascend-data-filter-src-ipv4))))
        (cons 'ascend-data-filter-dst-ipv4 (list (cons 'raw ascend-data-filter-dst-ipv4) (cons 'formatted (fmt-ipv4 ascend-data-filter-dst-ipv4))))
        (cons 'ascend-data-filter-src-ip-prefix (list (cons 'raw ascend-data-filter-src-ip-prefix) (cons 'formatted (number->string ascend-data-filter-src-ip-prefix))))
        (cons 'ascend-data-filter-dst-ip-prefix (list (cons 'raw ascend-data-filter-dst-ip-prefix) (cons 'formatted (number->string ascend-data-filter-dst-ip-prefix))))
        (cons 'ascend-data-filter-established (list (cons 'raw ascend-data-filter-established) (cons 'formatted (number->string ascend-data-filter-established))))
        (cons 'ascend-data-filter-src-port (list (cons 'raw ascend-data-filter-src-port) (cons 'formatted (number->string ascend-data-filter-src-port))))
        (cons 'ascend-data-filter-dst-port (list (cons 'raw ascend-data-filter-dst-port) (cons 'formatted (number->string ascend-data-filter-dst-port))))
        (cons 'ascend-data-filter-reserved (list (cons 'raw ascend-data-filter-reserved) (cons 'formatted (fmt-hex ascend-data-filter-reserved))))
        )))

    (catch (e)
      (err (str "RADIUS parse error: " e)))))

;; dissect-radius: parse RADIUS from bytevector
;; Returns (ok fields-alist) or (err message)