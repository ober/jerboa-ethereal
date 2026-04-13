;; packet-stun.c
;; Routines for Session Traversal Utilities for NAT (STUN) dissection
;; Copyright 2003, Shiang-Ming Huang <smhuang@pcs.csie.nctu.edu.tw>
;; Copyright 2006, Marc Petit-Huguenin <marc@petit-huguenin.org>
;; Copyright 2007-2008, 8x8 Inc. <petithug@8x8.com>
;; Copyright 2008, Gael Breard <gael@breard.org>
;; Copyright 2013, Media5 Corporation, David Bergeron <dbergeron@media5corp.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Please refer to the following specs for protocol detail:
;; - RFC 3489 (Addition of deprecated attributes for diagnostics purpose)
;; STUN - Simple Traversal of User Datagram Protocol (UDP)
;; Through Network Address Translators (NATs) (superseded by RFC 5389)
;; - RFC 5389, formerly draft-ietf-behave-rfc3489bis-18
;; Session Traversal Utilities for NAT (STUN) (superseded by RFC 8489)
;; - RFC 8489  Session Traversal Utilities for NAT (STUN)
;; - RFC 5780, formerly draft-ietf-behave-nat-behavior-discovery-08
;; NAT Behavior Discovery Using Session Traversal Utilities for NAT (STUN)
;; - RFC 5766, formerly draft-ietf-behave-turn-16
;; Traversal Using Relays around NAT (TURN) (superseded by RFC 8656)
;; - RFC 8656  Traversal Using Relays around NAT (TURN)
;; - RFC 6062  Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
;; - RFC 6156, formerly draft-ietf-behave-turn-ipv6-11
;; Traversal Using Relays around NAT (TURN) Extension for IPv6
;; - RFC 5245, formerly draft-ietf-mmusic-ice-19
;; Interactive Connectivity Establishment (ICE)
;; - RFC 6544  TCP Candidates with Interactive Connectivity Establishment (ICE)
;;
;; Iana registered values:
;; https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml
;;
;; From MS
;; MS-TURN: Traversal Using Relay NAT (TURN) Extensions https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-turn
;; MS-TURNBWM:  Traversal using Relay NAT (TURN) Bandwidth Management Extensions https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-turnbwm
;; MS-ICE: Interactive Connectivity Establishment (ICE) Extensions https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-ice
;; MS-ICE2:  Interactive Connectivity Establishment ICE Extensions 2.0 https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-ice2
;; MS-ICE2BWN: Interactive Connectivity Establishment (ICE) 2.0 Bandwidth Management Extensions https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-ice2bwm
;;

;; jerboa-ethereal/dissectors/stun.ss
;; Auto-generated from wireshark/epan/dissectors/packet-stun.c
;; RFC 3489

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
(def (dissect-stun buffer)
  "Session Traversal Utilities for NAT"
  (try
    (let* (
           (duplicate (unwrap (read-u32be buffer 0)))
           (tcp-frame-length (unwrap (read-u16be buffer 0)))
           (type (unwrap (read-u16be buffer 2)))
           (type-class (unwrap (read-u16be buffer 2)))
           (type-method (unwrap (read-u16be buffer 2)))
           (length (unwrap (read-u16be buffer 4)))
           (cookie (unwrap (slice buffer 6 4)))
           (id (unwrap (slice buffer 10 12)))
           (attr (unwrap (read-u16be buffer 22)))
           (att-type (unwrap (read-u16be buffer 22)))
           (att-length (unwrap (read-u16be buffer 22)))
           (att-reserved (unwrap (slice buffer 26 1)))
           (att-port (unwrap (read-u16be buffer 26)))
           (att-ipv4 (unwrap (read-u32be buffer 26)))
           (att-ipv6 (unwrap (slice buffer 26 16)))
           (att-password (unwrap (slice buffer 26 1)))
           (att-change-ip (unwrap (read-u8 buffer 26)))
           (att-change-port (unwrap (read-u8 buffer 26)))
           (att-username (unwrap (slice buffer 26 1)))
           (att-username-opaque (unwrap (slice buffer 26 1)))
           (att-hmac (unwrap (slice buffer 26 1)))
           (att-error-class (unwrap (read-u8 buffer 26)))
           (att-error-number (unwrap (read-u8 buffer 26)))
           (att-error-reason (unwrap (slice buffer 26 1)))
           (att-unknown (unwrap (read-u16be buffer 26)))
           (att-realm (unwrap (slice buffer 26 1)))
           (att-nonce (unwrap (slice buffer 26 1)))
           (att-xor-port (unwrap (slice buffer 26 2)))
           (att-xor-ipv4 (unwrap (slice buffer 26 4)))
           (att-xor-ipv6 (unwrap (slice buffer 26 16)))
           (att-token (unwrap (slice buffer 26 8)))
           (att-priority (unwrap (read-u32be buffer 26)))
           (att-padding (unwrap (read-u16be buffer 26)))
           (att-icmp-type (unwrap (read-u8 buffer 26)))
           (att-icmp-code (unwrap (read-u8 buffer 26)))
           (att-ms-turn-unknown-8006 (unwrap (slice buffer 26 1)))
           (att-software (unwrap (slice buffer 26 1)))
           (att-cache-timeout (unwrap (read-u32be buffer 26)))
           (att-tie-breaker (unwrap (slice buffer 26 8)))
           (att-value (unwrap (slice buffer 26 1)))
           (att-channelnum (unwrap (read-u16be buffer 26)))
           (att-magic-cookie (unwrap (read-u32be buffer 26)))
           (att-bandwidth (unwrap (read-u32be buffer 26)))
           (att-lifetime (unwrap (read-u32be buffer 26)))
           (att-ms-connection-id (unwrap (slice buffer 26 20)))
           (att-ms-sequence-number (unwrap (read-u32be buffer 26)))
           (att-bandwidth-rsv-id (unwrap (slice buffer 26 16)))
           (att-bandwidth-rsv-amount-masb (unwrap (read-u32be buffer 26)))
           (att-bandwidth-rsv-amount-misb (unwrap (read-u32be buffer 26)))
           (att-bandwidth-rsv-amount-marb (unwrap (read-u32be buffer 26)))
           (att-bandwidth-rsv-amount-mirb (unwrap (read-u32be buffer 26)))
           (att-address-rp-a (unwrap (read-u8 buffer 26)))
           (att-address-rp-b (unwrap (read-u8 buffer 26)))
           (att-address-rp-rsv1 (unwrap (read-u32be buffer 26)))
           (att-address-rp-masb (unwrap (read-u32be buffer 26)))
           (att-address-rp-marb (unwrap (read-u32be buffer 26)))
           (att-address-rp-rsv2 (unwrap (read-u32be buffer 26)))
           (att-sip-dialog-id (unwrap (slice buffer 26 1)))
           (att-sip-call-id (unwrap (slice buffer 26 1)))
           (att-ms-foundation (unwrap (slice buffer 26 4)))
           (att-ms-multiplexed-turn-session-id (unwrap (read-u64be buffer 26)))
           (att-google-network-id (unwrap (read-u16be buffer 26)))
           )

      (ok (list
        (cons 'duplicate (list (cons 'raw duplicate) (cons 'formatted (number->string duplicate))))
        (cons 'tcp-frame-length (list (cons 'raw tcp-frame-length) (cons 'formatted (number->string tcp-frame-length))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (fmt-hex type))))
        (cons 'type-class (list (cons 'raw type-class) (cons 'formatted (fmt-hex type-class))))
        (cons 'type-method (list (cons 'raw type-method) (cons 'formatted (fmt-hex type-method))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'cookie (list (cons 'raw cookie) (cons 'formatted (fmt-bytes cookie))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-bytes id))))
        (cons 'attr (list (cons 'raw attr) (cons 'formatted (fmt-hex attr))))
        (cons 'att-type (list (cons 'raw att-type) (cons 'formatted (fmt-hex att-type))))
        (cons 'att-length (list (cons 'raw att-length) (cons 'formatted (number->string att-length))))
        (cons 'att-reserved (list (cons 'raw att-reserved) (cons 'formatted (fmt-bytes att-reserved))))
        (cons 'att-port (list (cons 'raw att-port) (cons 'formatted (number->string att-port))))
        (cons 'att-ipv4 (list (cons 'raw att-ipv4) (cons 'formatted (fmt-ipv4 att-ipv4))))
        (cons 'att-ipv6 (list (cons 'raw att-ipv6) (cons 'formatted (fmt-ipv6-address att-ipv6))))
        (cons 'att-password (list (cons 'raw att-password) (cons 'formatted (fmt-bytes att-password))))
        (cons 'att-change-ip (list (cons 'raw att-change-ip) (cons 'formatted (if (= att-change-ip 0) "False" "True"))))
        (cons 'att-change-port (list (cons 'raw att-change-port) (cons 'formatted (if (= att-change-port 0) "False" "True"))))
        (cons 'att-username (list (cons 'raw att-username) (cons 'formatted (utf8->string att-username))))
        (cons 'att-username-opaque (list (cons 'raw att-username-opaque) (cons 'formatted (fmt-bytes att-username-opaque))))
        (cons 'att-hmac (list (cons 'raw att-hmac) (cons 'formatted (fmt-bytes att-hmac))))
        (cons 'att-error-class (list (cons 'raw att-error-class) (cons 'formatted (number->string att-error-class))))
        (cons 'att-error-number (list (cons 'raw att-error-number) (cons 'formatted (number->string att-error-number))))
        (cons 'att-error-reason (list (cons 'raw att-error-reason) (cons 'formatted (utf8->string att-error-reason))))
        (cons 'att-unknown (list (cons 'raw att-unknown) (cons 'formatted (fmt-hex att-unknown))))
        (cons 'att-realm (list (cons 'raw att-realm) (cons 'formatted (utf8->string att-realm))))
        (cons 'att-nonce (list (cons 'raw att-nonce) (cons 'formatted (utf8->string att-nonce))))
        (cons 'att-xor-port (list (cons 'raw att-xor-port) (cons 'formatted (fmt-bytes att-xor-port))))
        (cons 'att-xor-ipv4 (list (cons 'raw att-xor-ipv4) (cons 'formatted (fmt-bytes att-xor-ipv4))))
        (cons 'att-xor-ipv6 (list (cons 'raw att-xor-ipv6) (cons 'formatted (fmt-bytes att-xor-ipv6))))
        (cons 'att-token (list (cons 'raw att-token) (cons 'formatted (fmt-bytes att-token))))
        (cons 'att-priority (list (cons 'raw att-priority) (cons 'formatted (number->string att-priority))))
        (cons 'att-padding (list (cons 'raw att-padding) (cons 'formatted (number->string att-padding))))
        (cons 'att-icmp-type (list (cons 'raw att-icmp-type) (cons 'formatted (number->string att-icmp-type))))
        (cons 'att-icmp-code (list (cons 'raw att-icmp-code) (cons 'formatted (number->string att-icmp-code))))
        (cons 'att-ms-turn-unknown-8006 (list (cons 'raw att-ms-turn-unknown-8006) (cons 'formatted (fmt-bytes att-ms-turn-unknown-8006))))
        (cons 'att-software (list (cons 'raw att-software) (cons 'formatted (utf8->string att-software))))
        (cons 'att-cache-timeout (list (cons 'raw att-cache-timeout) (cons 'formatted (number->string att-cache-timeout))))
        (cons 'att-tie-breaker (list (cons 'raw att-tie-breaker) (cons 'formatted (fmt-bytes att-tie-breaker))))
        (cons 'att-value (list (cons 'raw att-value) (cons 'formatted (fmt-bytes att-value))))
        (cons 'att-channelnum (list (cons 'raw att-channelnum) (cons 'formatted (fmt-hex att-channelnum))))
        (cons 'att-magic-cookie (list (cons 'raw att-magic-cookie) (cons 'formatted (fmt-hex att-magic-cookie))))
        (cons 'att-bandwidth (list (cons 'raw att-bandwidth) (cons 'formatted (number->string att-bandwidth))))
        (cons 'att-lifetime (list (cons 'raw att-lifetime) (cons 'formatted (number->string att-lifetime))))
        (cons 'att-ms-connection-id (list (cons 'raw att-ms-connection-id) (cons 'formatted (fmt-bytes att-ms-connection-id))))
        (cons 'att-ms-sequence-number (list (cons 'raw att-ms-sequence-number) (cons 'formatted (number->string att-ms-sequence-number))))
        (cons 'att-bandwidth-rsv-id (list (cons 'raw att-bandwidth-rsv-id) (cons 'formatted (fmt-bytes att-bandwidth-rsv-id))))
        (cons 'att-bandwidth-rsv-amount-masb (list (cons 'raw att-bandwidth-rsv-amount-masb) (cons 'formatted (number->string att-bandwidth-rsv-amount-masb))))
        (cons 'att-bandwidth-rsv-amount-misb (list (cons 'raw att-bandwidth-rsv-amount-misb) (cons 'formatted (number->string att-bandwidth-rsv-amount-misb))))
        (cons 'att-bandwidth-rsv-amount-marb (list (cons 'raw att-bandwidth-rsv-amount-marb) (cons 'formatted (number->string att-bandwidth-rsv-amount-marb))))
        (cons 'att-bandwidth-rsv-amount-mirb (list (cons 'raw att-bandwidth-rsv-amount-mirb) (cons 'formatted (number->string att-bandwidth-rsv-amount-mirb))))
        (cons 'att-address-rp-a (list (cons 'raw att-address-rp-a) (cons 'formatted (if (= att-address-rp-a 0) "False" "True"))))
        (cons 'att-address-rp-b (list (cons 'raw att-address-rp-b) (cons 'formatted (if (= att-address-rp-b 0) "False" "True"))))
        (cons 'att-address-rp-rsv1 (list (cons 'raw att-address-rp-rsv1) (cons 'formatted (fmt-hex att-address-rp-rsv1))))
        (cons 'att-address-rp-masb (list (cons 'raw att-address-rp-masb) (cons 'formatted (number->string att-address-rp-masb))))
        (cons 'att-address-rp-marb (list (cons 'raw att-address-rp-marb) (cons 'formatted (number->string att-address-rp-marb))))
        (cons 'att-address-rp-rsv2 (list (cons 'raw att-address-rp-rsv2) (cons 'formatted (fmt-hex att-address-rp-rsv2))))
        (cons 'att-sip-dialog-id (list (cons 'raw att-sip-dialog-id) (cons 'formatted (fmt-bytes att-sip-dialog-id))))
        (cons 'att-sip-call-id (list (cons 'raw att-sip-call-id) (cons 'formatted (fmt-bytes att-sip-call-id))))
        (cons 'att-ms-foundation (list (cons 'raw att-ms-foundation) (cons 'formatted (utf8->string att-ms-foundation))))
        (cons 'att-ms-multiplexed-turn-session-id (list (cons 'raw att-ms-multiplexed-turn-session-id) (cons 'formatted (fmt-hex att-ms-multiplexed-turn-session-id))))
        (cons 'att-google-network-id (list (cons 'raw att-google-network-id) (cons 'formatted (number->string att-google-network-id))))
        )))

    (catch (e)
      (err (str "STUN parse error: " e)))))

;; dissect-stun: parse STUN from bytevector
;; Returns (ok fields-alist) or (err message)