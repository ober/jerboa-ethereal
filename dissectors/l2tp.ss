;; packet-l2tp.c
;; Routines for Layer Two Tunnelling Protocol (L2TP) packet disassembly
;; John Thomes <john@ensemblecom.com>
;;
;; Minor changes by: (2000-01-10)
;; Laurent Cazalet <laurent.cazalet@mailclub.net>
;; Thomas Parvais <thomas.parvais@advalvas.be>
;;
;; Added RFC 5515 by Uli Heilmeier <uh@heilmeier.eu>, 2016-02-29
;;
;; Ericsson L2TP by Harald Welte <laforge@gnumonks.org>, 2016-07-16
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/l2tp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-l2tp.c
;; RFC 5515

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
(def (dissect-l2tp buffer)
  "Layer 2 Tunneling Protocol"
  (try
    (let* (
           (flags (unwrap (read-u16be buffer 0)))
           (length-bit (extract-bits flags 0x4000 14))
           (seq-bit (extract-bits flags 0x800 11))
           (version (extract-bits flags 0xF 0))
           (sid (unwrap (read-u32be buffer 0)))
           (avp-mandatory (unwrap (read-u8 buffer 0)))
           (avp-hidden (unwrap (read-u8 buffer 0)))
           (avp-length (unwrap (read-u16be buffer 0)))
           (ericsson-tcg-ip (unwrap (read-u32be buffer 0)))
           (res (unwrap (read-u16be buffer 2)))
           (ericsson-tcg-bundling-max-pkt (unwrap (read-u16be buffer 4)))
           (cisco-assigned-control-connection-id (unwrap (read-u32be buffer 6)))
           (broadband-agent-circuit-id (unwrap (slice buffer 6 1)))
           (broadband-agent-remote-id (unwrap (slice buffer 6 1)))
           (broadband-actual-dr-up (unwrap (read-u64be buffer 6)))
           (broadband-actual-dr-down (unwrap (read-u64be buffer 6)))
           (broadband-minimum-dr-up (unwrap (read-u64be buffer 6)))
           (broadband-minimum-dr-down (unwrap (read-u64be buffer 6)))
           (broadband-attainable-dr-up (unwrap (read-u64be buffer 6)))
           (broadband-attainable-dr-down (unwrap (read-u64be buffer 6)))
           (broadband-maximum-dr-up (unwrap (read-u64be buffer 6)))
           (broadband-maximum-dr-down (unwrap (read-u64be buffer 6)))
           (broadband-minimum-dr-up-low-power (unwrap (read-u64be buffer 6)))
           (broadband-minimum-dr-down-low-power (unwrap (read-u64be buffer 6)))
           (broadband-maximum-interleaving-delay-up (unwrap (read-u32be buffer 6)))
           (broadband-actual-interleaving-delay-up (unwrap (read-u32be buffer 6)))
           (broadband-maximum-interleaving-delay-down (unwrap (read-u32be buffer 6)))
           (broadband-actual-interleaving-delay-down (unwrap (read-u32be buffer 6)))
           (ericsson-ver-pref (unwrap (read-u32be buffer 6)))
           (ericsson-ver-2 (unwrap (read-u32be buffer 6)))
           (ericsson-ver-3 (unwrap (read-u32be buffer 6)))
           (ericsson-stn-name (unwrap (slice buffer 6 1)))
           (ericsson-crc32-enable (unwrap (read-u8 buffer 6)))
           (ericsson-tc-overl-thresh (unwrap (read-u16be buffer 6)))
           (ericsson-tc-num-groups (unwrap (read-u8 buffer 6)))
           (cisco-local-session-id (unwrap (read-u32be buffer 8)))
           (cisco-remote-session-id (unwrap (read-u32be buffer 8)))
           (cisco-assigned-cookie (unwrap (slice buffer 8 1)))
           (cisco-remote-end-id (unwrap (slice buffer 8 1)))
           (cisco-circuit-status (unwrap (read-u8 buffer 8)))
           (cisco-circuit-type (unwrap (read-u8 buffer 8)))
           (cisco-tie-breaker (unwrap (read-u64be buffer 8)))
           (cisco-draft-avp-version (unwrap (read-u16be buffer 8)))
           (cisco-message-digest (unwrap (slice buffer 8 1)))
           (cisco-nonce (unwrap (slice buffer 8 1)))
           (cisco-interface-mtu (unwrap (read-u16be buffer 8)))
           (cablel-avp-frequency (unwrap (read-u32be buffer 8)))
           (cablel-avp-l-bit (unwrap (read-u8 buffer 14)))
           (cablel-avp-tsid-group-id (unwrap (read-u16be buffer 14)))
           (cablel-avp-m (unwrap (read-u16be buffer 16)))
           (cablel-avp-n (unwrap (read-u16be buffer 18)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'length-bit (list (cons 'raw length-bit) (cons 'formatted (if (= length-bit 0) "Length field is not present" "Length field is present"))))
        (cons 'seq-bit (list (cons 'raw seq-bit) (cons 'formatted (if (= seq-bit 0) "Ns and Nr fields are not present" "Ns and Nr fields are present"))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (if (= version 0) "Not set" "Set"))))
        (cons 'sid (list (cons 'raw sid) (cons 'formatted (fmt-hex sid))))
        (cons 'avp-mandatory (list (cons 'raw avp-mandatory) (cons 'formatted (number->string avp-mandatory))))
        (cons 'avp-hidden (list (cons 'raw avp-hidden) (cons 'formatted (number->string avp-hidden))))
        (cons 'avp-length (list (cons 'raw avp-length) (cons 'formatted (number->string avp-length))))
        (cons 'ericsson-tcg-ip (list (cons 'raw ericsson-tcg-ip) (cons 'formatted (fmt-ipv4 ericsson-tcg-ip))))
        (cons 'res (list (cons 'raw res) (cons 'formatted (fmt-hex res))))
        (cons 'ericsson-tcg-bundling-max-pkt (list (cons 'raw ericsson-tcg-bundling-max-pkt) (cons 'formatted (number->string ericsson-tcg-bundling-max-pkt))))
        (cons 'cisco-assigned-control-connection-id (list (cons 'raw cisco-assigned-control-connection-id) (cons 'formatted (number->string cisco-assigned-control-connection-id))))
        (cons 'broadband-agent-circuit-id (list (cons 'raw broadband-agent-circuit-id) (cons 'formatted (utf8->string broadband-agent-circuit-id))))
        (cons 'broadband-agent-remote-id (list (cons 'raw broadband-agent-remote-id) (cons 'formatted (utf8->string broadband-agent-remote-id))))
        (cons 'broadband-actual-dr-up (list (cons 'raw broadband-actual-dr-up) (cons 'formatted (number->string broadband-actual-dr-up))))
        (cons 'broadband-actual-dr-down (list (cons 'raw broadband-actual-dr-down) (cons 'formatted (number->string broadband-actual-dr-down))))
        (cons 'broadband-minimum-dr-up (list (cons 'raw broadband-minimum-dr-up) (cons 'formatted (number->string broadband-minimum-dr-up))))
        (cons 'broadband-minimum-dr-down (list (cons 'raw broadband-minimum-dr-down) (cons 'formatted (number->string broadband-minimum-dr-down))))
        (cons 'broadband-attainable-dr-up (list (cons 'raw broadband-attainable-dr-up) (cons 'formatted (number->string broadband-attainable-dr-up))))
        (cons 'broadband-attainable-dr-down (list (cons 'raw broadband-attainable-dr-down) (cons 'formatted (number->string broadband-attainable-dr-down))))
        (cons 'broadband-maximum-dr-up (list (cons 'raw broadband-maximum-dr-up) (cons 'formatted (number->string broadband-maximum-dr-up))))
        (cons 'broadband-maximum-dr-down (list (cons 'raw broadband-maximum-dr-down) (cons 'formatted (number->string broadband-maximum-dr-down))))
        (cons 'broadband-minimum-dr-up-low-power (list (cons 'raw broadband-minimum-dr-up-low-power) (cons 'formatted (number->string broadband-minimum-dr-up-low-power))))
        (cons 'broadband-minimum-dr-down-low-power (list (cons 'raw broadband-minimum-dr-down-low-power) (cons 'formatted (number->string broadband-minimum-dr-down-low-power))))
        (cons 'broadband-maximum-interleaving-delay-up (list (cons 'raw broadband-maximum-interleaving-delay-up) (cons 'formatted (number->string broadband-maximum-interleaving-delay-up))))
        (cons 'broadband-actual-interleaving-delay-up (list (cons 'raw broadband-actual-interleaving-delay-up) (cons 'formatted (number->string broadband-actual-interleaving-delay-up))))
        (cons 'broadband-maximum-interleaving-delay-down (list (cons 'raw broadband-maximum-interleaving-delay-down) (cons 'formatted (number->string broadband-maximum-interleaving-delay-down))))
        (cons 'broadband-actual-interleaving-delay-down (list (cons 'raw broadband-actual-interleaving-delay-down) (cons 'formatted (number->string broadband-actual-interleaving-delay-down))))
        (cons 'ericsson-ver-pref (list (cons 'raw ericsson-ver-pref) (cons 'formatted (number->string ericsson-ver-pref))))
        (cons 'ericsson-ver-2 (list (cons 'raw ericsson-ver-2) (cons 'formatted (number->string ericsson-ver-2))))
        (cons 'ericsson-ver-3 (list (cons 'raw ericsson-ver-3) (cons 'formatted (number->string ericsson-ver-3))))
        (cons 'ericsson-stn-name (list (cons 'raw ericsson-stn-name) (cons 'formatted (utf8->string ericsson-stn-name))))
        (cons 'ericsson-crc32-enable (list (cons 'raw ericsson-crc32-enable) (cons 'formatted (number->string ericsson-crc32-enable))))
        (cons 'ericsson-tc-overl-thresh (list (cons 'raw ericsson-tc-overl-thresh) (cons 'formatted (number->string ericsson-tc-overl-thresh))))
        (cons 'ericsson-tc-num-groups (list (cons 'raw ericsson-tc-num-groups) (cons 'formatted (number->string ericsson-tc-num-groups))))
        (cons 'cisco-local-session-id (list (cons 'raw cisco-local-session-id) (cons 'formatted (number->string cisco-local-session-id))))
        (cons 'cisco-remote-session-id (list (cons 'raw cisco-remote-session-id) (cons 'formatted (number->string cisco-remote-session-id))))
        (cons 'cisco-assigned-cookie (list (cons 'raw cisco-assigned-cookie) (cons 'formatted (fmt-bytes cisco-assigned-cookie))))
        (cons 'cisco-remote-end-id (list (cons 'raw cisco-remote-end-id) (cons 'formatted (utf8->string cisco-remote-end-id))))
        (cons 'cisco-circuit-status (list (cons 'raw cisco-circuit-status) (cons 'formatted (if (= cisco-circuit-status 0) "False" "True"))))
        (cons 'cisco-circuit-type (list (cons 'raw cisco-circuit-type) (cons 'formatted (if (= cisco-circuit-type 0) "Existing" "New"))))
        (cons 'cisco-tie-breaker (list (cons 'raw cisco-tie-breaker) (cons 'formatted (fmt-hex cisco-tie-breaker))))
        (cons 'cisco-draft-avp-version (list (cons 'raw cisco-draft-avp-version) (cons 'formatted (number->string cisco-draft-avp-version))))
        (cons 'cisco-message-digest (list (cons 'raw cisco-message-digest) (cons 'formatted (fmt-bytes cisco-message-digest))))
        (cons 'cisco-nonce (list (cons 'raw cisco-nonce) (cons 'formatted (fmt-bytes cisco-nonce))))
        (cons 'cisco-interface-mtu (list (cons 'raw cisco-interface-mtu) (cons 'formatted (number->string cisco-interface-mtu))))
        (cons 'cablel-avp-frequency (list (cons 'raw cablel-avp-frequency) (cons 'formatted (number->string cablel-avp-frequency))))
        (cons 'cablel-avp-l-bit (list (cons 'raw cablel-avp-l-bit) (cons 'formatted (number->string cablel-avp-l-bit))))
        (cons 'cablel-avp-tsid-group-id (list (cons 'raw cablel-avp-tsid-group-id) (cons 'formatted (number->string cablel-avp-tsid-group-id))))
        (cons 'cablel-avp-m (list (cons 'raw cablel-avp-m) (cons 'formatted (number->string cablel-avp-m))))
        (cons 'cablel-avp-n (list (cons 'raw cablel-avp-n) (cons 'formatted (number->string cablel-avp-n))))
        )))

    (catch (e)
      (err (str "L2TP parse error: " e)))))

;; dissect-l2tp: parse L2TP from bytevector
;; Returns (ok fields-alist) or (err message)