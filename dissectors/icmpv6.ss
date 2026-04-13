;; packet-icmpv6.c
;; Routines for ICMPv6 packet disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
;; Copyright 2006, Nicolas DICHTEL - 6WIND - <nicolas.dichtel@6wind.com>
;;
;; HMIPv6 support added by Martti Kuparinen <martti.kuparinen@iki.fi>
;;
;; FMIPv6 support added by Martin Andre <andre@clarinet.u-strasbg.fr>
;;
;; RPL support added by Colin O'Flynn & Owen Kirby.
;;
;; Enhance ICMPv6 dissector by Alexis La Goutte
;;
;; P2P-RPL support added by Cenk Gundogan <cnkgndgn@gmail.com>
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/icmpv6.ss
;; Auto-generated from wireshark/epan/dissectors/packet-icmpv6.c
;; RFC 1885

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
(def (dissect-icmpv6 buffer)
  "Internet Control Message Protocol v6"
  (try
    (let* (
           (mcast-ra-reserved (unwrap (read-u8 buffer 1)))
           (code (unwrap (read-u8 buffer 1)))
           (da-code-prefix (unwrap (read-u8 buffer 1)))
           (da-code-suffix (unwrap (read-u8 buffer 1)))
           (echo-sequence-number (unwrap (read-u16be buffer 6)))
           (nonce (unwrap (slice buffer 8 4)))
           (length (unwrap (read-u8 buffer 12)))
           (mtu (unwrap (read-u32be buffer 28)))
           (pointer (unwrap (read-u32be buffer 32)))
           (mld-mrc (unwrap (read-u16be buffer 36)))
           (mld-flag (unwrap (read-u8 buffer 56)))
           (mld-flag-s (extract-bits mld-flag 0x0 0))
           (mld-flag-qrv (extract-bits mld-flag 0x0 0))
           (mld-flag-rsv (extract-bits mld-flag 0x0 0))
           (mld-qqi (unwrap (read-u8 buffer 57)))
           (mld-nb-sources (unwrap (read-u16be buffer 58)))
           (mld-source-address (unwrap (slice buffer 60 16)))
           (mld-mrd (unwrap (read-u16be buffer 76)))
           (mld-multicast-address (unwrap (slice buffer 80 16)))
           (nd-ra-cur-hop-limit (unwrap (read-u8 buffer 100)))
           (nd-ra-flag (unwrap (read-u8 buffer 101)))
           (nd-ra-flag-m (extract-bits nd-ra-flag 0x0 0))
           (nd-ra-flag-o (extract-bits nd-ra-flag 0x0 0))
           (nd-ra-flag-h (extract-bits nd-ra-flag 0x0 0))
           (nd-ra-flag-p (extract-bits nd-ra-flag 0x0 0))
           (nd-ra-flag-s (extract-bits nd-ra-flag 0x0 0))
           (nd-ra-flag-rsv (extract-bits nd-ra-flag 0x0 0))
           (nd-ra-router-lifetime (unwrap (read-u16be buffer 102)))
           (nd-ra-reachable-time (unwrap (read-u32be buffer 104)))
           (nd-ra-retrans-timer (unwrap (read-u32be buffer 108)))
           (nd-ns-target-address (unwrap (slice buffer 116 16)))
           (nd-na-flag (unwrap (read-u32be buffer 132)))
           (nd-na-flag-r (extract-bits nd-na-flag 0x0 0))
           (nd-na-flag-s (extract-bits nd-na-flag 0x0 0))
           (nd-na-flag-o (extract-bits nd-na-flag 0x0 0))
           (nd-na-flag-rsv (extract-bits nd-na-flag 0x0 0))
           (nd-na-target-address (unwrap (slice buffer 136 16)))
           (nd-rd-target-address (unwrap (slice buffer 156 16)))
           (nd-rd-destination-address (unwrap (slice buffer 172 16)))
           (mip6-home-agent-address (unwrap (slice buffer 200 16)))
           (mip6-identifier (unwrap (read-u16be buffer 220)))
           (mip6-flag (unwrap (read-u16be buffer 222)))
           (mip6-flag-m (extract-bits mip6-flag 0x0 0))
           (mip6-flag-o (extract-bits mip6-flag 0x0 0))
           (mip6-flag-rsv (extract-bits mip6-flag 0x0 0))
           (send-identifier (unwrap (read-u16be buffer 228)))
           (send-all-components (unwrap (read-u16be buffer 230)))
           (send-component (unwrap (read-u16be buffer 232)))
           (fmip6-hi-flag (unwrap (read-u8 buffer 237)))
           (fmip6-hi-flag-s (extract-bits fmip6-hi-flag 0x0 0))
           (fmip6-hi-flag-u (extract-bits fmip6-hi-flag 0x0 0))
           (fmip6-hi-flag-reserved (extract-bits fmip6-hi-flag 0x0 0))
           (fmip6-identifier (unwrap (read-u16be buffer 238)))
           (mcast-ra-query-interval (unwrap (read-u16be buffer 240)))
           (mcast-ra-robustness-variable (unwrap (read-u16be buffer 242)))
           (ilnp-nb-locs (unwrap (read-u8 buffer 244)))
           (reserved (unwrap (slice buffer 245 1)))
           (ilnp-locator (unwrap (read-u64be buffer 248)))
           (ilnp-preference (unwrap (read-u32be buffer 256)))
           (ilnp-lifetime (unwrap (read-u32be buffer 258)))
           (da-rsv (unwrap (read-u8 buffer 261)))
           (da-lifetime (unwrap (read-u16be buffer 262)))
           (da-rovr (unwrap (slice buffer 288 24)))
           (da-raddr (unwrap (slice buffer 352 16)))
           (ext-echo-req-reserved (unwrap (read-u8 buffer 371)))
           (ext-echo-req-local (unwrap (read-u8 buffer 371)))
           (echo-identifier (unwrap (read-u16be buffer 372)))
           (ext-echo-seq-num (unwrap (read-u8 buffer 374)))
           (ext-echo-rsp-reserved (unwrap (read-u8 buffer 375)))
           (ext-echo-rsp-active (unwrap (read-u8 buffer 375)))
           (ext-echo-rsp-ipv4 (unwrap (read-u8 buffer 375)))
           (ext-echo-rsp-ipv6 (unwrap (read-u8 buffer 375)))
           (data (unwrap (slice buffer 376 1)))
           )

      (ok (list
        (cons 'mcast-ra-reserved (list (cons 'raw mcast-ra-reserved) (cons 'formatted (number->string mcast-ra-reserved))))
        (cons 'code (list (cons 'raw code) (cons 'formatted (number->string code))))
        (cons 'da-code-prefix (list (cons 'raw da-code-prefix) (cons 'formatted (number->string da-code-prefix))))
        (cons 'da-code-suffix (list (cons 'raw da-code-suffix) (cons 'formatted (number->string da-code-suffix))))
        (cons 'echo-sequence-number (list (cons 'raw echo-sequence-number) (cons 'formatted (number->string echo-sequence-number))))
        (cons 'nonce (list (cons 'raw nonce) (cons 'formatted (fmt-bytes nonce))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'mtu (list (cons 'raw mtu) (cons 'formatted (number->string mtu))))
        (cons 'pointer (list (cons 'raw pointer) (cons 'formatted (number->string pointer))))
        (cons 'mld-mrc (list (cons 'raw mld-mrc) (cons 'formatted (number->string mld-mrc))))
        (cons 'mld-flag (list (cons 'raw mld-flag) (cons 'formatted (fmt-hex mld-flag))))
        (cons 'mld-flag-s (list (cons 'raw mld-flag-s) (cons 'formatted (if (= mld-flag-s 0) "Not set" "Set"))))
        (cons 'mld-flag-qrv (list (cons 'raw mld-flag-qrv) (cons 'formatted (if (= mld-flag-qrv 0) "Not set" "Set"))))
        (cons 'mld-flag-rsv (list (cons 'raw mld-flag-rsv) (cons 'formatted (if (= mld-flag-rsv 0) "Not set" "Set"))))
        (cons 'mld-qqi (list (cons 'raw mld-qqi) (cons 'formatted (number->string mld-qqi))))
        (cons 'mld-nb-sources (list (cons 'raw mld-nb-sources) (cons 'formatted (number->string mld-nb-sources))))
        (cons 'mld-source-address (list (cons 'raw mld-source-address) (cons 'formatted (fmt-ipv6-address mld-source-address))))
        (cons 'mld-mrd (list (cons 'raw mld-mrd) (cons 'formatted (number->string mld-mrd))))
        (cons 'mld-multicast-address (list (cons 'raw mld-multicast-address) (cons 'formatted (fmt-ipv6-address mld-multicast-address))))
        (cons 'nd-ra-cur-hop-limit (list (cons 'raw nd-ra-cur-hop-limit) (cons 'formatted (number->string nd-ra-cur-hop-limit))))
        (cons 'nd-ra-flag (list (cons 'raw nd-ra-flag) (cons 'formatted (fmt-hex nd-ra-flag))))
        (cons 'nd-ra-flag-m (list (cons 'raw nd-ra-flag-m) (cons 'formatted (if (= nd-ra-flag-m 0) "Not set" "Set"))))
        (cons 'nd-ra-flag-o (list (cons 'raw nd-ra-flag-o) (cons 'formatted (if (= nd-ra-flag-o 0) "Not set" "Set"))))
        (cons 'nd-ra-flag-h (list (cons 'raw nd-ra-flag-h) (cons 'formatted (if (= nd-ra-flag-h 0) "Not set" "Set"))))
        (cons 'nd-ra-flag-p (list (cons 'raw nd-ra-flag-p) (cons 'formatted (if (= nd-ra-flag-p 0) "Not set" "Set"))))
        (cons 'nd-ra-flag-s (list (cons 'raw nd-ra-flag-s) (cons 'formatted (if (= nd-ra-flag-s 0) "Not set" "Set"))))
        (cons 'nd-ra-flag-rsv (list (cons 'raw nd-ra-flag-rsv) (cons 'formatted (if (= nd-ra-flag-rsv 0) "Not set" "Set"))))
        (cons 'nd-ra-router-lifetime (list (cons 'raw nd-ra-router-lifetime) (cons 'formatted (number->string nd-ra-router-lifetime))))
        (cons 'nd-ra-reachable-time (list (cons 'raw nd-ra-reachable-time) (cons 'formatted (number->string nd-ra-reachable-time))))
        (cons 'nd-ra-retrans-timer (list (cons 'raw nd-ra-retrans-timer) (cons 'formatted (number->string nd-ra-retrans-timer))))
        (cons 'nd-ns-target-address (list (cons 'raw nd-ns-target-address) (cons 'formatted (fmt-ipv6-address nd-ns-target-address))))
        (cons 'nd-na-flag (list (cons 'raw nd-na-flag) (cons 'formatted (fmt-hex nd-na-flag))))
        (cons 'nd-na-flag-r (list (cons 'raw nd-na-flag-r) (cons 'formatted (if (= nd-na-flag-r 0) "Not set" "Set"))))
        (cons 'nd-na-flag-s (list (cons 'raw nd-na-flag-s) (cons 'formatted (if (= nd-na-flag-s 0) "Not set" "Set"))))
        (cons 'nd-na-flag-o (list (cons 'raw nd-na-flag-o) (cons 'formatted (if (= nd-na-flag-o 0) "Not set" "Set"))))
        (cons 'nd-na-flag-rsv (list (cons 'raw nd-na-flag-rsv) (cons 'formatted (if (= nd-na-flag-rsv 0) "Not set" "Set"))))
        (cons 'nd-na-target-address (list (cons 'raw nd-na-target-address) (cons 'formatted (fmt-ipv6-address nd-na-target-address))))
        (cons 'nd-rd-target-address (list (cons 'raw nd-rd-target-address) (cons 'formatted (fmt-ipv6-address nd-rd-target-address))))
        (cons 'nd-rd-destination-address (list (cons 'raw nd-rd-destination-address) (cons 'formatted (fmt-ipv6-address nd-rd-destination-address))))
        (cons 'mip6-home-agent-address (list (cons 'raw mip6-home-agent-address) (cons 'formatted (fmt-ipv6-address mip6-home-agent-address))))
        (cons 'mip6-identifier (list (cons 'raw mip6-identifier) (cons 'formatted (number->string mip6-identifier))))
        (cons 'mip6-flag (list (cons 'raw mip6-flag) (cons 'formatted (fmt-hex mip6-flag))))
        (cons 'mip6-flag-m (list (cons 'raw mip6-flag-m) (cons 'formatted (if (= mip6-flag-m 0) "Not set" "Set"))))
        (cons 'mip6-flag-o (list (cons 'raw mip6-flag-o) (cons 'formatted (if (= mip6-flag-o 0) "Not set" "Set"))))
        (cons 'mip6-flag-rsv (list (cons 'raw mip6-flag-rsv) (cons 'formatted (if (= mip6-flag-rsv 0) "Not set" "Set"))))
        (cons 'send-identifier (list (cons 'raw send-identifier) (cons 'formatted (number->string send-identifier))))
        (cons 'send-all-components (list (cons 'raw send-all-components) (cons 'formatted (number->string send-all-components))))
        (cons 'send-component (list (cons 'raw send-component) (cons 'formatted (number->string send-component))))
        (cons 'fmip6-hi-flag (list (cons 'raw fmip6-hi-flag) (cons 'formatted (fmt-hex fmip6-hi-flag))))
        (cons 'fmip6-hi-flag-s (list (cons 'raw fmip6-hi-flag-s) (cons 'formatted (if (= fmip6-hi-flag-s 0) "Not set" "Set"))))
        (cons 'fmip6-hi-flag-u (list (cons 'raw fmip6-hi-flag-u) (cons 'formatted (if (= fmip6-hi-flag-u 0) "Not set" "Set"))))
        (cons 'fmip6-hi-flag-reserved (list (cons 'raw fmip6-hi-flag-reserved) (cons 'formatted (if (= fmip6-hi-flag-reserved 0) "Not set" "Set"))))
        (cons 'fmip6-identifier (list (cons 'raw fmip6-identifier) (cons 'formatted (number->string fmip6-identifier))))
        (cons 'mcast-ra-query-interval (list (cons 'raw mcast-ra-query-interval) (cons 'formatted (number->string mcast-ra-query-interval))))
        (cons 'mcast-ra-robustness-variable (list (cons 'raw mcast-ra-robustness-variable) (cons 'formatted (number->string mcast-ra-robustness-variable))))
        (cons 'ilnp-nb-locs (list (cons 'raw ilnp-nb-locs) (cons 'formatted (number->string ilnp-nb-locs))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'ilnp-locator (list (cons 'raw ilnp-locator) (cons 'formatted (fmt-hex ilnp-locator))))
        (cons 'ilnp-preference (list (cons 'raw ilnp-preference) (cons 'formatted (number->string ilnp-preference))))
        (cons 'ilnp-lifetime (list (cons 'raw ilnp-lifetime) (cons 'formatted (number->string ilnp-lifetime))))
        (cons 'da-rsv (list (cons 'raw da-rsv) (cons 'formatted (number->string da-rsv))))
        (cons 'da-lifetime (list (cons 'raw da-lifetime) (cons 'formatted (number->string da-lifetime))))
        (cons 'da-rovr (list (cons 'raw da-rovr) (cons 'formatted (fmt-bytes da-rovr))))
        (cons 'da-raddr (list (cons 'raw da-raddr) (cons 'formatted (fmt-ipv6-address da-raddr))))
        (cons 'ext-echo-req-reserved (list (cons 'raw ext-echo-req-reserved) (cons 'formatted (fmt-hex ext-echo-req-reserved))))
        (cons 'ext-echo-req-local (list (cons 'raw ext-echo-req-local) (cons 'formatted (if (= ext-echo-req-local 0) "False" "True"))))
        (cons 'echo-identifier (list (cons 'raw echo-identifier) (cons 'formatted (fmt-hex echo-identifier))))
        (cons 'ext-echo-seq-num (list (cons 'raw ext-echo-seq-num) (cons 'formatted (number->string ext-echo-seq-num))))
        (cons 'ext-echo-rsp-reserved (list (cons 'raw ext-echo-rsp-reserved) (cons 'formatted (fmt-hex ext-echo-rsp-reserved))))
        (cons 'ext-echo-rsp-active (list (cons 'raw ext-echo-rsp-active) (cons 'formatted (if (= ext-echo-rsp-active 0) "False" "True"))))
        (cons 'ext-echo-rsp-ipv4 (list (cons 'raw ext-echo-rsp-ipv4) (cons 'formatted (if (= ext-echo-rsp-ipv4 0) "False" "True"))))
        (cons 'ext-echo-rsp-ipv6 (list (cons 'raw ext-echo-rsp-ipv6) (cons 'formatted (if (= ext-echo-rsp-ipv6 0) "False" "True"))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        )))

    (catch (e)
      (err (str "ICMPV6 parse error: " e)))))

;; dissect-icmpv6: parse ICMPV6 from bytevector
;; Returns (ok fields-alist) or (err message)