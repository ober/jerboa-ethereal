;; packet-rohc.c
;; Routines for RObust Header Compression (ROHC) dissection.
;;
;; Copyright 2011, Anders Broman <anders.broman[at]ericsson.com>
;; Per Liedberg  <per.liedberg [at]ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Ref:
;; https://www.ietf.org/rfc/rfc3095             RObust Header Compression (ROHC): Framework and four profiles: RTP, UDP, ESP, and uncompressed
;; https://datatracker.ietf.org/doc/rfc4815/    RObust Header Compression (ROHC): Corrections and Clarifications to RFC 3095
;; https://datatracker.ietf.org/doc/rfc5225/    RObust Header Compression Version 2 (ROHCv2): Profiles for RTP, UDP, IP, ESP and UDP-Lite
;;
;; Only RTP (1) and UDP (2) are currently implemented.
;;

;; jerboa-ethereal/dissectors/rohc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rohc.c
;; RFC 3095

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
(def (dissect-rohc buffer)
  "RObust Header Compression (ROHC)"
  (try
    (let* (
           (padding (unwrap (slice buffer 0 1)))
           (ir-previous-frame (unwrap (read-u32be buffer 0)))
           (ir-pkt-frame (unwrap (read-u32be buffer 0)))
           (small-cid (unwrap (read-u8 buffer 0)))
           (ext-sn (unwrap (read-u24be buffer 0)))
           (add-cid (unwrap (read-u8 buffer 0)))
           (feedback (unwrap (read-u8 buffer 0)))
           (code (unwrap (read-u8 buffer 0)))
           (size (unwrap (read-u8 buffer 0)))
           (ip-id (unwrap (read-u16be buffer 0)))
           (ext (unwrap (slice buffer 10 1)))
           (ext3-r-p (unwrap (read-u8 buffer 20)))
           (profile-spec-octet (unwrap (read-u8 buffer 29)))
           (fb1-sn (unwrap (read-u8 buffer 29)))
           (sn (unwrap (read-u16be buffer 29)))
           (opt-len (unwrap (read-u8 buffer 31)))
           (opt-sn (unwrap (read-u8 buffer 31)))
           (opt-clock (unwrap (read-u8 buffer 31)))
           (opt-jitter (unwrap (read-u8 buffer 31)))
           (opt-loss (unwrap (read-u8 buffer 31)))
           (unknown-option-data (unwrap (slice buffer 31 1)))
           (compressed-list-gp (unwrap (read-u8 buffer 31)))
           (compressed-list-cc (unwrap (read-u8 buffer 31)))
           (compressed-list-res (unwrap (read-u8 buffer 33)))
           (compressed-list-count (unwrap (read-u8 buffer 33)))
           (compressed-list-xi-1 (unwrap (read-u8 buffer 35)))
           (compressed-list-gen-id (unwrap (read-u8 buffer 35)))
           (compressed-list-ref-id (unwrap (read-u8 buffer 35)))
           (compressed-list-mask-size (unwrap (read-u8 buffer 37)))
           (rtp-tos (unwrap (read-u8 buffer 39)))
           (rtp-ttl (unwrap (read-u8 buffer 39)))
           (rtp-id (unwrap (read-u16be buffer 39)))
           (rtp-df (unwrap (read-u8 buffer 41)))
           (rtp-rnd (unwrap (read-u8 buffer 41)))
           (rtp-nbo (unwrap (read-u8 buffer 41)))
           (ipv6-tc (unwrap (read-u8 buffer 41)))
           (ipv6-hop-limit (unwrap (read-u8 buffer 41)))
           (comp-ip-id (unwrap (read-u16be buffer 43)))
           (rtp-v (unwrap (read-u8 buffer 45)))
           (rtp-p (unwrap (read-u8 buffer 45)))
           (rtp-rx (unwrap (read-u8 buffer 45)))
           (rtp-cc (unwrap (read-u8 buffer 45)))
           (rtp-sn (unwrap (read-u16be buffer 45)))
           (rtp-timestamp (unwrap (read-u32be buffer 47)))
           (rtp-x (unwrap (read-u8 buffer 51)))
           (rtp-tis (unwrap (read-u8 buffer 51)))
           (rtp-tss (unwrap (read-u8 buffer 51)))
           (ipv4-src (unwrap (read-u32be buffer 51)))
           (ipv4-dst (unwrap (read-u32be buffer 55)))
           (ipv6-flow (unwrap (read-u24be buffer 59)))
           (ipv6-nxt-hdr (unwrap (read-u8 buffer 62)))
           (ipv6-src (unwrap (slice buffer 62 16)))
           (ipv6-dst (unwrap (slice buffer 78 16)))
           (udp-src-port (unwrap (read-u16be buffer 94)))
           (udp-dst-port (unwrap (read-u16be buffer 96)))
           (rtp-ssrc (unwrap (read-u32be buffer 98)))
           (ir-packet (unwrap (read-u8 buffer 102)))
           (crc (unwrap (read-u8 buffer 102)))
           (ir-dyn-packet (unwrap (read-u8 buffer 102)))
           )

      (ok (list
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'ir-previous-frame (list (cons 'raw ir-previous-frame) (cons 'formatted (number->string ir-previous-frame))))
        (cons 'ir-pkt-frame (list (cons 'raw ir-pkt-frame) (cons 'formatted (number->string ir-pkt-frame))))
        (cons 'small-cid (list (cons 'raw small-cid) (cons 'formatted (number->string small-cid))))
        (cons 'ext-sn (list (cons 'raw ext-sn) (cons 'formatted (fmt-hex ext-sn))))
        (cons 'add-cid (list (cons 'raw add-cid) (cons 'formatted (fmt-hex add-cid))))
        (cons 'feedback (list (cons 'raw feedback) (cons 'formatted (fmt-hex feedback))))
        (cons 'code (list (cons 'raw code) (cons 'formatted (number->string code))))
        (cons 'size (list (cons 'raw size) (cons 'formatted (number->string size))))
        (cons 'ip-id (list (cons 'raw ip-id) (cons 'formatted (fmt-hex ip-id))))
        (cons 'ext (list (cons 'raw ext) (cons 'formatted (utf8->string ext))))
        (cons 'ext3-r-p (list (cons 'raw ext3-r-p) (cons 'formatted (if (= ext3-r-p 0) "False" "True"))))
        (cons 'profile-spec-octet (list (cons 'raw profile-spec-octet) (cons 'formatted (fmt-hex profile-spec-octet))))
        (cons 'fb1-sn (list (cons 'raw fb1-sn) (cons 'formatted (fmt-hex fb1-sn))))
        (cons 'sn (list (cons 'raw sn) (cons 'formatted (fmt-hex sn))))
        (cons 'opt-len (list (cons 'raw opt-len) (cons 'formatted (number->string opt-len))))
        (cons 'opt-sn (list (cons 'raw opt-sn) (cons 'formatted (fmt-hex opt-sn))))
        (cons 'opt-clock (list (cons 'raw opt-clock) (cons 'formatted (number->string opt-clock))))
        (cons 'opt-jitter (list (cons 'raw opt-jitter) (cons 'formatted (number->string opt-jitter))))
        (cons 'opt-loss (list (cons 'raw opt-loss) (cons 'formatted (number->string opt-loss))))
        (cons 'unknown-option-data (list (cons 'raw unknown-option-data) (cons 'formatted (fmt-bytes unknown-option-data))))
        (cons 'compressed-list-gp (list (cons 'raw compressed-list-gp) (cons 'formatted (number->string compressed-list-gp))))
        (cons 'compressed-list-cc (list (cons 'raw compressed-list-cc) (cons 'formatted (number->string compressed-list-cc))))
        (cons 'compressed-list-res (list (cons 'raw compressed-list-res) (cons 'formatted (number->string compressed-list-res))))
        (cons 'compressed-list-count (list (cons 'raw compressed-list-count) (cons 'formatted (number->string compressed-list-count))))
        (cons 'compressed-list-xi-1 (list (cons 'raw compressed-list-xi-1) (cons 'formatted (number->string compressed-list-xi-1))))
        (cons 'compressed-list-gen-id (list (cons 'raw compressed-list-gen-id) (cons 'formatted (number->string compressed-list-gen-id))))
        (cons 'compressed-list-ref-id (list (cons 'raw compressed-list-ref-id) (cons 'formatted (number->string compressed-list-ref-id))))
        (cons 'compressed-list-mask-size (list (cons 'raw compressed-list-mask-size) (cons 'formatted (if (= compressed-list-mask-size 0) "7-bit mask" "15-bit mask"))))
        (cons 'rtp-tos (list (cons 'raw rtp-tos) (cons 'formatted (fmt-hex rtp-tos))))
        (cons 'rtp-ttl (list (cons 'raw rtp-ttl) (cons 'formatted (number->string rtp-ttl))))
        (cons 'rtp-id (list (cons 'raw rtp-id) (cons 'formatted (fmt-hex rtp-id))))
        (cons 'rtp-df (list (cons 'raw rtp-df) (cons 'formatted (number->string rtp-df))))
        (cons 'rtp-rnd (list (cons 'raw rtp-rnd) (cons 'formatted (number->string rtp-rnd))))
        (cons 'rtp-nbo (list (cons 'raw rtp-nbo) (cons 'formatted (number->string rtp-nbo))))
        (cons 'ipv6-tc (list (cons 'raw ipv6-tc) (cons 'formatted (number->string ipv6-tc))))
        (cons 'ipv6-hop-limit (list (cons 'raw ipv6-hop-limit) (cons 'formatted (number->string ipv6-hop-limit))))
        (cons 'comp-ip-id (list (cons 'raw comp-ip-id) (cons 'formatted (fmt-hex comp-ip-id))))
        (cons 'rtp-v (list (cons 'raw rtp-v) (cons 'formatted (number->string rtp-v))))
        (cons 'rtp-p (list (cons 'raw rtp-p) (cons 'formatted (number->string rtp-p))))
        (cons 'rtp-rx (list (cons 'raw rtp-rx) (cons 'formatted (number->string rtp-rx))))
        (cons 'rtp-cc (list (cons 'raw rtp-cc) (cons 'formatted (number->string rtp-cc))))
        (cons 'rtp-sn (list (cons 'raw rtp-sn) (cons 'formatted (number->string rtp-sn))))
        (cons 'rtp-timestamp (list (cons 'raw rtp-timestamp) (cons 'formatted (number->string rtp-timestamp))))
        (cons 'rtp-x (list (cons 'raw rtp-x) (cons 'formatted (if (= rtp-x 0) "False" "True"))))
        (cons 'rtp-tis (list (cons 'raw rtp-tis) (cons 'formatted (number->string rtp-tis))))
        (cons 'rtp-tss (list (cons 'raw rtp-tss) (cons 'formatted (number->string rtp-tss))))
        (cons 'ipv4-src (list (cons 'raw ipv4-src) (cons 'formatted (fmt-ipv4 ipv4-src))))
        (cons 'ipv4-dst (list (cons 'raw ipv4-dst) (cons 'formatted (fmt-ipv4 ipv4-dst))))
        (cons 'ipv6-flow (list (cons 'raw ipv6-flow) (cons 'formatted (number->string ipv6-flow))))
        (cons 'ipv6-nxt-hdr (list (cons 'raw ipv6-nxt-hdr) (cons 'formatted (number->string ipv6-nxt-hdr))))
        (cons 'ipv6-src (list (cons 'raw ipv6-src) (cons 'formatted (fmt-ipv6-address ipv6-src))))
        (cons 'ipv6-dst (list (cons 'raw ipv6-dst) (cons 'formatted (fmt-ipv6-address ipv6-dst))))
        (cons 'udp-src-port (list (cons 'raw udp-src-port) (cons 'formatted (fmt-port udp-src-port))))
        (cons 'udp-dst-port (list (cons 'raw udp-dst-port) (cons 'formatted (fmt-port udp-dst-port))))
        (cons 'rtp-ssrc (list (cons 'raw rtp-ssrc) (cons 'formatted (fmt-hex rtp-ssrc))))
        (cons 'ir-packet (list (cons 'raw ir-packet) (cons 'formatted (fmt-hex ir-packet))))
        (cons 'crc (list (cons 'raw crc) (cons 'formatted (fmt-hex crc))))
        (cons 'ir-dyn-packet (list (cons 'raw ir-dyn-packet) (cons 'formatted (fmt-hex ir-dyn-packet))))
        )))

    (catch (e)
      (err (str "ROHC parse error: " e)))))

;; dissect-rohc: parse ROHC from bytevector
;; Returns (ok fields-alist) or (err message)