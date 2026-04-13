;; packet-nat-pmp.c
;; Routines for NAT Port Mapping Protocol packet disassembly.
;; RFC 6886
;;
;; Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
;;
;; Routines for Port Control Protocol packet disassembly
;; (backwards compatible with NAT Port Mapping protocol)
;; RFC6887: Port Control Protocol (PCP) https://tools.ietf.org/html/rfc6887
;;
;; Copyright 2012, Michael Mann
;;
;; Description Option for the Port Control Protocol
;; RFC 7220
;; Discovering NAT64 IPv6 Prefixes Using the Port Control Protocol (PCP)
;; RFC 7225
;;
;; Alexis La Goutte
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nat-pmp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nat_pmp.c
;; RFC 6886

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
(def (dissect-nat-pmp buffer)
  "NAT Port Mapping Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (r (unwrap (read-u8 buffer 0)))
           (hf-request (unwrap (read-u8 buffer 0)))
           (hf-reserved2 (unwrap (read-u16be buffer 0)))
           (ip (unwrap (slice buffer 6 16)))
           (hf-reserved (unwrap (read-u16be buffer 10)))
           (port-requested (unwrap (read-u16be buffer 14)))
           (hf-rpmlis (unwrap (read-u32be buffer 16)))
           (hf-sssoe (unwrap (read-u32be buffer 22)))
           (hf-response (unwrap (read-u8 buffer 22)))
           (hf-reserved1 (unwrap (read-u8 buffer 22)))
           (lifetime (unwrap (read-u32be buffer 22)))
           (port (unwrap (read-u16be buffer 26)))
           (time (unwrap (read-u32be buffer 26)))
           (port-mapped (unwrap (read-u16be buffer 28)))
           (hf-pmlis (unwrap (read-u32be buffer 30)))
           (hf-reserved12 (unwrap (slice buffer 30 12)))
           (reserved1 (unwrap (read-u24be buffer 54)))
           (nonce (unwrap (slice buffer 95 12)))
           (protocol (unwrap (read-u8 buffer 107)))
           (internal-port (unwrap (read-u16be buffer 110)))
           (req-sug-external-port (unwrap (read-u16be buffer 112)))
           (req-sug-ext-ip (unwrap (slice buffer 114 16)))
           (rsp-assigned-external-port (unwrap (read-u16be buffer 130)))
           (rsp-assigned-ext-ip (unwrap (slice buffer 132 16)))
           (remote-peer-port (unwrap (read-u16be buffer 148)))
           (remote-peer-ip (unwrap (slice buffer 152 16)))
           (reserved (unwrap (read-u8 buffer 168)))
           (length (unwrap (read-u16be buffer 168)))
           (third-party-internal-ip (unwrap (slice buffer 170 16)))
           (filter-reserved (unwrap (read-u8 buffer 170)))
           (filter-prefix-length (unwrap (read-u8 buffer 170)))
           (filter-remote-peer-port (unwrap (read-u16be buffer 170)))
           (filter-remote-peer-ip (unwrap (slice buffer 170 16)))
           (description (unwrap (slice buffer 170 1)))
           (p64-length (unwrap (read-u16be buffer 170)))
           (p64-prefix64 (unwrap (slice buffer 172 1)))
           (p64-suffix (unwrap (slice buffer 172 12)))
           (p64-ipv4-prefix-count (unwrap (read-u16be buffer 184)))
           (p64-ipv4-prefix-length (unwrap (read-u16be buffer 186)))
           (p64-ipv4-address (unwrap (read-u32be buffer 188)))
           (portset-size (unwrap (read-u16be buffer 192)))
           (portset-first-suggested-port (unwrap (read-u16be buffer 192)))
           (portset-first-assigned-port (unwrap (read-u16be buffer 192)))
           (portset-reserved (unwrap (read-u8 buffer 192)))
           (portset-parity (unwrap (read-u8 buffer 192)))
           (padding (unwrap (slice buffer 192 1)))
           (hf-version (unwrap (read-u8 buffer 194)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'r (list (cons 'raw r) (cons 'formatted (if (= r 0) "False" "True"))))
        (cons 'hf-request (list (cons 'raw hf-request) (cons 'formatted (number->string hf-request))))
        (cons 'hf-reserved2 (list (cons 'raw hf-reserved2) (cons 'formatted (number->string hf-reserved2))))
        (cons 'ip (list (cons 'raw ip) (cons 'formatted (fmt-ipv6-address ip))))
        (cons 'hf-reserved (list (cons 'raw hf-reserved) (cons 'formatted (number->string hf-reserved))))
        (cons 'port-requested (list (cons 'raw port-requested) (cons 'formatted (number->string port-requested))))
        (cons 'hf-rpmlis (list (cons 'raw hf-rpmlis) (cons 'formatted (number->string hf-rpmlis))))
        (cons 'hf-sssoe (list (cons 'raw hf-sssoe) (cons 'formatted (number->string hf-sssoe))))
        (cons 'hf-response (list (cons 'raw hf-response) (cons 'formatted (number->string hf-response))))
        (cons 'hf-reserved1 (list (cons 'raw hf-reserved1) (cons 'formatted (number->string hf-reserved1))))
        (cons 'lifetime (list (cons 'raw lifetime) (cons 'formatted (number->string lifetime))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'time (list (cons 'raw time) (cons 'formatted (number->string time))))
        (cons 'port-mapped (list (cons 'raw port-mapped) (cons 'formatted (number->string port-mapped))))
        (cons 'hf-pmlis (list (cons 'raw hf-pmlis) (cons 'formatted (number->string hf-pmlis))))
        (cons 'hf-reserved12 (list (cons 'raw hf-reserved12) (cons 'formatted (fmt-bytes hf-reserved12))))
        (cons 'reserved1 (list (cons 'raw reserved1) (cons 'formatted (number->string reserved1))))
        (cons 'nonce (list (cons 'raw nonce) (cons 'formatted (fmt-bytes nonce))))
        (cons 'protocol (list (cons 'raw protocol) (cons 'formatted (number->string protocol))))
        (cons 'internal-port (list (cons 'raw internal-port) (cons 'formatted (number->string internal-port))))
        (cons 'req-sug-external-port (list (cons 'raw req-sug-external-port) (cons 'formatted (number->string req-sug-external-port))))
        (cons 'req-sug-ext-ip (list (cons 'raw req-sug-ext-ip) (cons 'formatted (fmt-ipv6-address req-sug-ext-ip))))
        (cons 'rsp-assigned-external-port (list (cons 'raw rsp-assigned-external-port) (cons 'formatted (number->string rsp-assigned-external-port))))
        (cons 'rsp-assigned-ext-ip (list (cons 'raw rsp-assigned-ext-ip) (cons 'formatted (fmt-ipv6-address rsp-assigned-ext-ip))))
        (cons 'remote-peer-port (list (cons 'raw remote-peer-port) (cons 'formatted (number->string remote-peer-port))))
        (cons 'remote-peer-ip (list (cons 'raw remote-peer-ip) (cons 'formatted (fmt-ipv6-address remote-peer-ip))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'third-party-internal-ip (list (cons 'raw third-party-internal-ip) (cons 'formatted (fmt-ipv6-address third-party-internal-ip))))
        (cons 'filter-reserved (list (cons 'raw filter-reserved) (cons 'formatted (number->string filter-reserved))))
        (cons 'filter-prefix-length (list (cons 'raw filter-prefix-length) (cons 'formatted (number->string filter-prefix-length))))
        (cons 'filter-remote-peer-port (list (cons 'raw filter-remote-peer-port) (cons 'formatted (number->string filter-remote-peer-port))))
        (cons 'filter-remote-peer-ip (list (cons 'raw filter-remote-peer-ip) (cons 'formatted (fmt-ipv6-address filter-remote-peer-ip))))
        (cons 'description (list (cons 'raw description) (cons 'formatted (utf8->string description))))
        (cons 'p64-length (list (cons 'raw p64-length) (cons 'formatted (number->string p64-length))))
        (cons 'p64-prefix64 (list (cons 'raw p64-prefix64) (cons 'formatted (fmt-bytes p64-prefix64))))
        (cons 'p64-suffix (list (cons 'raw p64-suffix) (cons 'formatted (fmt-bytes p64-suffix))))
        (cons 'p64-ipv4-prefix-count (list (cons 'raw p64-ipv4-prefix-count) (cons 'formatted (number->string p64-ipv4-prefix-count))))
        (cons 'p64-ipv4-prefix-length (list (cons 'raw p64-ipv4-prefix-length) (cons 'formatted (number->string p64-ipv4-prefix-length))))
        (cons 'p64-ipv4-address (list (cons 'raw p64-ipv4-address) (cons 'formatted (fmt-ipv4 p64-ipv4-address))))
        (cons 'portset-size (list (cons 'raw portset-size) (cons 'formatted (number->string portset-size))))
        (cons 'portset-first-suggested-port (list (cons 'raw portset-first-suggested-port) (cons 'formatted (number->string portset-first-suggested-port))))
        (cons 'portset-first-assigned-port (list (cons 'raw portset-first-assigned-port) (cons 'formatted (number->string portset-first-assigned-port))))
        (cons 'portset-reserved (list (cons 'raw portset-reserved) (cons 'formatted (fmt-hex portset-reserved))))
        (cons 'portset-parity (list (cons 'raw portset-parity) (cons 'formatted (number->string portset-parity))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        )))

    (catch (e)
      (err (str "NAT-PMP parse error: " e)))))

;; dissect-nat-pmp: parse NAT-PMP from bytevector
;; Returns (ok fields-alist) or (err message)