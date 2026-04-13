;; packet-nhrp.c
;; Routines for NBMA Next Hop Resolution Protocol
;; RFC 2332 plus Cisco extensions:
;; I-D draft-detienne-dmvpn-01: Flexible Dynamic Mesh VPN
;; others?  (documented where?)
;; plus extensions from:
;; RFC 2520: NHRP with Mobile NHCs
;; RFC 2735: NHRP Support for Virtual Private Networks
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; CIE decoding for extensions and Cisco 12.4T extensions
;; added by Timo Teras <timo.teras@iki.fi>
;;

;; jerboa-ethereal/dissectors/nhrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nhrp.c
;; RFC 2332

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
(def (dissect-nhrp buffer)
  "NBMA Next Hop Resolution Protocol"
  (try
    (let* (
           (src-proto-len (unwrap (read-u16be buffer 0)))
           (dst-proto-len (unwrap (read-u16be buffer 1)))
           (hdr-pro-type (unwrap (read-u16be buffer 2)))
           (hdr-pro-snap-oui (unwrap (read-u24be buffer 4)))
           (hdr-pro-snap-pid (unwrap (read-u16be buffer 7)))
           (protocol-type (unwrap (slice buffer 7 5)))
           (hdr-hopcnt (unwrap (read-u8 buffer 12)))
           (hdr-pktsz (unwrap (read-u16be buffer 13)))
           (flags (unwrap (read-u16be buffer 14)))
           (flag-N (extract-bits flags 0x8000 15))
           (flag-NAT (extract-bits flags 0x2 1))
           (request-id (unwrap (read-u32be buffer 16)))
           (hdr-extoff (unwrap (read-u16be buffer 17)))
           (hdr-version (unwrap (read-u8 buffer 19)))
           (hdr-shtl (unwrap (read-u8 buffer 21)))
           (hdr-shtl-len (unwrap (read-u8 buffer 21)))
           (hdr-sstl (unwrap (read-u8 buffer 22)))
           (hdr-sstl-len (unwrap (read-u8 buffer 22)))
           (prefix-len (unwrap (read-u8 buffer 24)))
           (error-offset (unwrap (read-u16be buffer 24)))
           (unused (unwrap (read-u16be buffer 25)))
           (mtu (unwrap (read-u16be buffer 27)))
           (holding-time (unwrap (read-u16be buffer 29)))
           (cli-addr-tl (unwrap (read-u8 buffer 31)))
           (cli-addr-tl-len (unwrap (read-u8 buffer 31)))
           (cli-saddr-tl (unwrap (read-u8 buffer 32)))
           (cli-saddr-tl-len (unwrap (read-u8 buffer 32)))
           (cli-prot-len (unwrap (read-u8 buffer 33)))
           (pref (unwrap (read-u8 buffer 34)))
           (client-nbma-addr (unwrap (read-u32be buffer 35)))
           (client-nbma-address-bytes (unwrap (slice buffer 35 1)))
           (client-nbma-addr-v6 (unwrap (slice buffer 35 16)))
           (client-nbma-saddr (unwrap (slice buffer 35 1)))
           (client-prot-addr (unwrap (read-u32be buffer 35)))
           (client-prot-addr-v6 (unwrap (slice buffer 35 16)))
           (client-prot-addr-bytes (unwrap (slice buffer 35 1)))
           (src-nbma-addr (unwrap (read-u32be buffer 38)))
           (src-nbma-addr-bytes (unwrap (slice buffer 38 1)))
           (src-nbma-addr-v6 (unwrap (slice buffer 38 16)))
           (src-nbma-saddr (unwrap (slice buffer 38 1)))
           (src-prot-addr (unwrap (read-u32be buffer 38)))
           (dst-prot-addr (unwrap (read-u32be buffer 58)))
           (dst-prot-addr-v6 (unwrap (slice buffer 62 16)))
           (dst-prot-addr-bytes (unwrap (slice buffer 78 1)))
           (ext-C (unwrap (read-u8 buffer 78)))
           (ext-len (unwrap (read-u16be buffer 80)))
           (devcap-ext-srccap (unwrap (read-u32be buffer 82)))
           (devcap-ext-srccap-V (unwrap (read-u8 buffer 82)))
           (devcap-ext-dstcap (unwrap (read-u32be buffer 82)))
           (devcap-ext-dstcap-V (unwrap (read-u8 buffer 82)))
           (auth-ext-reserved (unwrap (read-u16be buffer 82)))
           (auth-ext-spi (unwrap (read-u16be buffer 82)))
           (auth-ext-src-addr (unwrap (read-u32be buffer 82)))
           (auth-ext-src-addr-v6 (unwrap (slice buffer 82 16)))
           (auth-ext-src-addr-bytes (unwrap (slice buffer 82 1)))
           (vendor-ext-id (unwrap (read-u24be buffer 82)))
           (vendor-ext-data (unwrap (slice buffer 82 1)))
           (unknown-ext-value (unwrap (slice buffer 82 1)))
           )

      (ok (list
        (cons 'src-proto-len (list (cons 'raw src-proto-len) (cons 'formatted (number->string src-proto-len))))
        (cons 'dst-proto-len (list (cons 'raw dst-proto-len) (cons 'formatted (number->string dst-proto-len))))
        (cons 'hdr-pro-type (list (cons 'raw hdr-pro-type) (cons 'formatted (fmt-hex hdr-pro-type))))
        (cons 'hdr-pro-snap-oui (list (cons 'raw hdr-pro-snap-oui) (cons 'formatted (number->string hdr-pro-snap-oui))))
        (cons 'hdr-pro-snap-pid (list (cons 'raw hdr-pro-snap-pid) (cons 'formatted (fmt-hex hdr-pro-snap-pid))))
        (cons 'protocol-type (list (cons 'raw protocol-type) (cons 'formatted (fmt-bytes protocol-type))))
        (cons 'hdr-hopcnt (list (cons 'raw hdr-hopcnt) (cons 'formatted (number->string hdr-hopcnt))))
        (cons 'hdr-pktsz (list (cons 'raw hdr-pktsz) (cons 'formatted (number->string hdr-pktsz))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flag-N (list (cons 'raw flag-N) (cons 'formatted (if (= flag-N 0) "Not set" "Set"))))
        (cons 'flag-NAT (list (cons 'raw flag-NAT) (cons 'formatted (if (= flag-NAT 0) "Not set" "Set"))))
        (cons 'request-id (list (cons 'raw request-id) (cons 'formatted (fmt-hex request-id))))
        (cons 'hdr-extoff (list (cons 'raw hdr-extoff) (cons 'formatted (number->string hdr-extoff))))
        (cons 'hdr-version (list (cons 'raw hdr-version) (cons 'formatted (number->string hdr-version))))
        (cons 'hdr-shtl (list (cons 'raw hdr-shtl) (cons 'formatted (number->string hdr-shtl))))
        (cons 'hdr-shtl-len (list (cons 'raw hdr-shtl-len) (cons 'formatted (number->string hdr-shtl-len))))
        (cons 'hdr-sstl (list (cons 'raw hdr-sstl) (cons 'formatted (number->string hdr-sstl))))
        (cons 'hdr-sstl-len (list (cons 'raw hdr-sstl-len) (cons 'formatted (number->string hdr-sstl-len))))
        (cons 'prefix-len (list (cons 'raw prefix-len) (cons 'formatted (number->string prefix-len))))
        (cons 'error-offset (list (cons 'raw error-offset) (cons 'formatted (number->string error-offset))))
        (cons 'unused (list (cons 'raw unused) (cons 'formatted (number->string unused))))
        (cons 'mtu (list (cons 'raw mtu) (cons 'formatted (number->string mtu))))
        (cons 'holding-time (list (cons 'raw holding-time) (cons 'formatted (number->string holding-time))))
        (cons 'cli-addr-tl (list (cons 'raw cli-addr-tl) (cons 'formatted (number->string cli-addr-tl))))
        (cons 'cli-addr-tl-len (list (cons 'raw cli-addr-tl-len) (cons 'formatted (number->string cli-addr-tl-len))))
        (cons 'cli-saddr-tl (list (cons 'raw cli-saddr-tl) (cons 'formatted (number->string cli-saddr-tl))))
        (cons 'cli-saddr-tl-len (list (cons 'raw cli-saddr-tl-len) (cons 'formatted (number->string cli-saddr-tl-len))))
        (cons 'cli-prot-len (list (cons 'raw cli-prot-len) (cons 'formatted (number->string cli-prot-len))))
        (cons 'pref (list (cons 'raw pref) (cons 'formatted (number->string pref))))
        (cons 'client-nbma-addr (list (cons 'raw client-nbma-addr) (cons 'formatted (fmt-ipv4 client-nbma-addr))))
        (cons 'client-nbma-address-bytes (list (cons 'raw client-nbma-address-bytes) (cons 'formatted (fmt-bytes client-nbma-address-bytes))))
        (cons 'client-nbma-addr-v6 (list (cons 'raw client-nbma-addr-v6) (cons 'formatted (fmt-ipv6-address client-nbma-addr-v6))))
        (cons 'client-nbma-saddr (list (cons 'raw client-nbma-saddr) (cons 'formatted (fmt-bytes client-nbma-saddr))))
        (cons 'client-prot-addr (list (cons 'raw client-prot-addr) (cons 'formatted (fmt-ipv4 client-prot-addr))))
        (cons 'client-prot-addr-v6 (list (cons 'raw client-prot-addr-v6) (cons 'formatted (fmt-ipv6-address client-prot-addr-v6))))
        (cons 'client-prot-addr-bytes (list (cons 'raw client-prot-addr-bytes) (cons 'formatted (fmt-bytes client-prot-addr-bytes))))
        (cons 'src-nbma-addr (list (cons 'raw src-nbma-addr) (cons 'formatted (fmt-ipv4 src-nbma-addr))))
        (cons 'src-nbma-addr-bytes (list (cons 'raw src-nbma-addr-bytes) (cons 'formatted (fmt-bytes src-nbma-addr-bytes))))
        (cons 'src-nbma-addr-v6 (list (cons 'raw src-nbma-addr-v6) (cons 'formatted (fmt-ipv6-address src-nbma-addr-v6))))
        (cons 'src-nbma-saddr (list (cons 'raw src-nbma-saddr) (cons 'formatted (fmt-bytes src-nbma-saddr))))
        (cons 'src-prot-addr (list (cons 'raw src-prot-addr) (cons 'formatted (fmt-ipv4 src-prot-addr))))
        (cons 'dst-prot-addr (list (cons 'raw dst-prot-addr) (cons 'formatted (fmt-ipv4 dst-prot-addr))))
        (cons 'dst-prot-addr-v6 (list (cons 'raw dst-prot-addr-v6) (cons 'formatted (fmt-ipv6-address dst-prot-addr-v6))))
        (cons 'dst-prot-addr-bytes (list (cons 'raw dst-prot-addr-bytes) (cons 'formatted (fmt-bytes dst-prot-addr-bytes))))
        (cons 'ext-C (list (cons 'raw ext-C) (cons 'formatted (number->string ext-C))))
        (cons 'ext-len (list (cons 'raw ext-len) (cons 'formatted (number->string ext-len))))
        (cons 'devcap-ext-srccap (list (cons 'raw devcap-ext-srccap) (cons 'formatted (fmt-hex devcap-ext-srccap))))
        (cons 'devcap-ext-srccap-V (list (cons 'raw devcap-ext-srccap-V) (cons 'formatted (number->string devcap-ext-srccap-V))))
        (cons 'devcap-ext-dstcap (list (cons 'raw devcap-ext-dstcap) (cons 'formatted (fmt-hex devcap-ext-dstcap))))
        (cons 'devcap-ext-dstcap-V (list (cons 'raw devcap-ext-dstcap-V) (cons 'formatted (number->string devcap-ext-dstcap-V))))
        (cons 'auth-ext-reserved (list (cons 'raw auth-ext-reserved) (cons 'formatted (number->string auth-ext-reserved))))
        (cons 'auth-ext-spi (list (cons 'raw auth-ext-spi) (cons 'formatted (number->string auth-ext-spi))))
        (cons 'auth-ext-src-addr (list (cons 'raw auth-ext-src-addr) (cons 'formatted (fmt-ipv4 auth-ext-src-addr))))
        (cons 'auth-ext-src-addr-v6 (list (cons 'raw auth-ext-src-addr-v6) (cons 'formatted (fmt-ipv6-address auth-ext-src-addr-v6))))
        (cons 'auth-ext-src-addr-bytes (list (cons 'raw auth-ext-src-addr-bytes) (cons 'formatted (fmt-bytes auth-ext-src-addr-bytes))))
        (cons 'vendor-ext-id (list (cons 'raw vendor-ext-id) (cons 'formatted (number->string vendor-ext-id))))
        (cons 'vendor-ext-data (list (cons 'raw vendor-ext-data) (cons 'formatted (fmt-bytes vendor-ext-data))))
        (cons 'unknown-ext-value (list (cons 'raw unknown-ext-value) (cons 'formatted (fmt-bytes unknown-ext-value))))
        )))

    (catch (e)
      (err (str "NHRP parse error: " e)))))

;; dissect-nhrp: parse NHRP from bytevector
;; Returns (ok fields-alist) or (err message)