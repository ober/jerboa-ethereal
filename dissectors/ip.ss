;; packet-ip.c
;; Routines for IP and miscellaneous IP protocol packet disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Wednesday, January 17, 2006
;; Support for the CIPSO IPv4 option
;; (http://sourceforge.net/docman/display_doc.php?docid=34650&group_id=174379)
;; by   Paul Moore <paul.moore@hp.com>
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ip.c
;; RFC 2474

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
(def (dissect-ip buffer)
  "Internet Protocol Version 4"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (opt-type (unwrap (read-u8 buffer 0)))
           (opt-type-copy (unwrap (read-u8 buffer 0)))
           (dsfield (unwrap (read-u8 buffer 0)))
           (tos (unwrap (read-u8 buffer 0)))
           (tos-delay (unwrap (read-u8 buffer 0)))
           (tos-throughput (unwrap (read-u8 buffer 0)))
           (tos-reliability (unwrap (read-u8 buffer 0)))
           (tos-cost (unwrap (read-u8 buffer 0)))
           (len (unwrap (read-u16be buffer 0)))
           (id (unwrap (read-u16be buffer 0)))
           (flags (unwrap (read-u8 buffer 0)))
           (flags-sf (extract-bits flags 0x80 7))
           (flags-df (extract-bits flags 0x40 6))
           (flags-mf (extract-bits flags 0x20 5))
           (frag-offset (unwrap (read-u16be buffer 0)))
           (ttl (unwrap (read-u8 buffer 0)))
           (checksum-calculated (unwrap (read-u16be buffer 0)))
           (checksum (unwrap (read-u16be buffer 0)))
           (src (unwrap (read-u32be buffer 0)))
           (addr (unwrap (read-u32be buffer 0)))
           (src-host (unwrap (slice buffer 0 4)))
           (host (unwrap (slice buffer 0 4)))
           (cur-rt (unwrap (read-u32be buffer 0)))
           (cur-rt-host (unwrap (slice buffer 0 4)))
           (dst (unwrap (read-u32be buffer 0)))
           (dst-host (unwrap (slice buffer 0 4)))
           (stream (unwrap (read-u32be buffer 0)))
           (opt-mtu (unwrap (read-u16be buffer 2)))
           (opt-sid (unwrap (read-u16be buffer 2)))
           (cipso-doi (unwrap (read-u32be buffer 2)))
           (opt-id-number (unwrap (read-u16be buffer 2)))
           (opt-ohc (unwrap (read-u16be buffer 2)))
           (opt-rhc (unwrap (read-u16be buffer 2)))
           (opt-originator (unwrap (read-u32be buffer 2)))
           (opt-ptr (unwrap (read-u8 buffer 2)))
           (opt-overflow (unwrap (read-u8 buffer 2)))
           (opt-time-stamp-addr (unwrap (read-u32be buffer 2)))
           (opt-qs-ttl (unwrap (read-u8 buffer 2)))
           (opt-qs-ttl-diff (unwrap (read-u8 buffer 2)))
           (opt-qs-nonce (unwrap (read-u32be buffer 2)))
           (opt-qs-reserved (unwrap (read-u32be buffer 2)))
           (opt-qs-unused (unwrap (read-u8 buffer 2)))
           (opt-dsr-cilium-service-port (unwrap (read-u16be buffer 2)))
           (opt-dsr-cilium-service-ip (unwrap (read-u32be buffer 4)))
           (opt-len (unwrap (read-u8 buffer 4)))
           (opt-data (unwrap (slice buffer 4 1)))
           (opt-addr (unwrap (read-u32be buffer 6)))
           (opt-padding (unwrap (slice buffer 6 1)))
           (opt-time-stamp (unwrap (read-u32be buffer 10)))
           (cipso-categories (unwrap (slice buffer 11 1)))
           (cipso-sensitivity-level (unwrap (read-u8 buffer 14)))
           (cipso-tag-data (unwrap (slice buffer 27 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'opt-type (list (cons 'raw opt-type) (cons 'formatted (number->string opt-type))))
        (cons 'opt-type-copy (list (cons 'raw opt-type-copy) (cons 'formatted (if (= opt-type-copy 0) "False" "True"))))
        (cons 'dsfield (list (cons 'raw dsfield) (cons 'formatted (fmt-hex dsfield))))
        (cons 'tos (list (cons 'raw tos) (cons 'formatted (number->string tos))))
        (cons 'tos-delay (list (cons 'raw tos-delay) (cons 'formatted (if (= tos-delay 0) "False" "True"))))
        (cons 'tos-throughput (list (cons 'raw tos-throughput) (cons 'formatted (if (= tos-throughput 0) "False" "True"))))
        (cons 'tos-reliability (list (cons 'raw tos-reliability) (cons 'formatted (if (= tos-reliability 0) "False" "True"))))
        (cons 'tos-cost (list (cons 'raw tos-cost) (cons 'formatted (if (= tos-cost 0) "False" "True"))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-hex id))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-sf (list (cons 'raw flags-sf) (cons 'formatted (if (= flags-sf 0) "Not evil" "Evil"))))
        (cons 'flags-df (list (cons 'raw flags-df) (cons 'formatted (if (= flags-df 0) "Not set" "Set"))))
        (cons 'flags-mf (list (cons 'raw flags-mf) (cons 'formatted (if (= flags-mf 0) "Not set" "Set"))))
        (cons 'frag-offset (list (cons 'raw frag-offset) (cons 'formatted (number->string frag-offset))))
        (cons 'ttl (list (cons 'raw ttl) (cons 'formatted (number->string ttl))))
        (cons 'checksum-calculated (list (cons 'raw checksum-calculated) (cons 'formatted (fmt-hex checksum-calculated))))
        (cons 'checksum (list (cons 'raw checksum) (cons 'formatted (fmt-hex checksum))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (fmt-ipv4 src))))
        (cons 'addr (list (cons 'raw addr) (cons 'formatted (fmt-ipv4 addr))))
        (cons 'src-host (list (cons 'raw src-host) (cons 'formatted (utf8->string src-host))))
        (cons 'host (list (cons 'raw host) (cons 'formatted (utf8->string host))))
        (cons 'cur-rt (list (cons 'raw cur-rt) (cons 'formatted (fmt-ipv4 cur-rt))))
        (cons 'cur-rt-host (list (cons 'raw cur-rt-host) (cons 'formatted (utf8->string cur-rt-host))))
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (fmt-ipv4 dst))))
        (cons 'dst-host (list (cons 'raw dst-host) (cons 'formatted (utf8->string dst-host))))
        (cons 'stream (list (cons 'raw stream) (cons 'formatted (number->string stream))))
        (cons 'opt-mtu (list (cons 'raw opt-mtu) (cons 'formatted (number->string opt-mtu))))
        (cons 'opt-sid (list (cons 'raw opt-sid) (cons 'formatted (number->string opt-sid))))
        (cons 'cipso-doi (list (cons 'raw cipso-doi) (cons 'formatted (number->string cipso-doi))))
        (cons 'opt-id-number (list (cons 'raw opt-id-number) (cons 'formatted (number->string opt-id-number))))
        (cons 'opt-ohc (list (cons 'raw opt-ohc) (cons 'formatted (number->string opt-ohc))))
        (cons 'opt-rhc (list (cons 'raw opt-rhc) (cons 'formatted (number->string opt-rhc))))
        (cons 'opt-originator (list (cons 'raw opt-originator) (cons 'formatted (fmt-ipv4 opt-originator))))
        (cons 'opt-ptr (list (cons 'raw opt-ptr) (cons 'formatted (number->string opt-ptr))))
        (cons 'opt-overflow (list (cons 'raw opt-overflow) (cons 'formatted (number->string opt-overflow))))
        (cons 'opt-time-stamp-addr (list (cons 'raw opt-time-stamp-addr) (cons 'formatted (fmt-ipv4 opt-time-stamp-addr))))
        (cons 'opt-qs-ttl (list (cons 'raw opt-qs-ttl) (cons 'formatted (number->string opt-qs-ttl))))
        (cons 'opt-qs-ttl-diff (list (cons 'raw opt-qs-ttl-diff) (cons 'formatted (number->string opt-qs-ttl-diff))))
        (cons 'opt-qs-nonce (list (cons 'raw opt-qs-nonce) (cons 'formatted (fmt-hex opt-qs-nonce))))
        (cons 'opt-qs-reserved (list (cons 'raw opt-qs-reserved) (cons 'formatted (fmt-hex opt-qs-reserved))))
        (cons 'opt-qs-unused (list (cons 'raw opt-qs-unused) (cons 'formatted (number->string opt-qs-unused))))
        (cons 'opt-dsr-cilium-service-port (list (cons 'raw opt-dsr-cilium-service-port) (cons 'formatted (number->string opt-dsr-cilium-service-port))))
        (cons 'opt-dsr-cilium-service-ip (list (cons 'raw opt-dsr-cilium-service-ip) (cons 'formatted (fmt-ipv4 opt-dsr-cilium-service-ip))))
        (cons 'opt-len (list (cons 'raw opt-len) (cons 'formatted (number->string opt-len))))
        (cons 'opt-data (list (cons 'raw opt-data) (cons 'formatted (fmt-bytes opt-data))))
        (cons 'opt-addr (list (cons 'raw opt-addr) (cons 'formatted (fmt-ipv4 opt-addr))))
        (cons 'opt-padding (list (cons 'raw opt-padding) (cons 'formatted (fmt-bytes opt-padding))))
        (cons 'opt-time-stamp (list (cons 'raw opt-time-stamp) (cons 'formatted (number->string opt-time-stamp))))
        (cons 'cipso-categories (list (cons 'raw cipso-categories) (cons 'formatted (utf8->string cipso-categories))))
        (cons 'cipso-sensitivity-level (list (cons 'raw cipso-sensitivity-level) (cons 'formatted (number->string cipso-sensitivity-level))))
        (cons 'cipso-tag-data (list (cons 'raw cipso-tag-data) (cons 'formatted (fmt-bytes cipso-tag-data))))
        )))

    (catch (e)
      (err (str "IP parse error: " e)))))

;; dissect-ip: parse IP from bytevector
;; Returns (ok fields-alist) or (err message)