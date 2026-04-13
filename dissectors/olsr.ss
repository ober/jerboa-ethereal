;; packet-olsr.c
;; Routines for OLSR (IPv4 & IPv6 compatible) RFC parsing
;; Compatible with RFC-compliant OLSR implementations such as
;; NRLOLSRD (http://pf.itd.nrl.navy.mil/projects/olsr/).
;; Parser created by Aaron Woo <woo@itd.nrl.navy.mil> of
;; the Naval Research Laboratory
;; Currently maintained by Jeff Weston <weston@itd.nrl.navy.mil>.
;;
;; Updated to Olsr.org and NRLOLSR packages by Henning Rogge <rogge@fgan.de>
;; https://www.ietf.org/rfc/rfc3626
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/olsr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-olsr.c

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
(def (dissect-olsr buffer)
  "Optimized Link State Routing Protocol"
  (try
    (let* (
           (packet-len (unwrap (read-u16be buffer 0)))
           (packet-seq-num (unwrap (read-u16be buffer 2)))
           (message (unwrap (slice buffer 4 1)))
           (vtime (unwrap (read-u64be buffer 5)))
           (message-size (unwrap (read-u16be buffer 6)))
           (origin-addr (unwrap (read-u32be buffer 8)))
           (origin6-addr (unwrap (slice buffer 12 16)))
           (ttl (unwrap (read-u8 buffer 28)))
           (hop-count (unwrap (read-u8 buffer 28)))
           (message-seq-num (unwrap (read-u16be buffer 28)))
           (data (unwrap (slice buffer 32 1)))
           (ansn (unwrap (read-u16be buffer 50)))
           (htime (unwrap (read-u64be buffer 76)))
           (link-message-size (unwrap (read-u16be buffer 78)))
           (neighbor-addr (unwrap (read-u32be buffer 100)))
           (neighbor (unwrap (slice buffer 104 20)))
           (neighbor6-addr (unwrap (slice buffer 104 16)))
           (interface-addr (unwrap (read-u32be buffer 122)))
           (interface6-addr (unwrap (slice buffer 126 16)))
           (network-addr (unwrap (read-u32be buffer 142)))
           (netmask (unwrap (read-u32be buffer 146)))
           (network6-addr (unwrap (slice buffer 150 4)))
           (netmask6 (unwrap (slice buffer 166 4)))
           (ns-version (unwrap (read-u16be buffer 182)))
           (ns-count (unwrap (read-u16be buffer 182)))
           (ns (unwrap (slice buffer 186 1)))
           (ns-length (unwrap (read-u16be buffer 186)))
           (ns-ip (unwrap (read-u32be buffer 186)))
           (ns-ip6 (unwrap (slice buffer 186 16)))
           (ns-content (unwrap (slice buffer 186 1)))
           )

      (ok (list
        (cons 'packet-len (list (cons 'raw packet-len) (cons 'formatted (number->string packet-len))))
        (cons 'packet-seq-num (list (cons 'raw packet-seq-num) (cons 'formatted (number->string packet-seq-num))))
        (cons 'message (list (cons 'raw message) (cons 'formatted (fmt-bytes message))))
        (cons 'vtime (list (cons 'raw vtime) (cons 'formatted (number->string vtime))))
        (cons 'message-size (list (cons 'raw message-size) (cons 'formatted (number->string message-size))))
        (cons 'origin-addr (list (cons 'raw origin-addr) (cons 'formatted (fmt-ipv4 origin-addr))))
        (cons 'origin6-addr (list (cons 'raw origin6-addr) (cons 'formatted (fmt-ipv6-address origin6-addr))))
        (cons 'ttl (list (cons 'raw ttl) (cons 'formatted (number->string ttl))))
        (cons 'hop-count (list (cons 'raw hop-count) (cons 'formatted (number->string hop-count))))
        (cons 'message-seq-num (list (cons 'raw message-seq-num) (cons 'formatted (number->string message-seq-num))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'ansn (list (cons 'raw ansn) (cons 'formatted (number->string ansn))))
        (cons 'htime (list (cons 'raw htime) (cons 'formatted (number->string htime))))
        (cons 'link-message-size (list (cons 'raw link-message-size) (cons 'formatted (number->string link-message-size))))
        (cons 'neighbor-addr (list (cons 'raw neighbor-addr) (cons 'formatted (fmt-ipv4 neighbor-addr))))
        (cons 'neighbor (list (cons 'raw neighbor) (cons 'formatted (fmt-bytes neighbor))))
        (cons 'neighbor6-addr (list (cons 'raw neighbor6-addr) (cons 'formatted (fmt-ipv6-address neighbor6-addr))))
        (cons 'interface-addr (list (cons 'raw interface-addr) (cons 'formatted (fmt-ipv4 interface-addr))))
        (cons 'interface6-addr (list (cons 'raw interface6-addr) (cons 'formatted (fmt-ipv6-address interface6-addr))))
        (cons 'network-addr (list (cons 'raw network-addr) (cons 'formatted (fmt-ipv4 network-addr))))
        (cons 'netmask (list (cons 'raw netmask) (cons 'formatted (fmt-ipv4 netmask))))
        (cons 'network6-addr (list (cons 'raw network6-addr) (cons 'formatted (fmt-ipv6-address network6-addr))))
        (cons 'netmask6 (list (cons 'raw netmask6) (cons 'formatted (fmt-ipv6-address netmask6))))
        (cons 'ns-version (list (cons 'raw ns-version) (cons 'formatted (number->string ns-version))))
        (cons 'ns-count (list (cons 'raw ns-count) (cons 'formatted (number->string ns-count))))
        (cons 'ns (list (cons 'raw ns) (cons 'formatted (fmt-bytes ns))))
        (cons 'ns-length (list (cons 'raw ns-length) (cons 'formatted (number->string ns-length))))
        (cons 'ns-ip (list (cons 'raw ns-ip) (cons 'formatted (fmt-ipv4 ns-ip))))
        (cons 'ns-ip6 (list (cons 'raw ns-ip6) (cons 'formatted (fmt-ipv6-address ns-ip6))))
        (cons 'ns-content (list (cons 'raw ns-content) (cons 'formatted (utf8->string ns-content))))
        )))

    (catch (e)
      (err (str "OLSR parse error: " e)))))

;; dissect-olsr: parse OLSR from bytevector
;; Returns (ok fields-alist) or (err message)