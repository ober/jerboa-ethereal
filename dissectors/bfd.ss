;; packet-bfd.c
;; Routines for Bidirectional Forwarding Detection (BFD) message dissection
;; RFCs
;; 5880: Bidirectional Forwarding Detection (BFD)
;; 5881: Bidirectional Forwarding Detection (BFD) for IPv4 and IPv6 (Single Hop)
;; 5882: Generic Application of Bidirectional Forwarding Detection (BFD)
;; 5883: Bidirectional Forwarding Detection (BFD) for Multihop Paths
;; 5884: Bidirectional Forwarding Detection (BFD) for MPLS Label Switched Paths (LSPs)
;; 5885: Bidirectional Forwarding Detection (BFD) for the Pseudowire Virtual Circuit Connectivity Verification (VCCV)
;; 7130: Bidirectional Forwarding Detection (BFD) on Link Aggregation Group (LAG) Interfaces
;; 7881: Seamless Bidirectional Forwarding Detection (S-BFD) for IPv4, IPv6, and MPLS
;; (and https://tools.ietf.org/html/draft-ietf-bfd-base-01 for version 0)
;;
;; Copyright 2003, Hannes Gredler <hannes@juniper.net>
;; Copyright 2006, Balint Reczey <Balint.Reczey@ericsson.com>
;; Copyright 2007, Todd J Martin <todd.martin@acm.org>
;;
;; Copyright 2011, Jaihari Kalijanakiraman <jaiharik@ipinfusion.com>
;; Krishnamurthy Mayya <krishnamurthy.mayya@ipinfusion.com>
;; Nikitha Malgi       <malgi.nikitha@ipinfusion.com>
;; - support for MPLS-TP BFD Proactive CV Message Format as per RFC 6428
;; - includes decoding support for Section MEP-ID, LSP MEP-ID, PW MEP-ID
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bfd.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bfd.c
;; RFC 6428

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
(def (dissect-bfd buffer)
  "Bidirectional Forwarding Detection Control Message"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (echo (unwrap (slice buffer 0 1)))
           (flags (unwrap (read-u8 buffer 1)))
           (flags-p (extract-bits flags 0x20 5))
           (flags-f (extract-bits flags 0x10 4))
           (flags-c (extract-bits flags 0x8 3))
           (flags-a (extract-bits flags 0x4 2))
           (flags-d (extract-bits flags 0x2 1))
           (flags-m (extract-bits flags 0x1 0))
           (detect-time-multiplier (unwrap (read-u8 buffer 2)))
           (my-discriminator (unwrap (read-u32be buffer 4)))
           (your-discriminator (unwrap (read-u32be buffer 8)))
           (desired-min-tx-interval (unwrap (read-u32be buffer 12)))
           (required-min-rx-interval (unwrap (read-u32be buffer 16)))
           (required-min-echo-interval (unwrap (read-u32be buffer 20)))
           (auth-key (unwrap (read-u8 buffer 24)))
           (auth-password (unwrap (slice buffer 24 1)))
           (auth-seq-num (unwrap (read-u32be buffer 24)))
           (checksum (unwrap (slice buffer 24 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'echo (list (cons 'raw echo) (cons 'formatted (fmt-bytes echo))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-p (list (cons 'raw flags-p) (cons 'formatted (if (= flags-p 0) "Not set" "Set"))))
        (cons 'flags-f (list (cons 'raw flags-f) (cons 'formatted (if (= flags-f 0) "Not set" "Set"))))
        (cons 'flags-c (list (cons 'raw flags-c) (cons 'formatted (if (= flags-c 0) "Not set" "Set"))))
        (cons 'flags-a (list (cons 'raw flags-a) (cons 'formatted (if (= flags-a 0) "Not set" "Set"))))
        (cons 'flags-d (list (cons 'raw flags-d) (cons 'formatted (if (= flags-d 0) "Not set" "Set"))))
        (cons 'flags-m (list (cons 'raw flags-m) (cons 'formatted (if (= flags-m 0) "Not set" "Set"))))
        (cons 'detect-time-multiplier (list (cons 'raw detect-time-multiplier) (cons 'formatted (number->string detect-time-multiplier))))
        (cons 'my-discriminator (list (cons 'raw my-discriminator) (cons 'formatted (fmt-hex my-discriminator))))
        (cons 'your-discriminator (list (cons 'raw your-discriminator) (cons 'formatted (fmt-hex your-discriminator))))
        (cons 'desired-min-tx-interval (list (cons 'raw desired-min-tx-interval) (cons 'formatted (number->string desired-min-tx-interval))))
        (cons 'required-min-rx-interval (list (cons 'raw required-min-rx-interval) (cons 'formatted (number->string required-min-rx-interval))))
        (cons 'required-min-echo-interval (list (cons 'raw required-min-echo-interval) (cons 'formatted (number->string required-min-echo-interval))))
        (cons 'auth-key (list (cons 'raw auth-key) (cons 'formatted (number->string auth-key))))
        (cons 'auth-password (list (cons 'raw auth-password) (cons 'formatted (utf8->string auth-password))))
        (cons 'auth-seq-num (list (cons 'raw auth-seq-num) (cons 'formatted (fmt-hex auth-seq-num))))
        (cons 'checksum (list (cons 'raw checksum) (cons 'formatted (fmt-bytes checksum))))
        )))

    (catch (e)
      (err (str "BFD parse error: " e)))))

;; dissect-bfd: parse BFD from bytevector
;; Returns (ok fields-alist) or (err message)