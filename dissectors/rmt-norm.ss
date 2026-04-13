;; packet-rmt-norm.c
;; Reliable Multicast Transport (RMT)
;; NORM Protocol Instantiation dissector
;; Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
;;
;; Extensive changes to decode more information Julian Onions
;;
;; Negative-acknowledgment (NACK)-Oriented Reliable Multicast (NORM):
;; ------------------------------------------------------------------
;;
;; This protocol is designed to provide end-to-end reliable transport of
;; bulk data objects or streams over generic IP multicast routing and
;; forwarding services.  NORM uses a selective, negative acknowledgment
;; mechanism for transport reliability and offers additional protocol
;; mechanisms to allow for operation with minimal "a priori"
;; coordination among senders and receivers.
;;
;; References:
;; RFC 3940, Negative-acknowledgment (NACK)-Oriented Reliable Multicast (NORM) Protocol
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rmt-norm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rmt_norm.c
;; RFC 3940

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
(def (dissect-rmt-norm buffer)
  "Negative-acknowledgment Oriented Reliable Multicast"
  (try
    (let* (
           (hf-version (unwrap (read-u8 buffer 0)))
           (hf-hlen (unwrap (read-u8 buffer 0)))
           (hf-sequence (unwrap (read-u16be buffer 0)))
           (hf-grtt (unwrap (read-u64be buffer 2)))
           (hf-backoff (unwrap (read-u8 buffer 3)))
           (hf-gsize (unwrap (read-u64be buffer 3)))
           (hf-payload (unwrap (slice buffer 8 1)))
           (flags-segment (unwrap (read-u8 buffer 9)))
           (flags-block (unwrap (read-u8 buffer 9)))
           (flags-info (unwrap (read-u8 buffer 9)))
           (flags-object (unwrap (read-u8 buffer 9)))
           (length (unwrap (read-u16be buffer 10)))
           (len (unwrap (read-u16be buffer 15)))
           (offset (unwrap (read-u32be buffer 17)))
           (repair (unwrap (read-u8 buffer 21)))
           (norm-explicit (unwrap (read-u8 buffer 21)))
           (info (unwrap (read-u8 buffer 21)))
           (unreliable (unwrap (read-u8 buffer 21)))
           (file (unwrap (read-u8 buffer 21)))
           (stream (unwrap (read-u8 buffer 21)))
           (msgstart (unwrap (read-u8 buffer 21)))
           (hf-flags (unwrap (read-u8 buffer 25)))
           (sequence (unwrap (read-u16be buffer 29)))
           (sts (unwrap (read-u32be buffer 31)))
           (stus (unwrap (read-u32be buffer 35)))
           (node-id (unwrap (read-u32be buffer 39)))
           (flags (unwrap (read-u8 buffer 43)))
           (flags-clr (unwrap (read-u8 buffer 43)))
           (flags-plr (unwrap (read-u8 buffer 43)))
           (flags-rtt (unwrap (read-u8 buffer 43)))
           (flags-start (unwrap (read-u8 buffer 43)))
           (flags-leave (unwrap (read-u8 buffer 43)))
           (rtt (unwrap (read-u64be buffer 44)))
           (rate (unwrap (read-u64be buffer 45)))
           (transport-id (unwrap (read-u16be buffer 47)))
           (source (unwrap (read-u32be buffer 53)))
           (server (unwrap (read-u32be buffer 69)))
           (id (unwrap (read-u16be buffer 73)))
           (hf-reserved (unwrap (read-u16be buffer 75)))
           (grtt-sec (unwrap (read-u32be buffer 77)))
           (grtt-usec (unwrap (read-u32be buffer 81)))
           )

      (ok (list
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        (cons 'hf-hlen (list (cons 'raw hf-hlen) (cons 'formatted (number->string hf-hlen))))
        (cons 'hf-sequence (list (cons 'raw hf-sequence) (cons 'formatted (number->string hf-sequence))))
        (cons 'hf-grtt (list (cons 'raw hf-grtt) (cons 'formatted (number->string hf-grtt))))
        (cons 'hf-backoff (list (cons 'raw hf-backoff) (cons 'formatted (number->string hf-backoff))))
        (cons 'hf-gsize (list (cons 'raw hf-gsize) (cons 'formatted (number->string hf-gsize))))
        (cons 'hf-payload (list (cons 'raw hf-payload) (cons 'formatted (fmt-bytes hf-payload))))
        (cons 'flags-segment (list (cons 'raw flags-segment) (cons 'formatted (number->string flags-segment))))
        (cons 'flags-block (list (cons 'raw flags-block) (cons 'formatted (number->string flags-block))))
        (cons 'flags-info (list (cons 'raw flags-info) (cons 'formatted (number->string flags-info))))
        (cons 'flags-object (list (cons 'raw flags-object) (cons 'formatted (number->string flags-object))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (number->string offset))))
        (cons 'repair (list (cons 'raw repair) (cons 'formatted (number->string repair))))
        (cons 'norm-explicit (list (cons 'raw norm-explicit) (cons 'formatted (number->string norm-explicit))))
        (cons 'info (list (cons 'raw info) (cons 'formatted (number->string info))))
        (cons 'unreliable (list (cons 'raw unreliable) (cons 'formatted (number->string unreliable))))
        (cons 'file (list (cons 'raw file) (cons 'formatted (number->string file))))
        (cons 'stream (list (cons 'raw stream) (cons 'formatted (number->string stream))))
        (cons 'msgstart (list (cons 'raw msgstart) (cons 'formatted (number->string msgstart))))
        (cons 'hf-flags (list (cons 'raw hf-flags) (cons 'formatted (fmt-hex hf-flags))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (number->string sequence))))
        (cons 'sts (list (cons 'raw sts) (cons 'formatted (number->string sts))))
        (cons 'stus (list (cons 'raw stus) (cons 'formatted (number->string stus))))
        (cons 'node-id (list (cons 'raw node-id) (cons 'formatted (fmt-ipv4 node-id))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (number->string flags))))
        (cons 'flags-clr (list (cons 'raw flags-clr) (cons 'formatted (number->string flags-clr))))
        (cons 'flags-plr (list (cons 'raw flags-plr) (cons 'formatted (number->string flags-plr))))
        (cons 'flags-rtt (list (cons 'raw flags-rtt) (cons 'formatted (number->string flags-rtt))))
        (cons 'flags-start (list (cons 'raw flags-start) (cons 'formatted (number->string flags-start))))
        (cons 'flags-leave (list (cons 'raw flags-leave) (cons 'formatted (number->string flags-leave))))
        (cons 'rtt (list (cons 'raw rtt) (cons 'formatted (number->string rtt))))
        (cons 'rate (list (cons 'raw rate) (cons 'formatted (number->string rate))))
        (cons 'transport-id (list (cons 'raw transport-id) (cons 'formatted (number->string transport-id))))
        (cons 'source (list (cons 'raw source) (cons 'formatted (fmt-ipv4 source))))
        (cons 'server (list (cons 'raw server) (cons 'formatted (fmt-ipv4 server))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'hf-reserved (list (cons 'raw hf-reserved) (cons 'formatted (fmt-hex hf-reserved))))
        (cons 'grtt-sec (list (cons 'raw grtt-sec) (cons 'formatted (number->string grtt-sec))))
        (cons 'grtt-usec (list (cons 'raw grtt-usec) (cons 'formatted (number->string grtt-usec))))
        )))

    (catch (e)
      (err (str "RMT-NORM parse error: " e)))))

;; dissect-rmt-norm: parse RMT-NORM from bytevector
;; Returns (ok fields-alist) or (err message)