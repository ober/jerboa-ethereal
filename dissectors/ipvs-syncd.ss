;; packet-ipvs-syncd.c   2001 Ronnie Sahlberg <See AUTHORS for email>
;; Routines for IGMP packet disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ipvs-syncd.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ipvs_syncd.c

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
(def (dissect-ipvs-syncd buffer)
  "IP Virtual Services Sync Daemon"
  (try
    (let* (
           (hf-syncid (unwrap (read-u8 buffer 1)))
           (hf-size (unwrap (read-u16be buffer 2)))
           (count (unwrap (read-u8 buffer 4)))
           (hf-version (unwrap (read-u8 buffer 5)))
           (hf-ver (unwrap (read-u16be buffer 10)))
           (v1 (unwrap (read-u32be buffer 12)))
           (hf-fwmark (unwrap (read-u32be buffer 24)))
           (hf-timeout (unwrap (read-u32be buffer 28)))
           (hf-caddr6 (unwrap (slice buffer 44 16)))
           (hf-vaddr6 (unwrap (slice buffer 60 16)))
           (hf-daddr6 (unwrap (slice buffer 76 16)))
           (hf-resv (unwrap (slice buffer 92 1)))
           (hf-cport (unwrap (read-u16be buffer 94)))
           (hf-vport (unwrap (read-u16be buffer 96)))
           (hf-dport (unwrap (read-u16be buffer 98)))
           (hf-caddr (unwrap (read-u32be buffer 100)))
           (hf-vaddr (unwrap (read-u32be buffer 104)))
           (hf-daddr (unwrap (read-u32be buffer 108)))
           (hf-flags (unwrap (read-u16be buffer 112)))
           (hashed-entry (unwrap (read-u8 buffer 112)))
           (no-output-packets (unwrap (read-u8 buffer 112)))
           (conn-not-established (unwrap (read-u8 buffer 112)))
           (adjust-output-seq (unwrap (read-u8 buffer 112)))
           (adjust-input-seq (unwrap (read-u8 buffer 112)))
           (no-client-port-set (unwrap (read-u8 buffer 112)))
           (seq-init (unwrap (read-u32be buffer 128)))
           (seq-delta (unwrap (read-u32be buffer 132)))
           (seq-pdelta (unwrap (read-u32be buffer 136)))
           )

      (ok (list
        (cons 'hf-syncid (list (cons 'raw hf-syncid) (cons 'formatted (number->string hf-syncid))))
        (cons 'hf-size (list (cons 'raw hf-size) (cons 'formatted (number->string hf-size))))
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        (cons 'hf-ver (list (cons 'raw hf-ver) (cons 'formatted (number->string hf-ver))))
        (cons 'v1 (list (cons 'raw v1) (cons 'formatted (fmt-hex v1))))
        (cons 'hf-fwmark (list (cons 'raw hf-fwmark) (cons 'formatted (fmt-hex hf-fwmark))))
        (cons 'hf-timeout (list (cons 'raw hf-timeout) (cons 'formatted (number->string hf-timeout))))
        (cons 'hf-caddr6 (list (cons 'raw hf-caddr6) (cons 'formatted (fmt-ipv6-address hf-caddr6))))
        (cons 'hf-vaddr6 (list (cons 'raw hf-vaddr6) (cons 'formatted (fmt-ipv6-address hf-vaddr6))))
        (cons 'hf-daddr6 (list (cons 'raw hf-daddr6) (cons 'formatted (fmt-ipv6-address hf-daddr6))))
        (cons 'hf-resv (list (cons 'raw hf-resv) (cons 'formatted (fmt-bytes hf-resv))))
        (cons 'hf-cport (list (cons 'raw hf-cport) (cons 'formatted (number->string hf-cport))))
        (cons 'hf-vport (list (cons 'raw hf-vport) (cons 'formatted (number->string hf-vport))))
        (cons 'hf-dport (list (cons 'raw hf-dport) (cons 'formatted (number->string hf-dport))))
        (cons 'hf-caddr (list (cons 'raw hf-caddr) (cons 'formatted (fmt-ipv4 hf-caddr))))
        (cons 'hf-vaddr (list (cons 'raw hf-vaddr) (cons 'formatted (fmt-ipv4 hf-vaddr))))
        (cons 'hf-daddr (list (cons 'raw hf-daddr) (cons 'formatted (fmt-ipv4 hf-daddr))))
        (cons 'hf-flags (list (cons 'raw hf-flags) (cons 'formatted (fmt-hex hf-flags))))
        (cons 'hashed-entry (list (cons 'raw hashed-entry) (cons 'formatted (number->string hashed-entry))))
        (cons 'no-output-packets (list (cons 'raw no-output-packets) (cons 'formatted (number->string no-output-packets))))
        (cons 'conn-not-established (list (cons 'raw conn-not-established) (cons 'formatted (number->string conn-not-established))))
        (cons 'adjust-output-seq (list (cons 'raw adjust-output-seq) (cons 'formatted (number->string adjust-output-seq))))
        (cons 'adjust-input-seq (list (cons 'raw adjust-input-seq) (cons 'formatted (number->string adjust-input-seq))))
        (cons 'no-client-port-set (list (cons 'raw no-client-port-set) (cons 'formatted (number->string no-client-port-set))))
        (cons 'seq-init (list (cons 'raw seq-init) (cons 'formatted (fmt-hex seq-init))))
        (cons 'seq-delta (list (cons 'raw seq-delta) (cons 'formatted (fmt-hex seq-delta))))
        (cons 'seq-pdelta (list (cons 'raw seq-pdelta) (cons 'formatted (fmt-hex seq-pdelta))))
        )))

    (catch (e)
      (err (str "IPVS-SYNCD parse error: " e)))))

;; dissect-ipvs-syncd: parse IPVS-SYNCD from bytevector
;; Returns (ok fields-alist) or (err message)