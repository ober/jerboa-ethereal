;; packet-pflog.c
;; Routines for pflog (Firewall Logging) packet disassembly
;;
;; Copyright 2001 Mike Frantzen
;; All rights reserved.
;;
;; SPDX-License-Identifier: BSD-1-Clause
;;

;; jerboa-ethereal/dissectors/pflog.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pflog.c

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
(def (dissect-pflog buffer)
  "OpenBSD Packet Filter log file"
  (try
    (let* (
           (ifname (unwrap (slice buffer 4 16)))
           (ruleset (unwrap (slice buffer 20 16)))
           (rulenr (unwrap (read-u32be buffer 36)))
           (subrulenr (unwrap (read-u32be buffer 40)))
           (uid (unwrap (read-u32be buffer 44)))
           (pid (unwrap (read-u32be buffer 48)))
           (rule-uid (unwrap (read-u32be buffer 52)))
           (rule-pid (unwrap (read-u32be buffer 56)))
           (rewritten (unwrap (read-u8 buffer 61)))
           (saddr-ipv4 (unwrap (read-u32be buffer 64)))
           (daddr-ipv4 (unwrap (read-u32be buffer 80)))
           (saddr-ipv6 (unwrap (slice buffer 96 16)))
           (daddr-ipv6 (unwrap (slice buffer 112 16)))
           (saddr (unwrap (slice buffer 128 16)))
           (daddr (unwrap (slice buffer 144 16)))
           (sport (unwrap (read-u16be buffer 160)))
           (dport (unwrap (read-u16be buffer 162)))
           (pad (unwrap (slice buffer 164 3)))
           (length (unwrap (read-u8 buffer 167)))
           )

      (ok (list
        (cons 'ifname (list (cons 'raw ifname) (cons 'formatted (utf8->string ifname))))
        (cons 'ruleset (list (cons 'raw ruleset) (cons 'formatted (utf8->string ruleset))))
        (cons 'rulenr (list (cons 'raw rulenr) (cons 'formatted (number->string rulenr))))
        (cons 'subrulenr (list (cons 'raw subrulenr) (cons 'formatted (number->string subrulenr))))
        (cons 'uid (list (cons 'raw uid) (cons 'formatted (number->string uid))))
        (cons 'pid (list (cons 'raw pid) (cons 'formatted (number->string pid))))
        (cons 'rule-uid (list (cons 'raw rule-uid) (cons 'formatted (number->string rule-uid))))
        (cons 'rule-pid (list (cons 'raw rule-pid) (cons 'formatted (number->string rule-pid))))
        (cons 'rewritten (list (cons 'raw rewritten) (cons 'formatted (number->string rewritten))))
        (cons 'saddr-ipv4 (list (cons 'raw saddr-ipv4) (cons 'formatted (fmt-ipv4 saddr-ipv4))))
        (cons 'daddr-ipv4 (list (cons 'raw daddr-ipv4) (cons 'formatted (fmt-ipv4 daddr-ipv4))))
        (cons 'saddr-ipv6 (list (cons 'raw saddr-ipv6) (cons 'formatted (fmt-ipv6-address saddr-ipv6))))
        (cons 'daddr-ipv6 (list (cons 'raw daddr-ipv6) (cons 'formatted (fmt-ipv6-address daddr-ipv6))))
        (cons 'saddr (list (cons 'raw saddr) (cons 'formatted (fmt-bytes saddr))))
        (cons 'daddr (list (cons 'raw daddr) (cons 'formatted (fmt-bytes daddr))))
        (cons 'sport (list (cons 'raw sport) (cons 'formatted (number->string sport))))
        (cons 'dport (list (cons 'raw dport) (cons 'formatted (number->string dport))))
        (cons 'pad (list (cons 'raw pad) (cons 'formatted (fmt-bytes pad))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        )))

    (catch (e)
      (err (str "PFLOG parse error: " e)))))

;; dissect-pflog: parse PFLOG from bytevector
;; Returns (ok fields-alist) or (err message)