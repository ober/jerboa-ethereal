;; packet-igmp.c
;; Routines for IGMP packet disassembly
;; 2001 Ronnie Sahlberg
;; 2007 Thomas Morin
;; <See AUTHORS for emails>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/igmp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-igmp.c
;; RFC 988

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
(def (dissect-igmp buffer)
  "Internet Group Management Protocol"
  (try
    (let* (
           (hf-version (unwrap (read-u8 buffer 0)))
           (hf-data (unwrap (slice buffer 1 1)))
           (resp-exp (unwrap (read-u8 buffer 1)))
           (resp-mant (unwrap (read-u8 buffer 1)))
           (max-hops (unwrap (read-u8 buffer 1)))
           (data-len (unwrap (read-u8 buffer 4)))
           (hf-maddr (unwrap (read-u32be buffer 4)))
           (saddr (unwrap (read-u32be buffer 8)))
           (raddr (unwrap (read-u32be buffer 12)))
           (data (unwrap (slice buffer 15 1)))
           (rspaddr (unwrap (read-u32be buffer 16)))
           (grp-recs (unwrap (read-u16be buffer 20)))
           (resp-ttl (unwrap (read-u8 buffer 20)))
           (q-id (unwrap (read-u24be buffer 21)))
           (q-arrival (unwrap (read-u32be buffer 24)))
           (hf-qqic (unwrap (read-u8 buffer 28)))
           (q-inaddr (unwrap (read-u32be buffer 28)))
           (src (unwrap (read-u16be buffer 29)))
           (hf-saddr (unwrap (read-u32be buffer 31)))
           (q-outaddr (unwrap (read-u32be buffer 32)))
           (resp (unwrap (read-u8 buffer 35)))
           (q-prevrtr (unwrap (read-u32be buffer 36)))
           (q-inpkt (unwrap (read-u32be buffer 40)))
           (hf-reserved (unwrap (slice buffer 42 1)))
           (q-outpkt (unwrap (read-u32be buffer 44)))
           (q-total (unwrap (read-u32be buffer 48)))
           (pending (unwrap (read-u8 buffer 49)))
           (hf-identifier (unwrap (read-u32be buffer 52)))
           (q-fwd-ttl (unwrap (read-u8 buffer 53)))
           (q-mbz (unwrap (read-u8 buffer 54)))
           (q-s (unwrap (read-u8 buffer 54)))
           (q-src-mask (unwrap (read-u8 buffer 54)))
           (key (unwrap (slice buffer 60 8)))
           )

      (ok (list
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        (cons 'hf-data (list (cons 'raw hf-data) (cons 'formatted (fmt-bytes hf-data))))
        (cons 'resp-exp (list (cons 'raw resp-exp) (cons 'formatted (fmt-hex resp-exp))))
        (cons 'resp-mant (list (cons 'raw resp-mant) (cons 'formatted (fmt-hex resp-mant))))
        (cons 'max-hops (list (cons 'raw max-hops) (cons 'formatted (number->string max-hops))))
        (cons 'data-len (list (cons 'raw data-len) (cons 'formatted (number->string data-len))))
        (cons 'hf-maddr (list (cons 'raw hf-maddr) (cons 'formatted (fmt-ipv4 hf-maddr))))
        (cons 'saddr (list (cons 'raw saddr) (cons 'formatted (fmt-ipv4 saddr))))
        (cons 'raddr (list (cons 'raw raddr) (cons 'formatted (fmt-ipv4 raddr))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'rspaddr (list (cons 'raw rspaddr) (cons 'formatted (fmt-ipv4 rspaddr))))
        (cons 'grp-recs (list (cons 'raw grp-recs) (cons 'formatted (number->string grp-recs))))
        (cons 'resp-ttl (list (cons 'raw resp-ttl) (cons 'formatted (number->string resp-ttl))))
        (cons 'q-id (list (cons 'raw q-id) (cons 'formatted (number->string q-id))))
        (cons 'q-arrival (list (cons 'raw q-arrival) (cons 'formatted (number->string q-arrival))))
        (cons 'hf-qqic (list (cons 'raw hf-qqic) (cons 'formatted (number->string hf-qqic))))
        (cons 'q-inaddr (list (cons 'raw q-inaddr) (cons 'formatted (fmt-ipv4 q-inaddr))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (number->string src))))
        (cons 'hf-saddr (list (cons 'raw hf-saddr) (cons 'formatted (fmt-ipv4 hf-saddr))))
        (cons 'q-outaddr (list (cons 'raw q-outaddr) (cons 'formatted (fmt-ipv4 q-outaddr))))
        (cons 'resp (list (cons 'raw resp) (cons 'formatted (number->string resp))))
        (cons 'q-prevrtr (list (cons 'raw q-prevrtr) (cons 'formatted (fmt-ipv4 q-prevrtr))))
        (cons 'q-inpkt (list (cons 'raw q-inpkt) (cons 'formatted (number->string q-inpkt))))
        (cons 'hf-reserved (list (cons 'raw hf-reserved) (cons 'formatted (fmt-bytes hf-reserved))))
        (cons 'q-outpkt (list (cons 'raw q-outpkt) (cons 'formatted (number->string q-outpkt))))
        (cons 'q-total (list (cons 'raw q-total) (cons 'formatted (number->string q-total))))
        (cons 'pending (list (cons 'raw pending) (cons 'formatted (number->string pending))))
        (cons 'hf-identifier (list (cons 'raw hf-identifier) (cons 'formatted (number->string hf-identifier))))
        (cons 'q-fwd-ttl (list (cons 'raw q-fwd-ttl) (cons 'formatted (number->string q-fwd-ttl))))
        (cons 'q-mbz (list (cons 'raw q-mbz) (cons 'formatted (fmt-hex q-mbz))))
        (cons 'q-s (list (cons 'raw q-s) (cons 'formatted (fmt-hex q-s))))
        (cons 'q-src-mask (list (cons 'raw q-src-mask) (cons 'formatted (fmt-hex q-src-mask))))
        (cons 'key (list (cons 'raw key) (cons 'formatted (fmt-bytes key))))
        )))

    (catch (e)
      (err (str "IGMP parse error: " e)))))

;; dissect-igmp: parse IGMP from bytevector
;; Returns (ok fields-alist) or (err message)