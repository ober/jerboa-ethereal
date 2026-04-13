;; packet-geonw.c
;; Routines for GeoNetworking and BTP-A/B dissection
;; Coyright 2018, C. Guerber <cguerber@yahoo.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/geonw.ss
;; Auto-generated from wireshark/epan/dissectors/packet-geonw.c

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
(def (dissect-geonw buffer)
  "BTP-A"
  (try
    (let* (
           (dstport (unwrap (read-u16be buffer 0)))
           (bh-version (unwrap (read-u8 buffer 0)))
           (ch-reserved1 (unwrap (read-u8 buffer 0)))
           (bh-reserved (unwrap (read-u8 buffer 1)))
           (dstport-info (unwrap (read-u16be buffer 2)))
           (port (unwrap (read-u16be buffer 2)))
           (srcport (unwrap (read-u16be buffer 2)))
           (bh-life-time (unwrap (read-u8 buffer 2)))
           (bh-lt-mult (unwrap (read-u8 buffer 2)))
           (ch-traffic-class (unwrap (read-u8 buffer 2)))
           (ch-tc-scf (unwrap (read-u8 buffer 2)))
           (ch-tc-offload (unwrap (read-u8 buffer 2)))
           (bh-remain-hop-limit (unwrap (read-u8 buffer 3)))
           (ch-flags-mob (unwrap (read-u8 buffer 3)))
           (ch-flags-reserved (unwrap (read-u8 buffer 3)))
           (ch-payload-length (unwrap (read-u16be buffer 4)))
           (ch-max-hop-limit (unwrap (read-u8 buffer 6)))
           (ch-reserved2 (unwrap (read-u8 buffer 7)))
           (seq-num (unwrap (read-u16be buffer 8)))
           (reserved (unwrap (read-u16be buffer 10)))
           (so-pv (unwrap (slice buffer 12 24)))
           (so-pv-addr (unwrap (slice buffer 12 8)))
           (so-pv-addr-manual (unwrap (read-u8 buffer 12)))
           (so-pv-addr-mid (unwrap (slice buffer 14 6)))
           (so-pv-pai (unwrap (read-u8 buffer 32)))
           (de-pv (unwrap (slice buffer 36 20)))
           (de-pv-addr (unwrap (slice buffer 36 8)))
           (de-pv-addr-manual (unwrap (read-u8 buffer 36)))
           (de-pv-addr-mid (unwrap (slice buffer 38 6)))
           (dccmco-reserved (unwrap (read-u8 buffer 56)))
           (shb-reserved (unwrap (read-u32be buffer 56)))
           (gxc-reserved (unwrap (read-u16be buffer 80)))
           (lsrq-addr (unwrap (slice buffer 82 8)))
           (lsrq-addr-manual (unwrap (read-u8 buffer 82)))
           (lsrq-addr-mid (unwrap (slice buffer 84 6)))
           (version (unwrap (read-u8 buffer 89)))
           (profile (unwrap (read-u8 buffer 90)))
           (time64 (unwrap (read-u64be buffer 100)))
           (conf (unwrap (read-u8 buffer 100)))
           (time32 (unwrap (read-u32be buffer 109)))
           (lat (unwrap (read-u32be buffer 113)))
           (lon (unwrap (read-u32be buffer 113)))
           (hashedid3 (unwrap (slice buffer 123 3)))
           (msg-id (unwrap (read-u16be buffer 126)))
           (opaque (unwrap (slice buffer 129 1)))
           )

      (ok (list
        (cons 'dstport (list (cons 'raw dstport) (cons 'formatted (fmt-port dstport))))
        (cons 'bh-version (list (cons 'raw bh-version) (cons 'formatted (number->string bh-version))))
        (cons 'ch-reserved1 (list (cons 'raw ch-reserved1) (cons 'formatted (fmt-hex ch-reserved1))))
        (cons 'bh-reserved (list (cons 'raw bh-reserved) (cons 'formatted (fmt-hex bh-reserved))))
        (cons 'dstport-info (list (cons 'raw dstport-info) (cons 'formatted (fmt-hex dstport-info))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (fmt-port port))))
        (cons 'srcport (list (cons 'raw srcport) (cons 'formatted (fmt-port srcport))))
        (cons 'bh-life-time (list (cons 'raw bh-life-time) (cons 'formatted (number->string bh-life-time))))
        (cons 'bh-lt-mult (list (cons 'raw bh-lt-mult) (cons 'formatted (number->string bh-lt-mult))))
        (cons 'ch-traffic-class (list (cons 'raw ch-traffic-class) (cons 'formatted (number->string ch-traffic-class))))
        (cons 'ch-tc-scf (list (cons 'raw ch-tc-scf) (cons 'formatted (number->string ch-tc-scf))))
        (cons 'ch-tc-offload (list (cons 'raw ch-tc-offload) (cons 'formatted (number->string ch-tc-offload))))
        (cons 'bh-remain-hop-limit (list (cons 'raw bh-remain-hop-limit) (cons 'formatted (number->string bh-remain-hop-limit))))
        (cons 'ch-flags-mob (list (cons 'raw ch-flags-mob) (cons 'formatted (number->string ch-flags-mob))))
        (cons 'ch-flags-reserved (list (cons 'raw ch-flags-reserved) (cons 'formatted (number->string ch-flags-reserved))))
        (cons 'ch-payload-length (list (cons 'raw ch-payload-length) (cons 'formatted (number->string ch-payload-length))))
        (cons 'ch-max-hop-limit (list (cons 'raw ch-max-hop-limit) (cons 'formatted (number->string ch-max-hop-limit))))
        (cons 'ch-reserved2 (list (cons 'raw ch-reserved2) (cons 'formatted (fmt-hex ch-reserved2))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (number->string seq-num))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'so-pv (list (cons 'raw so-pv) (cons 'formatted (fmt-bytes so-pv))))
        (cons 'so-pv-addr (list (cons 'raw so-pv-addr) (cons 'formatted (fmt-bytes so-pv-addr))))
        (cons 'so-pv-addr-manual (list (cons 'raw so-pv-addr-manual) (cons 'formatted (number->string so-pv-addr-manual))))
        (cons 'so-pv-addr-mid (list (cons 'raw so-pv-addr-mid) (cons 'formatted (fmt-mac so-pv-addr-mid))))
        (cons 'so-pv-pai (list (cons 'raw so-pv-pai) (cons 'formatted (number->string so-pv-pai))))
        (cons 'de-pv (list (cons 'raw de-pv) (cons 'formatted (fmt-bytes de-pv))))
        (cons 'de-pv-addr (list (cons 'raw de-pv-addr) (cons 'formatted (fmt-bytes de-pv-addr))))
        (cons 'de-pv-addr-manual (list (cons 'raw de-pv-addr-manual) (cons 'formatted (number->string de-pv-addr-manual))))
        (cons 'de-pv-addr-mid (list (cons 'raw de-pv-addr-mid) (cons 'formatted (fmt-mac de-pv-addr-mid))))
        (cons 'dccmco-reserved (list (cons 'raw dccmco-reserved) (cons 'formatted (number->string dccmco-reserved))))
        (cons 'shb-reserved (list (cons 'raw shb-reserved) (cons 'formatted (number->string shb-reserved))))
        (cons 'gxc-reserved (list (cons 'raw gxc-reserved) (cons 'formatted (number->string gxc-reserved))))
        (cons 'lsrq-addr (list (cons 'raw lsrq-addr) (cons 'formatted (fmt-bytes lsrq-addr))))
        (cons 'lsrq-addr-manual (list (cons 'raw lsrq-addr-manual) (cons 'formatted (number->string lsrq-addr-manual))))
        (cons 'lsrq-addr-mid (list (cons 'raw lsrq-addr-mid) (cons 'formatted (fmt-mac lsrq-addr-mid))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'profile (list (cons 'raw profile) (cons 'formatted (number->string profile))))
        (cons 'time64 (list (cons 'raw time64) (cons 'formatted (number->string time64))))
        (cons 'conf (list (cons 'raw conf) (cons 'formatted (number->string conf))))
        (cons 'time32 (list (cons 'raw time32) (cons 'formatted (number->string time32))))
        (cons 'lat (list (cons 'raw lat) (cons 'formatted (number->string lat))))
        (cons 'lon (list (cons 'raw lon) (cons 'formatted (number->string lon))))
        (cons 'hashedid3 (list (cons 'raw hashedid3) (cons 'formatted (fmt-bytes hashedid3))))
        (cons 'msg-id (list (cons 'raw msg-id) (cons 'formatted (number->string msg-id))))
        (cons 'opaque (list (cons 'raw opaque) (cons 'formatted (fmt-bytes opaque))))
        )))

    (catch (e)
      (err (str "GEONW parse error: " e)))))

;; dissect-geonw: parse GEONW from bytevector
;; Returns (ok fields-alist) or (err message)