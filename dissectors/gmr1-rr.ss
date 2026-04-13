;; packet-gmr1_rr.c
;;
;; Routines for GMR-1 Radio Resource dissection in wireshark.
;; Copyright (c) 2011 Sylvain Munaut <tnt@246tNt.com>
;;
;; References:
;; [1] ETSI TS 101 376-4-8 V1.3.1 - GMR-1 04.008
;; [2] ETSI TS 101 376-4-8 V2.2.1 - GMPRS-1 04.008
;; [3] ETSI TS 101 376-4-8 V3.1.1 - GMR-1 3G 44.008
;; [4] ETSI TS 100 940 V7.21.0 - GSM 04.08
;; [5] ETSI TS 101 376-4-12 V3.2.1 - GMR-1 3G 44.060
;; [6] ETSI TS 101 376-5-6 V1.3.1 - GMR-1 05.008
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gmr1-rr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gmr1_rr.c

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
(def (dissect-gmr1-rr buffer)
  "GEO-Mobile Radio (1) RR"
  (try
    (let* (
           (message-elements (unwrap (slice buffer 0 1)))
           (ciph-resp-spare (unwrap (read-u8 buffer 32)))
           (l2-pseudo-len (unwrap (read-u8 buffer 32)))
           (page-mode-spare (unwrap (read-u8 buffer 32)))
           (req-ref-ra (unwrap (read-u8 buffer 32)))
           (req-ref-fn (unwrap (read-u8 buffer 32)))
           (tmsi-ptmsi (unwrap (read-u32be buffer 47)))
           (page-info-msc-id (unwrap (read-u8 buffer 62)))
           (pos-display-text (unwrap (slice buffer 62 11)))
           (gps-power-control-params (unwrap (slice buffer 76 5)))
           (msc-id (unwrap (read-u8 buffer 79)))
           (msc-id-spare (unwrap (read-u8 buffer 79)))
           (gps-discr (unwrap (read-u16be buffer 79)))
           (pkt-imm-ass-3-prm-spare (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-3-prm-start-fn (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-3-prm-mac-slot-alloc (unwrap (read-u8 buffer 79)))
           (pkt-freq-prm-spare (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-ac-spare1 (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-ac-final-alloc (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-ac-usf-granularity (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-ac-dl-ctl-mac-slot (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-ac-start-fn (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-ac-mcs (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-ac-tfi (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-ac-spare2 (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-ac-mac-slot-alloc (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-d-chan-mcs-cmd (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-d-chan-mcs-cmd-pnb512 (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-d-spare1 (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-d-rlc-dblk-gnt (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-d-spare2 (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-d-tfi (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-d-usf-granularity (unwrap (read-u8 buffer 79)))
           (pkt-imm-ass-2-prm-d-mac-slot-alloc (unwrap (read-u8 buffer 79)))
           (usf-spare (unwrap (read-u24be buffer 79)))
           (usf-value (unwrap (read-u8 buffer 79)))
           (timing-adv-idx-value (unwrap (read-u8 buffer 79)))
           (timing-adv-idx-spare (unwrap (read-u8 buffer 79)))
           (tlli (unwrap (read-u32be buffer 79)))
           (pkt-pwr-ctrl-prm-spare (unwrap (read-u8 buffer 79)))
           )

      (ok (list
        (cons 'message-elements (list (cons 'raw message-elements) (cons 'formatted (fmt-bytes message-elements))))
        (cons 'ciph-resp-spare (list (cons 'raw ciph-resp-spare) (cons 'formatted (number->string ciph-resp-spare))))
        (cons 'l2-pseudo-len (list (cons 'raw l2-pseudo-len) (cons 'formatted (number->string l2-pseudo-len))))
        (cons 'page-mode-spare (list (cons 'raw page-mode-spare) (cons 'formatted (number->string page-mode-spare))))
        (cons 'req-ref-ra (list (cons 'raw req-ref-ra) (cons 'formatted (fmt-hex req-ref-ra))))
        (cons 'req-ref-fn (list (cons 'raw req-ref-fn) (cons 'formatted (number->string req-ref-fn))))
        (cons 'tmsi-ptmsi (list (cons 'raw tmsi-ptmsi) (cons 'formatted (fmt-hex tmsi-ptmsi))))
        (cons 'page-info-msc-id (list (cons 'raw page-info-msc-id) (cons 'formatted (number->string page-info-msc-id))))
        (cons 'pos-display-text (list (cons 'raw pos-display-text) (cons 'formatted (utf8->string pos-display-text))))
        (cons 'gps-power-control-params (list (cons 'raw gps-power-control-params) (cons 'formatted (fmt-bytes gps-power-control-params))))
        (cons 'msc-id (list (cons 'raw msc-id) (cons 'formatted (number->string msc-id))))
        (cons 'msc-id-spare (list (cons 'raw msc-id-spare) (cons 'formatted (number->string msc-id-spare))))
        (cons 'gps-discr (list (cons 'raw gps-discr) (cons 'formatted (fmt-hex gps-discr))))
        (cons 'pkt-imm-ass-3-prm-spare (list (cons 'raw pkt-imm-ass-3-prm-spare) (cons 'formatted (number->string pkt-imm-ass-3-prm-spare))))
        (cons 'pkt-imm-ass-3-prm-start-fn (list (cons 'raw pkt-imm-ass-3-prm-start-fn) (cons 'formatted (number->string pkt-imm-ass-3-prm-start-fn))))
        (cons 'pkt-imm-ass-3-prm-mac-slot-alloc (list (cons 'raw pkt-imm-ass-3-prm-mac-slot-alloc) (cons 'formatted (fmt-hex pkt-imm-ass-3-prm-mac-slot-alloc))))
        (cons 'pkt-freq-prm-spare (list (cons 'raw pkt-freq-prm-spare) (cons 'formatted (number->string pkt-freq-prm-spare))))
        (cons 'pkt-imm-ass-2-prm-ac-spare1 (list (cons 'raw pkt-imm-ass-2-prm-ac-spare1) (cons 'formatted (number->string pkt-imm-ass-2-prm-ac-spare1))))
        (cons 'pkt-imm-ass-2-prm-ac-final-alloc (list (cons 'raw pkt-imm-ass-2-prm-ac-final-alloc) (cons 'formatted (number->string pkt-imm-ass-2-prm-ac-final-alloc))))
        (cons 'pkt-imm-ass-2-prm-ac-usf-granularity (list (cons 'raw pkt-imm-ass-2-prm-ac-usf-granularity) (cons 'formatted (number->string pkt-imm-ass-2-prm-ac-usf-granularity))))
        (cons 'pkt-imm-ass-2-prm-ac-dl-ctl-mac-slot (list (cons 'raw pkt-imm-ass-2-prm-ac-dl-ctl-mac-slot) (cons 'formatted (number->string pkt-imm-ass-2-prm-ac-dl-ctl-mac-slot))))
        (cons 'pkt-imm-ass-2-prm-ac-start-fn (list (cons 'raw pkt-imm-ass-2-prm-ac-start-fn) (cons 'formatted (number->string pkt-imm-ass-2-prm-ac-start-fn))))
        (cons 'pkt-imm-ass-2-prm-ac-mcs (list (cons 'raw pkt-imm-ass-2-prm-ac-mcs) (cons 'formatted (number->string pkt-imm-ass-2-prm-ac-mcs))))
        (cons 'pkt-imm-ass-2-prm-ac-tfi (list (cons 'raw pkt-imm-ass-2-prm-ac-tfi) (cons 'formatted (fmt-hex pkt-imm-ass-2-prm-ac-tfi))))
        (cons 'pkt-imm-ass-2-prm-ac-spare2 (list (cons 'raw pkt-imm-ass-2-prm-ac-spare2) (cons 'formatted (fmt-hex pkt-imm-ass-2-prm-ac-spare2))))
        (cons 'pkt-imm-ass-2-prm-ac-mac-slot-alloc (list (cons 'raw pkt-imm-ass-2-prm-ac-mac-slot-alloc) (cons 'formatted (fmt-hex pkt-imm-ass-2-prm-ac-mac-slot-alloc))))
        (cons 'pkt-imm-ass-2-prm-d-chan-mcs-cmd (list (cons 'raw pkt-imm-ass-2-prm-d-chan-mcs-cmd) (cons 'formatted (fmt-hex pkt-imm-ass-2-prm-d-chan-mcs-cmd))))
        (cons 'pkt-imm-ass-2-prm-d-chan-mcs-cmd-pnb512 (list (cons 'raw pkt-imm-ass-2-prm-d-chan-mcs-cmd-pnb512) (cons 'formatted (fmt-hex pkt-imm-ass-2-prm-d-chan-mcs-cmd-pnb512))))
        (cons 'pkt-imm-ass-2-prm-d-spare1 (list (cons 'raw pkt-imm-ass-2-prm-d-spare1) (cons 'formatted (fmt-hex pkt-imm-ass-2-prm-d-spare1))))
        (cons 'pkt-imm-ass-2-prm-d-rlc-dblk-gnt (list (cons 'raw pkt-imm-ass-2-prm-d-rlc-dblk-gnt) (cons 'formatted (number->string pkt-imm-ass-2-prm-d-rlc-dblk-gnt))))
        (cons 'pkt-imm-ass-2-prm-d-spare2 (list (cons 'raw pkt-imm-ass-2-prm-d-spare2) (cons 'formatted (fmt-hex pkt-imm-ass-2-prm-d-spare2))))
        (cons 'pkt-imm-ass-2-prm-d-tfi (list (cons 'raw pkt-imm-ass-2-prm-d-tfi) (cons 'formatted (fmt-hex pkt-imm-ass-2-prm-d-tfi))))
        (cons 'pkt-imm-ass-2-prm-d-usf-granularity (list (cons 'raw pkt-imm-ass-2-prm-d-usf-granularity) (cons 'formatted (number->string pkt-imm-ass-2-prm-d-usf-granularity))))
        (cons 'pkt-imm-ass-2-prm-d-mac-slot-alloc (list (cons 'raw pkt-imm-ass-2-prm-d-mac-slot-alloc) (cons 'formatted (fmt-hex pkt-imm-ass-2-prm-d-mac-slot-alloc))))
        (cons 'usf-spare (list (cons 'raw usf-spare) (cons 'formatted (number->string usf-spare))))
        (cons 'usf-value (list (cons 'raw usf-value) (cons 'formatted (fmt-hex usf-value))))
        (cons 'timing-adv-idx-value (list (cons 'raw timing-adv-idx-value) (cons 'formatted (number->string timing-adv-idx-value))))
        (cons 'timing-adv-idx-spare (list (cons 'raw timing-adv-idx-spare) (cons 'formatted (number->string timing-adv-idx-spare))))
        (cons 'tlli (list (cons 'raw tlli) (cons 'formatted (fmt-hex tlli))))
        (cons 'pkt-pwr-ctrl-prm-spare (list (cons 'raw pkt-pwr-ctrl-prm-spare) (cons 'formatted (number->string pkt-pwr-ctrl-prm-spare))))
        )))

    (catch (e)
      (err (str "GMR1-RR parse error: " e)))))

;; dissect-gmr1-rr: parse GMR1-RR from bytevector
;; Returns (ok fields-alist) or (err message)