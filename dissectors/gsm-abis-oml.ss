;; packet-gsm_abis_oml.c
;; Routines for packet dissection of GSM A-bis OML (3GPP TS 12.21)
;; Copyright 2009-2011 by Harald Welte <laforge@gnumonks.org>
;; Copyright 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
;; based on A-bis OML code in OpenBSC
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-abis-oml.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_abis_oml.c

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
(def (dissect-gsm-abis-oml buffer)
  "GSM A-bis OML"
  (try
    (let* (
           (ipa-tres-attr-len (unwrap (read-u16be buffer 0)))
           (ipa-tr-f-qual (unwrap (read-u16be buffer 2)))
           (fom-attr-len (unwrap (read-u16be buffer 2)))
           (ach-btsp (unwrap (read-u8 buffer 2)))
           (ach-tslot (unwrap (read-u8 buffer 2)))
           (ach-sslot (unwrap (read-u8 buffer 2)))
           (arfcn (unwrap (read-u16be buffer 2)))
           (bcch-arfcn (unwrap (read-u16be buffer 2)))
           (bsic (unwrap (read-u16be buffer 2)))
           (gsm-time (unwrap (read-u16be buffer 2)))
           (tei (unwrap (read-u8 buffer 2)))
           (tsc (unwrap (read-u8 buffer 2)))
           (hsn (unwrap (read-u8 buffer 2)))
           (maio (unwrap (read-u8 buffer 2)))
           (fom-attr-val (unwrap (slice buffer 2 1)))
           (ipa-rsl-ip (unwrap (read-u32be buffer 2)))
           (ipa-rsl-port (unwrap (read-u16be buffer 2)))
           (ipa-location-name (unwrap (slice buffer 2 1)))
           (ipa-unit-id (unwrap (slice buffer 2 1)))
           (ipa-unit-name (unwrap (slice buffer 2 1)))
           (ipa-prim-oml-ip (unwrap (read-u32be buffer 2)))
           (ipa-nv-flags (unwrap (read-u16be buffer 2)))
           (ipa-nv-mask (unwrap (read-u16be buffer 2)))
           (ipa-rac (unwrap (read-u8 buffer 2)))
           (ipa-nsei (unwrap (read-u16be buffer 2)))
           (ipa-nsvci (unwrap (read-u16be buffer 2)))
           (ipa-bvci (unwrap (read-u16be buffer 2)))
           (ipa-nsl-dport (unwrap (read-u16be buffer 2)))
           (ipa-nsl-daddr (unwrap (read-u32be buffer 2)))
           (ipa-nsl-sport (unwrap (read-u16be buffer 2)))
           (ipa-tr-f-err (unwrap (read-u16be buffer 4)))
           (ipa-tr-frame-offs (unwrap (read-u16be buffer 6)))
           (manuf-id-len (unwrap (read-u8 buffer 6)))
           (manuf-id-val (unwrap (slice buffer 6 1)))
           (ipa-tr-framenr-offs (unwrap (read-u32be buffer 8)))
           (ipa-tr-cell-id (unwrap (read-u16be buffer 17)))
           (ipa-tr-si2 (unwrap (slice buffer 19 16)))
           (ipa-tr-si2bis (unwrap (slice buffer 35 16)))
           (ipa-tr-si2ter (unwrap (slice buffer 51 16)))
           (ipa-tr-chan-desc (unwrap (slice buffer 67 16)))
           (ipa-tr-arfcn (unwrap (read-u16be buffer 83)))
           (ipa-tr-rxlev (unwrap (read-u16be buffer 83)))
           )

      (ok (list
        (cons 'ipa-tres-attr-len (list (cons 'raw ipa-tres-attr-len) (cons 'formatted (number->string ipa-tres-attr-len))))
        (cons 'ipa-tr-f-qual (list (cons 'raw ipa-tr-f-qual) (cons 'formatted (number->string ipa-tr-f-qual))))
        (cons 'fom-attr-len (list (cons 'raw fom-attr-len) (cons 'formatted (number->string fom-attr-len))))
        (cons 'ach-btsp (list (cons 'raw ach-btsp) (cons 'formatted (number->string ach-btsp))))
        (cons 'ach-tslot (list (cons 'raw ach-tslot) (cons 'formatted (number->string ach-tslot))))
        (cons 'ach-sslot (list (cons 'raw ach-sslot) (cons 'formatted (number->string ach-sslot))))
        (cons 'arfcn (list (cons 'raw arfcn) (cons 'formatted (number->string arfcn))))
        (cons 'bcch-arfcn (list (cons 'raw bcch-arfcn) (cons 'formatted (number->string bcch-arfcn))))
        (cons 'bsic (list (cons 'raw bsic) (cons 'formatted (fmt-hex bsic))))
        (cons 'gsm-time (list (cons 'raw gsm-time) (cons 'formatted (number->string gsm-time))))
        (cons 'tei (list (cons 'raw tei) (cons 'formatted (number->string tei))))
        (cons 'tsc (list (cons 'raw tsc) (cons 'formatted (fmt-hex tsc))))
        (cons 'hsn (list (cons 'raw hsn) (cons 'formatted (number->string hsn))))
        (cons 'maio (list (cons 'raw maio) (cons 'formatted (number->string maio))))
        (cons 'fom-attr-val (list (cons 'raw fom-attr-val) (cons 'formatted (fmt-bytes fom-attr-val))))
        (cons 'ipa-rsl-ip (list (cons 'raw ipa-rsl-ip) (cons 'formatted (fmt-ipv4 ipa-rsl-ip))))
        (cons 'ipa-rsl-port (list (cons 'raw ipa-rsl-port) (cons 'formatted (number->string ipa-rsl-port))))
        (cons 'ipa-location-name (list (cons 'raw ipa-location-name) (cons 'formatted (utf8->string ipa-location-name))))
        (cons 'ipa-unit-id (list (cons 'raw ipa-unit-id) (cons 'formatted (utf8->string ipa-unit-id))))
        (cons 'ipa-unit-name (list (cons 'raw ipa-unit-name) (cons 'formatted (utf8->string ipa-unit-name))))
        (cons 'ipa-prim-oml-ip (list (cons 'raw ipa-prim-oml-ip) (cons 'formatted (fmt-ipv4 ipa-prim-oml-ip))))
        (cons 'ipa-nv-flags (list (cons 'raw ipa-nv-flags) (cons 'formatted (fmt-hex ipa-nv-flags))))
        (cons 'ipa-nv-mask (list (cons 'raw ipa-nv-mask) (cons 'formatted (fmt-hex ipa-nv-mask))))
        (cons 'ipa-rac (list (cons 'raw ipa-rac) (cons 'formatted (fmt-hex ipa-rac))))
        (cons 'ipa-nsei (list (cons 'raw ipa-nsei) (cons 'formatted (number->string ipa-nsei))))
        (cons 'ipa-nsvci (list (cons 'raw ipa-nsvci) (cons 'formatted (number->string ipa-nsvci))))
        (cons 'ipa-bvci (list (cons 'raw ipa-bvci) (cons 'formatted (number->string ipa-bvci))))
        (cons 'ipa-nsl-dport (list (cons 'raw ipa-nsl-dport) (cons 'formatted (number->string ipa-nsl-dport))))
        (cons 'ipa-nsl-daddr (list (cons 'raw ipa-nsl-daddr) (cons 'formatted (fmt-ipv4 ipa-nsl-daddr))))
        (cons 'ipa-nsl-sport (list (cons 'raw ipa-nsl-sport) (cons 'formatted (number->string ipa-nsl-sport))))
        (cons 'ipa-tr-f-err (list (cons 'raw ipa-tr-f-err) (cons 'formatted (number->string ipa-tr-f-err))))
        (cons 'ipa-tr-frame-offs (list (cons 'raw ipa-tr-frame-offs) (cons 'formatted (number->string ipa-tr-frame-offs))))
        (cons 'manuf-id-len (list (cons 'raw manuf-id-len) (cons 'formatted (number->string manuf-id-len))))
        (cons 'manuf-id-val (list (cons 'raw manuf-id-val) (cons 'formatted (utf8->string manuf-id-val))))
        (cons 'ipa-tr-framenr-offs (list (cons 'raw ipa-tr-framenr-offs) (cons 'formatted (number->string ipa-tr-framenr-offs))))
        (cons 'ipa-tr-cell-id (list (cons 'raw ipa-tr-cell-id) (cons 'formatted (fmt-hex ipa-tr-cell-id))))
        (cons 'ipa-tr-si2 (list (cons 'raw ipa-tr-si2) (cons 'formatted (fmt-bytes ipa-tr-si2))))
        (cons 'ipa-tr-si2bis (list (cons 'raw ipa-tr-si2bis) (cons 'formatted (fmt-bytes ipa-tr-si2bis))))
        (cons 'ipa-tr-si2ter (list (cons 'raw ipa-tr-si2ter) (cons 'formatted (fmt-bytes ipa-tr-si2ter))))
        (cons 'ipa-tr-chan-desc (list (cons 'raw ipa-tr-chan-desc) (cons 'formatted (fmt-bytes ipa-tr-chan-desc))))
        (cons 'ipa-tr-arfcn (list (cons 'raw ipa-tr-arfcn) (cons 'formatted (number->string ipa-tr-arfcn))))
        (cons 'ipa-tr-rxlev (list (cons 'raw ipa-tr-rxlev) (cons 'formatted (number->string ipa-tr-rxlev))))
        )))

    (catch (e)
      (err (str "GSM-ABIS-OML parse error: " e)))))

;; dissect-gsm-abis-oml: parse GSM-ABIS-OML from bytevector
;; Returns (ok fields-alist) or (err message)