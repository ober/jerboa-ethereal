;; packet-gsm_abis_om2000.c
;; Routines for packet dissection of Ericsson A-bis OML (OM 2000)
;; Copyright 2010-2012 by Harald Welte <laforge@gnumonks.org>
;;
;; This dissector is not 100% complete, i.e. there are a number of FIXMEs
;; indicating where portions of the protocol are not dissected completely.
;; However, even a partial protocol decode is much more useful than no protocol
;; decode at all...
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-abis-om2000.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_abis_om2000.c

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
(def (dissect-gsm-abis-om2000 buffer)
  "Ericsson A-bis OML"
  (try
    (let* (
           (unknown-val (unwrap (slice buffer 0 1)))
           (isl (unwrap (slice buffer 0 1)))
           (isl-icp1 (unwrap (read-u16be buffer 0)))
           (isl-icp2 (unwrap (read-u16be buffer 2)))
           (conl (unwrap (slice buffer 4 1)))
           (conl-ccp (unwrap (read-u16be buffer 4)))
           (iwd-gen-rev (unwrap (slice buffer 14 6)))
           (cr (unwrap (read-u8 buffer 20)))
           (ipt3 (unwrap (read-u8 buffer 20)))
           (aop (unwrap (read-u8 buffer 20)))
           (filerel-ilr (unwrap (read-u8 buffer 20)))
           (file-rev (unwrap (slice buffer 20 8)))
           (fn-offs (unwrap (read-u16be buffer 28)))
           (bts-manuf (unwrap (slice buffer 30 3)))
           (bts-gen (unwrap (slice buffer 33 3)))
           (bts-rev (unwrap (slice buffer 36 3)))
           (bts-var (unwrap (slice buffer 39 3)))
           (lsc-fm (unwrap (read-u8 buffer 42)))
           (lsc-lsi (unwrap (read-u8 buffer 42)))
           (lsc-lsa (unwrap (read-u8 buffer 42)))
           (attr-index (unwrap (read-u8 buffer 42)))
           (hwinfo-sig (unwrap (read-u16be buffer 45)))
           (capa-sig (unwrap (read-u16be buffer 47)))
           (tf-fs-offset (unwrap (read-u64be buffer 49)))
           (trxc-list (unwrap (read-u16be buffer 54)))
           (max-allowed-power (unwrap (read-u8 buffer 56)))
           (max-allowed-num-trxcs (unwrap (read-u8 buffer 57)))
           (mctr-feat-sts-bitmap (unwrap (slice buffer 58 1)))
           (power-bo-ctype-map (unwrap (slice buffer 58 1)))
           (power-bo-priority (unwrap (slice buffer 58 1)))
           (power-bo-value (unwrap (slice buffer 58 1)))
           (unknown-tag (unwrap (read-u8 buffer 58)))
           (mo-if (unwrap (slice buffer 58 4)))
           (mo-sub1 (unwrap (read-u8 buffer 58)))
           (mo-sub2 (unwrap (read-u8 buffer 58)))
           (mo-instance (unwrap (read-u8 buffer 58)))
           )

      (ok (list
        (cons 'unknown-val (list (cons 'raw unknown-val) (cons 'formatted (fmt-bytes unknown-val))))
        (cons 'isl (list (cons 'raw isl) (cons 'formatted (fmt-bytes isl))))
        (cons 'isl-icp1 (list (cons 'raw isl-icp1) (cons 'formatted (number->string isl-icp1))))
        (cons 'isl-icp2 (list (cons 'raw isl-icp2) (cons 'formatted (number->string isl-icp2))))
        (cons 'conl (list (cons 'raw conl) (cons 'formatted (fmt-bytes conl))))
        (cons 'conl-ccp (list (cons 'raw conl-ccp) (cons 'formatted (number->string conl-ccp))))
        (cons 'iwd-gen-rev (list (cons 'raw iwd-gen-rev) (cons 'formatted (utf8->string iwd-gen-rev))))
        (cons 'cr (list (cons 'raw cr) (cons 'formatted (number->string cr))))
        (cons 'ipt3 (list (cons 'raw ipt3) (cons 'formatted (number->string ipt3))))
        (cons 'aop (list (cons 'raw aop) (cons 'formatted (number->string aop))))
        (cons 'filerel-ilr (list (cons 'raw filerel-ilr) (cons 'formatted (number->string filerel-ilr))))
        (cons 'file-rev (list (cons 'raw file-rev) (cons 'formatted (utf8->string file-rev))))
        (cons 'fn-offs (list (cons 'raw fn-offs) (cons 'formatted (number->string fn-offs))))
        (cons 'bts-manuf (list (cons 'raw bts-manuf) (cons 'formatted (utf8->string bts-manuf))))
        (cons 'bts-gen (list (cons 'raw bts-gen) (cons 'formatted (utf8->string bts-gen))))
        (cons 'bts-rev (list (cons 'raw bts-rev) (cons 'formatted (utf8->string bts-rev))))
        (cons 'bts-var (list (cons 'raw bts-var) (cons 'formatted (utf8->string bts-var))))
        (cons 'lsc-fm (list (cons 'raw lsc-fm) (cons 'formatted (number->string lsc-fm))))
        (cons 'lsc-lsi (list (cons 'raw lsc-lsi) (cons 'formatted (number->string lsc-lsi))))
        (cons 'lsc-lsa (list (cons 'raw lsc-lsa) (cons 'formatted (number->string lsc-lsa))))
        (cons 'attr-index (list (cons 'raw attr-index) (cons 'formatted (number->string attr-index))))
        (cons 'hwinfo-sig (list (cons 'raw hwinfo-sig) (cons 'formatted (fmt-hex hwinfo-sig))))
        (cons 'capa-sig (list (cons 'raw capa-sig) (cons 'formatted (fmt-hex capa-sig))))
        (cons 'tf-fs-offset (list (cons 'raw tf-fs-offset) (cons 'formatted (number->string tf-fs-offset))))
        (cons 'trxc-list (list (cons 'raw trxc-list) (cons 'formatted (fmt-hex trxc-list))))
        (cons 'max-allowed-power (list (cons 'raw max-allowed-power) (cons 'formatted (number->string max-allowed-power))))
        (cons 'max-allowed-num-trxcs (list (cons 'raw max-allowed-num-trxcs) (cons 'formatted (number->string max-allowed-num-trxcs))))
        (cons 'mctr-feat-sts-bitmap (list (cons 'raw mctr-feat-sts-bitmap) (cons 'formatted (fmt-bytes mctr-feat-sts-bitmap))))
        (cons 'power-bo-ctype-map (list (cons 'raw power-bo-ctype-map) (cons 'formatted (fmt-bytes power-bo-ctype-map))))
        (cons 'power-bo-priority (list (cons 'raw power-bo-priority) (cons 'formatted (fmt-bytes power-bo-priority))))
        (cons 'power-bo-value (list (cons 'raw power-bo-value) (cons 'formatted (fmt-bytes power-bo-value))))
        (cons 'unknown-tag (list (cons 'raw unknown-tag) (cons 'formatted (fmt-hex unknown-tag))))
        (cons 'mo-if (list (cons 'raw mo-if) (cons 'formatted (fmt-bytes mo-if))))
        (cons 'mo-sub1 (list (cons 'raw mo-sub1) (cons 'formatted (fmt-hex mo-sub1))))
        (cons 'mo-sub2 (list (cons 'raw mo-sub2) (cons 'formatted (fmt-hex mo-sub2))))
        (cons 'mo-instance (list (cons 'raw mo-instance) (cons 'formatted (number->string mo-instance))))
        )))

    (catch (e)
      (err (str "GSM-ABIS-OM2000 parse error: " e)))))

;; dissect-gsm-abis-om2000: parse GSM-ABIS-OM2000 from bytevector
;; Returns (ok fields-alist) or (err message)