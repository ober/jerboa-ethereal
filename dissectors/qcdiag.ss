;; packet-qcdiag.c
;; Dissector routines for Qualcomm DIAG packet handling
;;
;;
;; Credits/Sources:
;;
;; - Osmocom Wireshark qcdiag branch
;; https://gitea.osmocom.org/osmocom/wireshark/src/branch/osmocom/qcdiag
;;
;; - Osmocom tools for Qualcomm DIAG
;; https://cgit.osmocom.org/osmo-qcdiag
;;
;; - SCAT: Signaling Collection and Analysis Tool
;; https://github.com/fgsect/scat
;;
;; - Android Tools MSM8996
;; https://github.com/bcyj/android_tools_leeco_msm8996
;;
;; - MobileInsight Core Functionalities
;; https://github.com/mobile-insight/mobileinsight-core
;;
;;
;; (C) 2016-2017 by Harald Welte <laforge@gnumonks.org>
;; (C) 2025 by Oliver Smith <osmith@sysmocom.de>
;; (C) 2026 by Tamas Regos <regost@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/qcdiag.ss
;; Auto-generated from wireshark/epan/dissectors/packet-qcdiag.c

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
(def (dissect-qcdiag buffer)
  "Qualcomm Diagnostic"
  (try
    (let* (
           (verno-comp-date (unwrap (slice buffer 1 11)))
           (verno-comp-time (unwrap (slice buffer 12 8)))
           (verno-rel-date (unwrap (slice buffer 20 11)))
           (verno-rel-time (unwrap (slice buffer 31 8)))
           (verno-ver-dir (unwrap (slice buffer 39 8)))
           (verno-scm (unwrap (read-u8 buffer 47)))
           (verno-mob-cai-rev (unwrap (read-u8 buffer 48)))
           (verno-mob-model (unwrap (read-u8 buffer 49)))
           (verno-mob-firm-rev (unwrap (read-u16be buffer 50)))
           (verno-sci (unwrap (read-u8 buffer 52)))
           (verno-msm-ver (unwrap (slice buffer 53 2)))
           (esn (unwrap (read-u32be buffer 53)))
           (bad-cmd (unwrap (slice buffer 53 1)))
           (bad-parm (unwrap (slice buffer 53 1)))
           (bad-len (unwrap (slice buffer 53 1)))
           (bad-mode (unwrap (slice buffer 53 1)))
           (ts (unwrap (slice buffer 53 8)))
           (parm-set-id (unwrap (read-u16be buffer 53)))
           (parm-set-value (unwrap (read-u32be buffer 55)))
           (parm-set-time (unwrap (slice buffer 55 8)))
           (subsys-cmd-code (unwrap (read-u16be buffer 56)))
           (logcfg-res (unwrap (read-u24be buffer 58)))
           (logcfg-last-item (unwrap (read-u32be buffer 85)))
           (protocol-loopback (unwrap (slice buffer 91 1)))
           (ext-build-id-res (unwrap (read-u16be buffer 92)))
           (ext-build-id-msm (unwrap (read-u32be buffer 94)))
           (ext-build-id-mob-model (unwrap (read-u32be buffer 98)))
           (ext-build-id-sw-rev (unwrap (slice buffer 102 1)))
           (ext-build-id-mob-model-str (unwrap (slice buffer 102 1)))
           )

      (ok (list
        (cons 'verno-comp-date (list (cons 'raw verno-comp-date) (cons 'formatted (utf8->string verno-comp-date))))
        (cons 'verno-comp-time (list (cons 'raw verno-comp-time) (cons 'formatted (utf8->string verno-comp-time))))
        (cons 'verno-rel-date (list (cons 'raw verno-rel-date) (cons 'formatted (utf8->string verno-rel-date))))
        (cons 'verno-rel-time (list (cons 'raw verno-rel-time) (cons 'formatted (utf8->string verno-rel-time))))
        (cons 'verno-ver-dir (list (cons 'raw verno-ver-dir) (cons 'formatted (utf8->string verno-ver-dir))))
        (cons 'verno-scm (list (cons 'raw verno-scm) (cons 'formatted (number->string verno-scm))))
        (cons 'verno-mob-cai-rev (list (cons 'raw verno-mob-cai-rev) (cons 'formatted (number->string verno-mob-cai-rev))))
        (cons 'verno-mob-model (list (cons 'raw verno-mob-model) (cons 'formatted (number->string verno-mob-model))))
        (cons 'verno-mob-firm-rev (list (cons 'raw verno-mob-firm-rev) (cons 'formatted (number->string verno-mob-firm-rev))))
        (cons 'verno-sci (list (cons 'raw verno-sci) (cons 'formatted (number->string verno-sci))))
        (cons 'verno-msm-ver (list (cons 'raw verno-msm-ver) (cons 'formatted (utf8->string verno-msm-ver))))
        (cons 'esn (list (cons 'raw esn) (cons 'formatted (fmt-hex esn))))
        (cons 'bad-cmd (list (cons 'raw bad-cmd) (cons 'formatted (fmt-bytes bad-cmd))))
        (cons 'bad-parm (list (cons 'raw bad-parm) (cons 'formatted (fmt-bytes bad-parm))))
        (cons 'bad-len (list (cons 'raw bad-len) (cons 'formatted (fmt-bytes bad-len))))
        (cons 'bad-mode (list (cons 'raw bad-mode) (cons 'formatted (fmt-bytes bad-mode))))
        (cons 'ts (list (cons 'raw ts) (cons 'formatted (utf8->string ts))))
        (cons 'parm-set-id (list (cons 'raw parm-set-id) (cons 'formatted (fmt-hex parm-set-id))))
        (cons 'parm-set-value (list (cons 'raw parm-set-value) (cons 'formatted (number->string parm-set-value))))
        (cons 'parm-set-time (list (cons 'raw parm-set-time) (cons 'formatted (utf8->string parm-set-time))))
        (cons 'subsys-cmd-code (list (cons 'raw subsys-cmd-code) (cons 'formatted (fmt-hex subsys-cmd-code))))
        (cons 'logcfg-res (list (cons 'raw logcfg-res) (cons 'formatted (number->string logcfg-res))))
        (cons 'logcfg-last-item (list (cons 'raw logcfg-last-item) (cons 'formatted (number->string logcfg-last-item))))
        (cons 'protocol-loopback (list (cons 'raw protocol-loopback) (cons 'formatted (fmt-bytes protocol-loopback))))
        (cons 'ext-build-id-res (list (cons 'raw ext-build-id-res) (cons 'formatted (number->string ext-build-id-res))))
        (cons 'ext-build-id-msm (list (cons 'raw ext-build-id-msm) (cons 'formatted (fmt-hex ext-build-id-msm))))
        (cons 'ext-build-id-mob-model (list (cons 'raw ext-build-id-mob-model) (cons 'formatted (number->string ext-build-id-mob-model))))
        (cons 'ext-build-id-sw-rev (list (cons 'raw ext-build-id-sw-rev) (cons 'formatted (utf8->string ext-build-id-sw-rev))))
        (cons 'ext-build-id-mob-model-str (list (cons 'raw ext-build-id-mob-model-str) (cons 'formatted (utf8->string ext-build-id-mob-model-str))))
        )))

    (catch (e)
      (err (str "QCDIAG parse error: " e)))))

;; dissect-qcdiag: parse QCDIAG from bytevector
;; Returns (ok fields-alist) or (err message)