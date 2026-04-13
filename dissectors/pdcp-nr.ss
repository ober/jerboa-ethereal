;; packet-pdcp-nr.c
;; Routines for nr PDCP
;;
;; Martin Mathieson
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pdcp-nr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pdcp_nr.c

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
(def (dissect-pdcp-nr buffer)
  "PDCP-NR"
  (try
    (let* (
           (nr-security-setup-frame (unwrap (read-u32be buffer 0)))
           (nr-security (unwrap (slice buffer 0 1)))
           (nr-security-integrity-data (unwrap (slice buffer 0 1)))
           (nr-large-cid-present (unwrap (read-u8 buffer 0)))
           (nr-cid-inclusion-info (unwrap (read-u8 buffer 0)))
           (nr-rohc-udp-checksum-present (unwrap (read-u8 buffer 0)))
           (nr-rohc-rnd (unwrap (read-u8 buffer 0)))
           (nr-rohc-compression (unwrap (read-u8 buffer 0)))
           (nr-sdap (unwrap (read-u8 buffer 0)))
           (nr-ciphering-disabled (unwrap (read-u8 buffer 0)))
           (nr-maci-present (unwrap (read-u8 buffer 0)))
           (nr-seqnum-length (unwrap (read-u8 buffer 0)))
           (nr-bearer-id (unwrap (read-u8 buffer 0)))
           (nr-ueid (unwrap (read-u16be buffer 0)))
           (nr-configuration (unwrap (slice buffer 0 1)))
           (nr-security-integrity-key-setup-frame (unwrap (read-u32be buffer 0)))
           (nr-security-integrity-key (unwrap (slice buffer 0 1)))
           (nr-security-cipher-key-setup-frame (unwrap (read-u32be buffer 0)))
           (nr-security-cipher-key (unwrap (slice buffer 0 1)))
           (nr-security-count (unwrap (read-u32be buffer 0)))
           (nr-security-bearer (unwrap (read-u8 buffer 0)))
           (nr-sequence-analysis-repeated (unwrap (read-u8 buffer 0)))
           (nr-sequence-analysis-skipped (unwrap (read-u8 buffer 0)))
           (nr-sequence-analysis-next-frame (unwrap (read-u32be buffer 0)))
           (nr-sequence-analysis-ok (unwrap (read-u8 buffer 0)))
           (nr-sequence-analysis-expected-sn (unwrap (read-u32be buffer 0)))
           (nr-sequence-analysis-previous-frame (unwrap (read-u32be buffer 0)))
           (nr-sequence-analysis (unwrap (slice buffer 0 1)))
           (nr-control-plane-reserved (unwrap (read-u8 buffer 0)))
           (nr-data-control (unwrap (read-u8 buffer 2)))
           (nr-reserved3 (unwrap (read-u8 buffer 2)))
           (nr-seq-num-12 (unwrap (read-u16be buffer 2)))
           (nr-reserved5 (unwrap (read-u8 buffer 4)))
           (nr-seq-num-18 (unwrap (read-u24be buffer 4)))
           (nr-reserved4 (unwrap (read-u8 buffer 7)))
           (nr-fmc (unwrap (read-u32be buffer 7)))
           )

      (ok (list
        (cons 'nr-security-setup-frame (list (cons 'raw nr-security-setup-frame) (cons 'formatted (number->string nr-security-setup-frame))))
        (cons 'nr-security (list (cons 'raw nr-security) (cons 'formatted (utf8->string nr-security))))
        (cons 'nr-security-integrity-data (list (cons 'raw nr-security-integrity-data) (cons 'formatted (fmt-bytes nr-security-integrity-data))))
        (cons 'nr-large-cid-present (list (cons 'raw nr-large-cid-present) (cons 'formatted (number->string nr-large-cid-present))))
        (cons 'nr-cid-inclusion-info (list (cons 'raw nr-cid-inclusion-info) (cons 'formatted (number->string nr-cid-inclusion-info))))
        (cons 'nr-rohc-udp-checksum-present (list (cons 'raw nr-rohc-udp-checksum-present) (cons 'formatted (number->string nr-rohc-udp-checksum-present))))
        (cons 'nr-rohc-rnd (list (cons 'raw nr-rohc-rnd) (cons 'formatted (number->string nr-rohc-rnd))))
        (cons 'nr-rohc-compression (list (cons 'raw nr-rohc-compression) (cons 'formatted (number->string nr-rohc-compression))))
        (cons 'nr-sdap (list (cons 'raw nr-sdap) (cons 'formatted (if (= nr-sdap 0) "False" "True"))))
        (cons 'nr-ciphering-disabled (list (cons 'raw nr-ciphering-disabled) (cons 'formatted (number->string nr-ciphering-disabled))))
        (cons 'nr-maci-present (list (cons 'raw nr-maci-present) (cons 'formatted (number->string nr-maci-present))))
        (cons 'nr-seqnum-length (list (cons 'raw nr-seqnum-length) (cons 'formatted (number->string nr-seqnum-length))))
        (cons 'nr-bearer-id (list (cons 'raw nr-bearer-id) (cons 'formatted (number->string nr-bearer-id))))
        (cons 'nr-ueid (list (cons 'raw nr-ueid) (cons 'formatted (number->string nr-ueid))))
        (cons 'nr-configuration (list (cons 'raw nr-configuration) (cons 'formatted (utf8->string nr-configuration))))
        (cons 'nr-security-integrity-key-setup-frame (list (cons 'raw nr-security-integrity-key-setup-frame) (cons 'formatted (number->string nr-security-integrity-key-setup-frame))))
        (cons 'nr-security-integrity-key (list (cons 'raw nr-security-integrity-key) (cons 'formatted (utf8->string nr-security-integrity-key))))
        (cons 'nr-security-cipher-key-setup-frame (list (cons 'raw nr-security-cipher-key-setup-frame) (cons 'formatted (number->string nr-security-cipher-key-setup-frame))))
        (cons 'nr-security-cipher-key (list (cons 'raw nr-security-cipher-key) (cons 'formatted (utf8->string nr-security-cipher-key))))
        (cons 'nr-security-count (list (cons 'raw nr-security-count) (cons 'formatted (number->string nr-security-count))))
        (cons 'nr-security-bearer (list (cons 'raw nr-security-bearer) (cons 'formatted (number->string nr-security-bearer))))
        (cons 'nr-sequence-analysis-repeated (list (cons 'raw nr-sequence-analysis-repeated) (cons 'formatted (number->string nr-sequence-analysis-repeated))))
        (cons 'nr-sequence-analysis-skipped (list (cons 'raw nr-sequence-analysis-skipped) (cons 'formatted (number->string nr-sequence-analysis-skipped))))
        (cons 'nr-sequence-analysis-next-frame (list (cons 'raw nr-sequence-analysis-next-frame) (cons 'formatted (number->string nr-sequence-analysis-next-frame))))
        (cons 'nr-sequence-analysis-ok (list (cons 'raw nr-sequence-analysis-ok) (cons 'formatted (number->string nr-sequence-analysis-ok))))
        (cons 'nr-sequence-analysis-expected-sn (list (cons 'raw nr-sequence-analysis-expected-sn) (cons 'formatted (number->string nr-sequence-analysis-expected-sn))))
        (cons 'nr-sequence-analysis-previous-frame (list (cons 'raw nr-sequence-analysis-previous-frame) (cons 'formatted (number->string nr-sequence-analysis-previous-frame))))
        (cons 'nr-sequence-analysis (list (cons 'raw nr-sequence-analysis) (cons 'formatted (utf8->string nr-sequence-analysis))))
        (cons 'nr-control-plane-reserved (list (cons 'raw nr-control-plane-reserved) (cons 'formatted (number->string nr-control-plane-reserved))))
        (cons 'nr-data-control (list (cons 'raw nr-data-control) (cons 'formatted (if (= nr-data-control 0) "False" "True"))))
        (cons 'nr-reserved3 (list (cons 'raw nr-reserved3) (cons 'formatted (fmt-hex nr-reserved3))))
        (cons 'nr-seq-num-12 (list (cons 'raw nr-seq-num-12) (cons 'formatted (number->string nr-seq-num-12))))
        (cons 'nr-reserved5 (list (cons 'raw nr-reserved5) (cons 'formatted (fmt-hex nr-reserved5))))
        (cons 'nr-seq-num-18 (list (cons 'raw nr-seq-num-18) (cons 'formatted (number->string nr-seq-num-18))))
        (cons 'nr-reserved4 (list (cons 'raw nr-reserved4) (cons 'formatted (fmt-hex nr-reserved4))))
        (cons 'nr-fmc (list (cons 'raw nr-fmc) (cons 'formatted (number->string nr-fmc))))
        )))

    (catch (e)
      (err (str "PDCP-NR parse error: " e)))))

;; dissect-pdcp-nr: parse PDCP-NR from bytevector
;; Returns (ok fields-alist) or (err message)