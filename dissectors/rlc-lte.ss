;; Routines for LTE RLC disassembly
;;
;; Martin Mathieson
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rlc-lte.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rlc_lte.c

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
(def (dissect-rlc-lte buffer)
  "RLC-LTE"
  (try
    (let* (
           (lte-context-am-sn-length (unwrap (read-u8 buffer 0)))
           (lte-context-um-sn-length (unwrap (read-u8 buffer 0)))
           (lte-context-pdu-length (unwrap (read-u16be buffer 0)))
           (lte-context-channel-id (unwrap (read-u16be buffer 0)))
           (lte-context-priority (unwrap (read-u8 buffer 0)))
           (lte-context-ueid (unwrap (read-u16be buffer 0)))
           (lte-am-nacks (unwrap (read-u16be buffer 0)))
           (lte-sequence-analysis-repeated-nack (unwrap (read-u16be buffer 0)))
           (lte-sequence-analysis-expected-sn (unwrap (read-u16be buffer 0)))
           (lte-sequence-analysis-ack-out-of-range-opposite-frame (unwrap (read-u32be buffer 0)))
           (lte-sequence-analysis-ack-out-of-range (unwrap (read-u8 buffer 0)))
           (lte-sequence-analysis-skipped (unwrap (read-u8 buffer 0)))
           (lte-sequence-analysis-repeated (unwrap (read-u8 buffer 0)))
           (lte-sequence-analysis-retx (unwrap (read-u8 buffer 0)))
           (lte-sequence-analysis-mac-retx (unwrap (read-u8 buffer 0)))
           (lte-sequence-analysis-next-frame (unwrap (read-u32be buffer 0)))
           (lte-sequence-analysis-ok (unwrap (read-u8 buffer 0)))
           (lte-sequence-analysis-previous-frame (unwrap (read-u32be buffer 0)))
           (lte-sequence-analysis (unwrap (slice buffer 0 1)))
           (lte-sequence-analysis-framing-info-correct (unwrap (read-u8 buffer 0)))
           (lte-reassembly-source-segment-length (unwrap (read-u32be buffer 0)))
           (lte-reassembly-source-segment-framenum (unwrap (read-u32be buffer 0)))
           (lte-reassembly-source-segment-sn (unwrap (read-u16be buffer 0)))
           (lte-reassembly-source-total-length (unwrap (read-u16be buffer 0)))
           (lte-reassembly-source-number-of-segments (unwrap (read-u16be buffer 0)))
           (lte-reassembly-source (unwrap (slice buffer 0 1)))
           (lte-extension-part (unwrap (slice buffer 0 2)))
           (lte-context (unwrap (slice buffer 0 1)))
           (lte-predefined-pdu (unwrap (slice buffer 0 1)))
           (lte-tm (unwrap (slice buffer 4 1)))
           (lte-tm-data (unwrap (slice buffer 4 1)))
           (lte-um (unwrap (slice buffer 4 1)))
           (lte-um-header (unwrap (slice buffer 4 1)))
           (lte-um-fixed-reserved (unwrap (read-u8 buffer 4)))
           (lte-am (unwrap (slice buffer 10 1)))
           (lte-am-header (unwrap (slice buffer 10 1)))
           (lte-am-data-control (unwrap (read-u8 buffer 10)))
           (lte-am-fixed-reserved2 (unwrap (read-u8 buffer 10)))
           (lte-am-fixed-reserved (unwrap (read-u8 buffer 10)))
           (lte-am-fixed-sn16 (unwrap (read-u16be buffer 11)))
           (lte-am-fixed-sn (unwrap (read-u16be buffer 13)))
           (lte-am-segment-so16 (unwrap (read-u16be buffer 15)))
           (lte-am-segment-so (unwrap (read-u16be buffer 15)))
           )

      (ok (list
        (cons 'lte-context-am-sn-length (list (cons 'raw lte-context-am-sn-length) (cons 'formatted (number->string lte-context-am-sn-length))))
        (cons 'lte-context-um-sn-length (list (cons 'raw lte-context-um-sn-length) (cons 'formatted (number->string lte-context-um-sn-length))))
        (cons 'lte-context-pdu-length (list (cons 'raw lte-context-pdu-length) (cons 'formatted (number->string lte-context-pdu-length))))
        (cons 'lte-context-channel-id (list (cons 'raw lte-context-channel-id) (cons 'formatted (number->string lte-context-channel-id))))
        (cons 'lte-context-priority (list (cons 'raw lte-context-priority) (cons 'formatted (number->string lte-context-priority))))
        (cons 'lte-context-ueid (list (cons 'raw lte-context-ueid) (cons 'formatted (number->string lte-context-ueid))))
        (cons 'lte-am-nacks (list (cons 'raw lte-am-nacks) (cons 'formatted (number->string lte-am-nacks))))
        (cons 'lte-sequence-analysis-repeated-nack (list (cons 'raw lte-sequence-analysis-repeated-nack) (cons 'formatted (number->string lte-sequence-analysis-repeated-nack))))
        (cons 'lte-sequence-analysis-expected-sn (list (cons 'raw lte-sequence-analysis-expected-sn) (cons 'formatted (number->string lte-sequence-analysis-expected-sn))))
        (cons 'lte-sequence-analysis-ack-out-of-range-opposite-frame (list (cons 'raw lte-sequence-analysis-ack-out-of-range-opposite-frame) (cons 'formatted (number->string lte-sequence-analysis-ack-out-of-range-opposite-frame))))
        (cons 'lte-sequence-analysis-ack-out-of-range (list (cons 'raw lte-sequence-analysis-ack-out-of-range) (cons 'formatted (number->string lte-sequence-analysis-ack-out-of-range))))
        (cons 'lte-sequence-analysis-skipped (list (cons 'raw lte-sequence-analysis-skipped) (cons 'formatted (number->string lte-sequence-analysis-skipped))))
        (cons 'lte-sequence-analysis-repeated (list (cons 'raw lte-sequence-analysis-repeated) (cons 'formatted (number->string lte-sequence-analysis-repeated))))
        (cons 'lte-sequence-analysis-retx (list (cons 'raw lte-sequence-analysis-retx) (cons 'formatted (number->string lte-sequence-analysis-retx))))
        (cons 'lte-sequence-analysis-mac-retx (list (cons 'raw lte-sequence-analysis-mac-retx) (cons 'formatted (number->string lte-sequence-analysis-mac-retx))))
        (cons 'lte-sequence-analysis-next-frame (list (cons 'raw lte-sequence-analysis-next-frame) (cons 'formatted (number->string lte-sequence-analysis-next-frame))))
        (cons 'lte-sequence-analysis-ok (list (cons 'raw lte-sequence-analysis-ok) (cons 'formatted (number->string lte-sequence-analysis-ok))))
        (cons 'lte-sequence-analysis-previous-frame (list (cons 'raw lte-sequence-analysis-previous-frame) (cons 'formatted (number->string lte-sequence-analysis-previous-frame))))
        (cons 'lte-sequence-analysis (list (cons 'raw lte-sequence-analysis) (cons 'formatted (utf8->string lte-sequence-analysis))))
        (cons 'lte-sequence-analysis-framing-info-correct (list (cons 'raw lte-sequence-analysis-framing-info-correct) (cons 'formatted (number->string lte-sequence-analysis-framing-info-correct))))
        (cons 'lte-reassembly-source-segment-length (list (cons 'raw lte-reassembly-source-segment-length) (cons 'formatted (number->string lte-reassembly-source-segment-length))))
        (cons 'lte-reassembly-source-segment-framenum (list (cons 'raw lte-reassembly-source-segment-framenum) (cons 'formatted (number->string lte-reassembly-source-segment-framenum))))
        (cons 'lte-reassembly-source-segment-sn (list (cons 'raw lte-reassembly-source-segment-sn) (cons 'formatted (number->string lte-reassembly-source-segment-sn))))
        (cons 'lte-reassembly-source-total-length (list (cons 'raw lte-reassembly-source-total-length) (cons 'formatted (number->string lte-reassembly-source-total-length))))
        (cons 'lte-reassembly-source-number-of-segments (list (cons 'raw lte-reassembly-source-number-of-segments) (cons 'formatted (number->string lte-reassembly-source-number-of-segments))))
        (cons 'lte-reassembly-source (list (cons 'raw lte-reassembly-source) (cons 'formatted (utf8->string lte-reassembly-source))))
        (cons 'lte-extension-part (list (cons 'raw lte-extension-part) (cons 'formatted (utf8->string lte-extension-part))))
        (cons 'lte-context (list (cons 'raw lte-context) (cons 'formatted (utf8->string lte-context))))
        (cons 'lte-predefined-pdu (list (cons 'raw lte-predefined-pdu) (cons 'formatted (fmt-bytes lte-predefined-pdu))))
        (cons 'lte-tm (list (cons 'raw lte-tm) (cons 'formatted (utf8->string lte-tm))))
        (cons 'lte-tm-data (list (cons 'raw lte-tm-data) (cons 'formatted (fmt-bytes lte-tm-data))))
        (cons 'lte-um (list (cons 'raw lte-um) (cons 'formatted (utf8->string lte-um))))
        (cons 'lte-um-header (list (cons 'raw lte-um-header) (cons 'formatted (utf8->string lte-um-header))))
        (cons 'lte-um-fixed-reserved (list (cons 'raw lte-um-fixed-reserved) (cons 'formatted (number->string lte-um-fixed-reserved))))
        (cons 'lte-am (list (cons 'raw lte-am) (cons 'formatted (utf8->string lte-am))))
        (cons 'lte-am-header (list (cons 'raw lte-am-header) (cons 'formatted (utf8->string lte-am-header))))
        (cons 'lte-am-data-control (list (cons 'raw lte-am-data-control) (cons 'formatted (if (= lte-am-data-control 0) "False" "True"))))
        (cons 'lte-am-fixed-reserved2 (list (cons 'raw lte-am-fixed-reserved2) (cons 'formatted (number->string lte-am-fixed-reserved2))))
        (cons 'lte-am-fixed-reserved (list (cons 'raw lte-am-fixed-reserved) (cons 'formatted (number->string lte-am-fixed-reserved))))
        (cons 'lte-am-fixed-sn16 (list (cons 'raw lte-am-fixed-sn16) (cons 'formatted (number->string lte-am-fixed-sn16))))
        (cons 'lte-am-fixed-sn (list (cons 'raw lte-am-fixed-sn) (cons 'formatted (number->string lte-am-fixed-sn))))
        (cons 'lte-am-segment-so16 (list (cons 'raw lte-am-segment-so16) (cons 'formatted (number->string lte-am-segment-so16))))
        (cons 'lte-am-segment-so (list (cons 'raw lte-am-segment-so) (cons 'formatted (number->string lte-am-segment-so))))
        )))

    (catch (e)
      (err (str "RLC-LTE parse error: " e)))))

;; dissect-rlc-lte: parse RLC-LTE from bytevector
;; Returns (ok fields-alist) or (err message)