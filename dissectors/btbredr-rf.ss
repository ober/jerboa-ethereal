;; packet-btbredr_rf.c
;; Routines for Bluetooth Pseudoheader for BR/EDR Baseband
;;
;; Copyright 2020, Thomas Sailer <t.sailer@alumni.ethz.ch>
;; Copyright 2014, Michal Labedzki for Tieto Corporation
;; Copyright 2014, Dominic Spill <dominicgs@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btbredr-rf.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btbredr_rf.c

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
(def (dissect-btbredr-rf buffer)
  "Bluetooth Pseudoheader for BR/EDR"
  (try
    (let* (
           (address-offenses (unwrap (read-u8 buffer 3)))
           (transport-rate-ignored (unwrap (read-u8 buffer 4)))
           (transport-rate (unwrap (read-u8 buffer 4)))
           (header-bits (unwrap (read-u8 buffer 5)))
           (payload-bits (unwrap (read-u16be buffer 6)))
           (address-part (unwrap (read-u32be buffer 8)))
           (packet-header (unwrap (read-u32be buffer 16)))
           (header (unwrap (read-u32be buffer 16)))
           (header-reserved (unwrap (read-u32be buffer 16)))
           (header-broken-lt-addr (unwrap (read-u32be buffer 16)))
           (header-broken-type (unwrap (read-u32be buffer 16)))
           (header-broken-flow-control (unwrap (read-u8 buffer 16)))
           (header-broken-acknowledge-indication (unwrap (read-u8 buffer 16)))
           (header-broken-sequence-number (unwrap (read-u8 buffer 16)))
           (header-broken-header-error-check (unwrap (read-u32be buffer 16)))
           (header-lt-addr (unwrap (read-u32be buffer 16)))
           (header-type (unwrap (read-u32be buffer 16)))
           (header-flow-control (unwrap (read-u8 buffer 16)))
           (header-acknowledge-indication (unwrap (read-u8 buffer 16)))
           (header-sequence-number (unwrap (read-u8 buffer 16)))
           (header-header-error-check (unwrap (read-u32be buffer 16)))
           (hf-flags (unwrap (read-u16be buffer 20)))
           (reserved-15-14 (unwrap (read-u16be buffer 20)))
           (mic-pass (unwrap (read-u8 buffer 20)))
           (mic-checked (unwrap (read-u8 buffer 20)))
           (crc-pass (unwrap (read-u8 buffer 20)))
           (crc-checked (unwrap (read-u8 buffer 20)))
           (hec-pass (unwrap (read-u8 buffer 20)))
           (hec-checked (unwrap (read-u8 buffer 20)))
           (reference-upper-address-part-valid (unwrap (read-u8 buffer 20)))
           (rf-channel-aliasing (unwrap (read-u8 buffer 20)))
           (br-edr-data-present (unwrap (read-u8 buffer 20)))
           (reference-lower-address-part-valid (unwrap (read-u8 buffer 20)))
           (bredr-payload-decrypted (unwrap (read-u8 buffer 20)))
           (noise-power-valid (unwrap (read-u8 buffer 20)))
           (signal-power-valid (unwrap (read-u8 buffer 20)))
           (packet-header-and-br-edr-payload-dewhitened (unwrap (read-u8 buffer 20)))
           (header1 (unwrap (read-u8 buffer 24)))
           (header1-llid (unwrap (read-u8 buffer 24)))
           (header1-flow (unwrap (read-u8 buffer 24)))
           (header1-length (unwrap (read-u8 buffer 24)))
           (header2 (unwrap (read-u16be buffer 24)))
           (header2-llid (unwrap (read-u16be buffer 24)))
           (header2-flow (unwrap (read-u16be buffer 24)))
           (header2-length (unwrap (read-u16be buffer 24)))
           (header2-rfu (unwrap (read-u16be buffer 24)))
           (hf-crc (unwrap (read-u16be buffer 24)))
           )

      (ok (list
        (cons 'address-offenses (list (cons 'raw address-offenses) (cons 'formatted (number->string address-offenses))))
        (cons 'transport-rate-ignored (list (cons 'raw transport-rate-ignored) (cons 'formatted (fmt-hex transport-rate-ignored))))
        (cons 'transport-rate (list (cons 'raw transport-rate) (cons 'formatted (fmt-hex transport-rate))))
        (cons 'header-bits (list (cons 'raw header-bits) (cons 'formatted (number->string header-bits))))
        (cons 'payload-bits (list (cons 'raw payload-bits) (cons 'formatted (number->string payload-bits))))
        (cons 'address-part (list (cons 'raw address-part) (cons 'formatted (fmt-hex address-part))))
        (cons 'packet-header (list (cons 'raw packet-header) (cons 'formatted (fmt-hex packet-header))))
        (cons 'header (list (cons 'raw header) (cons 'formatted (fmt-hex header))))
        (cons 'header-reserved (list (cons 'raw header-reserved) (cons 'formatted (fmt-hex header-reserved))))
        (cons 'header-broken-lt-addr (list (cons 'raw header-broken-lt-addr) (cons 'formatted (fmt-hex header-broken-lt-addr))))
        (cons 'header-broken-type (list (cons 'raw header-broken-type) (cons 'formatted (fmt-hex header-broken-type))))
        (cons 'header-broken-flow-control (list (cons 'raw header-broken-flow-control) (cons 'formatted (number->string header-broken-flow-control))))
        (cons 'header-broken-acknowledge-indication (list (cons 'raw header-broken-acknowledge-indication) (cons 'formatted (number->string header-broken-acknowledge-indication))))
        (cons 'header-broken-sequence-number (list (cons 'raw header-broken-sequence-number) (cons 'formatted (number->string header-broken-sequence-number))))
        (cons 'header-broken-header-error-check (list (cons 'raw header-broken-header-error-check) (cons 'formatted (fmt-hex header-broken-header-error-check))))
        (cons 'header-lt-addr (list (cons 'raw header-lt-addr) (cons 'formatted (fmt-hex header-lt-addr))))
        (cons 'header-type (list (cons 'raw header-type) (cons 'formatted (fmt-hex header-type))))
        (cons 'header-flow-control (list (cons 'raw header-flow-control) (cons 'formatted (number->string header-flow-control))))
        (cons 'header-acknowledge-indication (list (cons 'raw header-acknowledge-indication) (cons 'formatted (number->string header-acknowledge-indication))))
        (cons 'header-sequence-number (list (cons 'raw header-sequence-number) (cons 'formatted (number->string header-sequence-number))))
        (cons 'header-header-error-check (list (cons 'raw header-header-error-check) (cons 'formatted (fmt-hex header-header-error-check))))
        (cons 'hf-flags (list (cons 'raw hf-flags) (cons 'formatted (fmt-hex hf-flags))))
        (cons 'reserved-15-14 (list (cons 'raw reserved-15-14) (cons 'formatted (fmt-hex reserved-15-14))))
        (cons 'mic-pass (list (cons 'raw mic-pass) (cons 'formatted (number->string mic-pass))))
        (cons 'mic-checked (list (cons 'raw mic-checked) (cons 'formatted (number->string mic-checked))))
        (cons 'crc-pass (list (cons 'raw crc-pass) (cons 'formatted (number->string crc-pass))))
        (cons 'crc-checked (list (cons 'raw crc-checked) (cons 'formatted (number->string crc-checked))))
        (cons 'hec-pass (list (cons 'raw hec-pass) (cons 'formatted (number->string hec-pass))))
        (cons 'hec-checked (list (cons 'raw hec-checked) (cons 'formatted (number->string hec-checked))))
        (cons 'reference-upper-address-part-valid (list (cons 'raw reference-upper-address-part-valid) (cons 'formatted (number->string reference-upper-address-part-valid))))
        (cons 'rf-channel-aliasing (list (cons 'raw rf-channel-aliasing) (cons 'formatted (number->string rf-channel-aliasing))))
        (cons 'br-edr-data-present (list (cons 'raw br-edr-data-present) (cons 'formatted (number->string br-edr-data-present))))
        (cons 'reference-lower-address-part-valid (list (cons 'raw reference-lower-address-part-valid) (cons 'formatted (number->string reference-lower-address-part-valid))))
        (cons 'bredr-payload-decrypted (list (cons 'raw bredr-payload-decrypted) (cons 'formatted (number->string bredr-payload-decrypted))))
        (cons 'noise-power-valid (list (cons 'raw noise-power-valid) (cons 'formatted (number->string noise-power-valid))))
        (cons 'signal-power-valid (list (cons 'raw signal-power-valid) (cons 'formatted (number->string signal-power-valid))))
        (cons 'packet-header-and-br-edr-payload-dewhitened (list (cons 'raw packet-header-and-br-edr-payload-dewhitened) (cons 'formatted (number->string packet-header-and-br-edr-payload-dewhitened))))
        (cons 'header1 (list (cons 'raw header1) (cons 'formatted (fmt-hex header1))))
        (cons 'header1-llid (list (cons 'raw header1-llid) (cons 'formatted (fmt-hex header1-llid))))
        (cons 'header1-flow (list (cons 'raw header1-flow) (cons 'formatted (fmt-hex header1-flow))))
        (cons 'header1-length (list (cons 'raw header1-length) (cons 'formatted (fmt-hex header1-length))))
        (cons 'header2 (list (cons 'raw header2) (cons 'formatted (fmt-hex header2))))
        (cons 'header2-llid (list (cons 'raw header2-llid) (cons 'formatted (fmt-hex header2-llid))))
        (cons 'header2-flow (list (cons 'raw header2-flow) (cons 'formatted (fmt-hex header2-flow))))
        (cons 'header2-length (list (cons 'raw header2-length) (cons 'formatted (fmt-hex header2-length))))
        (cons 'header2-rfu (list (cons 'raw header2-rfu) (cons 'formatted (fmt-hex header2-rfu))))
        (cons 'hf-crc (list (cons 'raw hf-crc) (cons 'formatted (fmt-hex hf-crc))))
        )))

    (catch (e)
      (err (str "BTBREDR-RF parse error: " e)))))

;; dissect-btbredr-rf: parse BTBREDR-RF from bytevector
;; Returns (ok fields-alist) or (err message)