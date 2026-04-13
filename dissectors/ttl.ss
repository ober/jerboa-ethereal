;; packet-ttl.c
;;
;; TTX Logger (TTL) format from TTTech Computertechnik AG dissector by
;; Giovanni Musto <giovanni.musto@italdesign.it>
;; Copyright 2025-2026 Giovanni Musto
;;
;; This dissector allows to parse TTL files.
;; You can find the PDF with the documentation of the format at
;; https://servicearea.tttech-auto.com/ (registration and approval required).
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ttl.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ttl.c

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
(def (dissect-ttl buffer)
  "TTL Format"
  (try
    (let* (
           (trace-data-entry-segment-key (unwrap (read-u32be buffer 0)))
           (trace-data-entry-dest-addr (unwrap (read-u16be buffer 0)))
           (trace-data-entry-dest-addr-function-unknown (unwrap (read-u16be buffer 0)))
           (trace-data-entry-src-addr (unwrap (read-u16be buffer 0)))
           (trace-data-entry-src-addr-function-unknown (unwrap (read-u16be buffer 0)))
           (trace-data-entry-eth-unused (unwrap (slice buffer 0 2)))
           (trace-data-entry-can-id (unwrap (read-u32be buffer 0)))
           (trace-data-entry-lin-checksum (unwrap (read-u8 buffer 0)))
           (trace-data-entry-fr-low-phase-counter (unwrap (read-u16be buffer 0)))
           (trace-data-entry-size (unwrap (read-u16be buffer 0)))
           (eth-phy-status-valid (unwrap (read-u8 buffer 2)))
           (eth-phy-status-res2 (unwrap (read-u8 buffer 2)))
           (eth-phy-status-unused (unwrap (read-u8 buffer 2)))
           (eth-phy-status-res1 (unwrap (read-u8 buffer 2)))
           (eth-phy-status-reg-addr (unwrap (read-u8 buffer 2)))
           (eth-phy-status-data (unwrap (read-u16be buffer 2)))
           (trace-data-entry-fr-unused (unwrap (read-u16be buffer 2)))
           (trace-data-entry-meta1 (unwrap (read-u16le buffer 2)))
           (trace-data-entry-meta1-frame-duplication (extract-bits trace-data-entry-meta1 0x8000 15))
           (trace-data-entry-meta1-compressed-format (extract-bits trace-data-entry-meta1 0x4000 14))
           (trace-data-entry-meta1-timestamp-source (extract-bits trace-data-entry-meta1 0x2000 13))
           (trace-data-entry-meta2 (unwrap (read-u16be buffer 2)))
           (trace-data-entry-status-information (unwrap (read-u16be buffer 2)))
           (trace-data-entry-fr-eray-eir-register (unwrap (read-u32be buffer 4)))
           (trace-data-entry-fr-eray-stpw1-register (unwrap (read-u32be buffer 8)))
           (trace-data-entry-segment-size (unwrap (read-u32be buffer 8)))
           (trace-data-entry-fr-eray-stpw2-register (unwrap (read-u32be buffer 12)))
           (trace-data-entry-unparsed (unwrap (slice buffer 12 1)))
           (trace-data-entry-fr-eray-ccsv-register (unwrap (read-u32be buffer 16)))
           (trace-data-entry-fr-eray-ccev-register (unwrap (read-u32be buffer 20)))
           (trace-data-entry-fr-eray-swnit-register (unwrap (read-u32be buffer 24)))
           (trace-data-entry-fr-eray-acs-register (unwrap (read-u32be buffer 28)))
           (trace-data-entry-payload (unwrap (slice buffer 32 1)))
           )

      (ok (list
        (cons 'trace-data-entry-segment-key (list (cons 'raw trace-data-entry-segment-key) (cons 'formatted (fmt-hex trace-data-entry-segment-key))))
        (cons 'trace-data-entry-dest-addr (list (cons 'raw trace-data-entry-dest-addr) (cons 'formatted (number->string trace-data-entry-dest-addr))))
        (cons 'trace-data-entry-dest-addr-function-unknown (list (cons 'raw trace-data-entry-dest-addr-function-unknown) (cons 'formatted (number->string trace-data-entry-dest-addr-function-unknown))))
        (cons 'trace-data-entry-src-addr (list (cons 'raw trace-data-entry-src-addr) (cons 'formatted (number->string trace-data-entry-src-addr))))
        (cons 'trace-data-entry-src-addr-function-unknown (list (cons 'raw trace-data-entry-src-addr-function-unknown) (cons 'formatted (number->string trace-data-entry-src-addr-function-unknown))))
        (cons 'trace-data-entry-eth-unused (list (cons 'raw trace-data-entry-eth-unused) (cons 'formatted (fmt-bytes trace-data-entry-eth-unused))))
        (cons 'trace-data-entry-can-id (list (cons 'raw trace-data-entry-can-id) (cons 'formatted (number->string trace-data-entry-can-id))))
        (cons 'trace-data-entry-lin-checksum (list (cons 'raw trace-data-entry-lin-checksum) (cons 'formatted (fmt-hex trace-data-entry-lin-checksum))))
        (cons 'trace-data-entry-fr-low-phase-counter (list (cons 'raw trace-data-entry-fr-low-phase-counter) (cons 'formatted (fmt-hex trace-data-entry-fr-low-phase-counter))))
        (cons 'trace-data-entry-size (list (cons 'raw trace-data-entry-size) (cons 'formatted (number->string trace-data-entry-size))))
        (cons 'eth-phy-status-valid (list (cons 'raw eth-phy-status-valid) (cons 'formatted (if (= eth-phy-status-valid 0) "False" "True"))))
        (cons 'eth-phy-status-res2 (list (cons 'raw eth-phy-status-res2) (cons 'formatted (fmt-hex eth-phy-status-res2))))
        (cons 'eth-phy-status-unused (list (cons 'raw eth-phy-status-unused) (cons 'formatted (fmt-hex eth-phy-status-unused))))
        (cons 'eth-phy-status-res1 (list (cons 'raw eth-phy-status-res1) (cons 'formatted (fmt-hex eth-phy-status-res1))))
        (cons 'eth-phy-status-reg-addr (list (cons 'raw eth-phy-status-reg-addr) (cons 'formatted (fmt-hex eth-phy-status-reg-addr))))
        (cons 'eth-phy-status-data (list (cons 'raw eth-phy-status-data) (cons 'formatted (fmt-hex eth-phy-status-data))))
        (cons 'trace-data-entry-fr-unused (list (cons 'raw trace-data-entry-fr-unused) (cons 'formatted (fmt-hex trace-data-entry-fr-unused))))
        (cons 'trace-data-entry-meta1 (list (cons 'raw trace-data-entry-meta1) (cons 'formatted (number->string trace-data-entry-meta1))))
        (cons 'trace-data-entry-meta1-frame-duplication (list (cons 'raw trace-data-entry-meta1-frame-duplication) (cons 'formatted (if (= trace-data-entry-meta1-frame-duplication 0) "No Frame Duplication" "Frame Duplication"))))
        (cons 'trace-data-entry-meta1-compressed-format (list (cons 'raw trace-data-entry-meta1-compressed-format) (cons 'formatted (if (= trace-data-entry-meta1-compressed-format 0) "Normal (64 bit) Timestamp" "Compressed (32 bit) Timestamp"))))
        (cons 'trace-data-entry-meta1-timestamp-source (list (cons 'raw trace-data-entry-meta1-timestamp-source) (cons 'formatted (if (= trace-data-entry-meta1-timestamp-source 0) "Timestamp comes from the FPGA" "Timestamp comes from Source Address component"))))
        (cons 'trace-data-entry-meta2 (list (cons 'raw trace-data-entry-meta2) (cons 'formatted (number->string trace-data-entry-meta2))))
        (cons 'trace-data-entry-status-information (list (cons 'raw trace-data-entry-status-information) (cons 'formatted (fmt-hex trace-data-entry-status-information))))
        (cons 'trace-data-entry-fr-eray-eir-register (list (cons 'raw trace-data-entry-fr-eray-eir-register) (cons 'formatted (fmt-hex trace-data-entry-fr-eray-eir-register))))
        (cons 'trace-data-entry-fr-eray-stpw1-register (list (cons 'raw trace-data-entry-fr-eray-stpw1-register) (cons 'formatted (fmt-hex trace-data-entry-fr-eray-stpw1-register))))
        (cons 'trace-data-entry-segment-size (list (cons 'raw trace-data-entry-segment-size) (cons 'formatted (number->string trace-data-entry-segment-size))))
        (cons 'trace-data-entry-fr-eray-stpw2-register (list (cons 'raw trace-data-entry-fr-eray-stpw2-register) (cons 'formatted (fmt-hex trace-data-entry-fr-eray-stpw2-register))))
        (cons 'trace-data-entry-unparsed (list (cons 'raw trace-data-entry-unparsed) (cons 'formatted (fmt-bytes trace-data-entry-unparsed))))
        (cons 'trace-data-entry-fr-eray-ccsv-register (list (cons 'raw trace-data-entry-fr-eray-ccsv-register) (cons 'formatted (fmt-hex trace-data-entry-fr-eray-ccsv-register))))
        (cons 'trace-data-entry-fr-eray-ccev-register (list (cons 'raw trace-data-entry-fr-eray-ccev-register) (cons 'formatted (fmt-hex trace-data-entry-fr-eray-ccev-register))))
        (cons 'trace-data-entry-fr-eray-swnit-register (list (cons 'raw trace-data-entry-fr-eray-swnit-register) (cons 'formatted (fmt-hex trace-data-entry-fr-eray-swnit-register))))
        (cons 'trace-data-entry-fr-eray-acs-register (list (cons 'raw trace-data-entry-fr-eray-acs-register) (cons 'formatted (fmt-hex trace-data-entry-fr-eray-acs-register))))
        (cons 'trace-data-entry-payload (list (cons 'raw trace-data-entry-payload) (cons 'formatted (fmt-bytes trace-data-entry-payload))))
        )))

    (catch (e)
      (err (str "TTL parse error: " e)))))

;; dissect-ttl: parse TTL from bytevector
;; Returns (ok fields-alist) or (err message)