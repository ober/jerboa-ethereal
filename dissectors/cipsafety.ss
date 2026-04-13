;; packet-cipsafety.c
;; Routines for CIP (Common Industrial Protocol) Safety dissection
;; CIP Safety Home: www.odva.org
;;
;; This dissector includes items from:
;; CIP Volume 1: Common Industrial Protocol, Edition 3.24
;; CIP Volume 5: CIP Safety, Edition 2.26
;;
;; Copyright 2011
;; Michael Mann <mmann@pyramidsolutions.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cipsafety.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cipsafety.c

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
(def (dissect-cipsafety buffer)
  "Common Industrial Protocol, Safety"
  (try
    (let* (
           (data (unwrap (slice buffer 0 1)))
           (ssupervisor-reset-password (unwrap (slice buffer 0 16)))
           (ssupervisor-reset-tunid (unwrap (slice buffer 0 10)))
           (ssupervisor-reset-attr-bitmap (unwrap (read-u8 buffer 0)))
           (ssupervisor-reset-attr-bitmap-macid (unwrap (read-u8 buffer 0)))
           (ssupervisor-reset-attr-bitmap-baudrate (unwrap (read-u8 buffer 0)))
           (ssupervisor-reset-attr-bitmap-tunid (unwrap (read-u8 buffer 0)))
           (ssupervisor-reset-attr-bitmap-password (unwrap (read-u8 buffer 0)))
           (ssupervisor-reset-attr-bitmap-cfunid (unwrap (read-u8 buffer 0)))
           (ssupervisor-reset-attr-bitmap-ocpunid (unwrap (read-u8 buffer 0)))
           (ssupervisor-reset-attr-bitmap-reserved (unwrap (read-u8 buffer 0)))
           (ssupervisor-reset-attr-bitmap-extended (unwrap (read-u8 buffer 0)))
           (ssupervisor-safety-configuration-id-sccrc (unwrap (read-u32be buffer 0)))
           (ssupervisor-cp-owners-num-entries (unwrap (read-u16be buffer 0)))
           (ssupervisor-cp-owners-app-path-size (unwrap (read-u8 buffer 0)))
           (svalidator-type (unwrap (read-u8 buffer 0)))
           (svalidator-time-coord-msg-min-mult-size (unwrap (read-u8 buffer 0)))
           (svalidator-network-time-multiplier-size (unwrap (read-u8 buffer 0)))
           (svalidator-timeout-multiplier-size (unwrap (read-u8 buffer 0)))
           (svalidator-coordination-conn-inst-size (unwrap (read-u8 buffer 0)))
           (svalidator-prod-cons-fault-count-size (unwrap (read-u8 buffer 0)))
           (mode-byte (unwrap (read-u8 buffer 0)))
           (mode-byte-ping-count (unwrap (read-u8 buffer 0)))
           (mode-byte-not-tbd (unwrap (read-u8 buffer 0)))
           (mode-byte-tbd-2-copy (unwrap (read-u8 buffer 0)))
           (mode-byte-not-run-idle (unwrap (read-u8 buffer 0)))
           (mode-byte-tbd (unwrap (read-u8 buffer 0)))
           (mode-byte-tbd-2-bit (unwrap (read-u8 buffer 0)))
           (mode-byte-run-idle (unwrap (read-u8 buffer 0)))
           (ack-byte (unwrap (read-u8 buffer 0)))
           (mcast-byte (unwrap (read-u8 buffer 0)))
           (mcast-byte-consumer-num (extract-bits mcast-byte 0xF 0))
           (mcast-byte-reserved1 (extract-bits mcast-byte 0x10 4))
           (mcast-byte-mai (extract-bits mcast-byte 0x20 5))
           (mcast-byte-reserved2 (extract-bits mcast-byte 0x40 6))
           (mcast-byte-parity-even (extract-bits mcast-byte 0x80 7))
           (time-correction (unwrap (read-u16be buffer 0)))
           (mcast-byte2 (unwrap (read-u8 buffer 0)))
           (crc-s3 (unwrap (read-u16be buffer 0)))
           (crc-s5-0 (unwrap (read-u8 buffer 0)))
           (crc-s5-1 (unwrap (read-u8 buffer 0)))
           (crc-s5-2 (unwrap (read-u8 buffer 0)))
           (sercosiii-link-error-count-p1 (unwrap (read-u16be buffer 0)))
           (sercosiii-link-error-count-p2 (unwrap (read-u16be buffer 0)))
           (sercosiii-link-snn (unwrap (slice buffer 0 6)))
           (consumer-time-value (unwrap (read-u16be buffer 1)))
           (ack-byte2 (unwrap (read-u8 buffer 3)))
           )

      (ok (list
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'ssupervisor-reset-password (list (cons 'raw ssupervisor-reset-password) (cons 'formatted (fmt-bytes ssupervisor-reset-password))))
        (cons 'ssupervisor-reset-tunid (list (cons 'raw ssupervisor-reset-tunid) (cons 'formatted (fmt-bytes ssupervisor-reset-tunid))))
        (cons 'ssupervisor-reset-attr-bitmap (list (cons 'raw ssupervisor-reset-attr-bitmap) (cons 'formatted (fmt-hex ssupervisor-reset-attr-bitmap))))
        (cons 'ssupervisor-reset-attr-bitmap-macid (list (cons 'raw ssupervisor-reset-attr-bitmap-macid) (cons 'formatted (number->string ssupervisor-reset-attr-bitmap-macid))))
        (cons 'ssupervisor-reset-attr-bitmap-baudrate (list (cons 'raw ssupervisor-reset-attr-bitmap-baudrate) (cons 'formatted (number->string ssupervisor-reset-attr-bitmap-baudrate))))
        (cons 'ssupervisor-reset-attr-bitmap-tunid (list (cons 'raw ssupervisor-reset-attr-bitmap-tunid) (cons 'formatted (number->string ssupervisor-reset-attr-bitmap-tunid))))
        (cons 'ssupervisor-reset-attr-bitmap-password (list (cons 'raw ssupervisor-reset-attr-bitmap-password) (cons 'formatted (number->string ssupervisor-reset-attr-bitmap-password))))
        (cons 'ssupervisor-reset-attr-bitmap-cfunid (list (cons 'raw ssupervisor-reset-attr-bitmap-cfunid) (cons 'formatted (number->string ssupervisor-reset-attr-bitmap-cfunid))))
        (cons 'ssupervisor-reset-attr-bitmap-ocpunid (list (cons 'raw ssupervisor-reset-attr-bitmap-ocpunid) (cons 'formatted (number->string ssupervisor-reset-attr-bitmap-ocpunid))))
        (cons 'ssupervisor-reset-attr-bitmap-reserved (list (cons 'raw ssupervisor-reset-attr-bitmap-reserved) (cons 'formatted (number->string ssupervisor-reset-attr-bitmap-reserved))))
        (cons 'ssupervisor-reset-attr-bitmap-extended (list (cons 'raw ssupervisor-reset-attr-bitmap-extended) (cons 'formatted (number->string ssupervisor-reset-attr-bitmap-extended))))
        (cons 'ssupervisor-safety-configuration-id-sccrc (list (cons 'raw ssupervisor-safety-configuration-id-sccrc) (cons 'formatted (fmt-hex ssupervisor-safety-configuration-id-sccrc))))
        (cons 'ssupervisor-cp-owners-num-entries (list (cons 'raw ssupervisor-cp-owners-num-entries) (cons 'formatted (number->string ssupervisor-cp-owners-num-entries))))
        (cons 'ssupervisor-cp-owners-app-path-size (list (cons 'raw ssupervisor-cp-owners-app-path-size) (cons 'formatted (number->string ssupervisor-cp-owners-app-path-size))))
        (cons 'svalidator-type (list (cons 'raw svalidator-type) (cons 'formatted (fmt-hex svalidator-type))))
        (cons 'svalidator-time-coord-msg-min-mult-size (list (cons 'raw svalidator-time-coord-msg-min-mult-size) (cons 'formatted (number->string svalidator-time-coord-msg-min-mult-size))))
        (cons 'svalidator-network-time-multiplier-size (list (cons 'raw svalidator-network-time-multiplier-size) (cons 'formatted (number->string svalidator-network-time-multiplier-size))))
        (cons 'svalidator-timeout-multiplier-size (list (cons 'raw svalidator-timeout-multiplier-size) (cons 'formatted (number->string svalidator-timeout-multiplier-size))))
        (cons 'svalidator-coordination-conn-inst-size (list (cons 'raw svalidator-coordination-conn-inst-size) (cons 'formatted (number->string svalidator-coordination-conn-inst-size))))
        (cons 'svalidator-prod-cons-fault-count-size (list (cons 'raw svalidator-prod-cons-fault-count-size) (cons 'formatted (number->string svalidator-prod-cons-fault-count-size))))
        (cons 'mode-byte (list (cons 'raw mode-byte) (cons 'formatted (fmt-hex mode-byte))))
        (cons 'mode-byte-ping-count (list (cons 'raw mode-byte-ping-count) (cons 'formatted (number->string mode-byte-ping-count))))
        (cons 'mode-byte-not-tbd (list (cons 'raw mode-byte-not-tbd) (cons 'formatted (number->string mode-byte-not-tbd))))
        (cons 'mode-byte-tbd-2-copy (list (cons 'raw mode-byte-tbd-2-copy) (cons 'formatted (number->string mode-byte-tbd-2-copy))))
        (cons 'mode-byte-not-run-idle (list (cons 'raw mode-byte-not-run-idle) (cons 'formatted (number->string mode-byte-not-run-idle))))
        (cons 'mode-byte-tbd (list (cons 'raw mode-byte-tbd) (cons 'formatted (number->string mode-byte-tbd))))
        (cons 'mode-byte-tbd-2-bit (list (cons 'raw mode-byte-tbd-2-bit) (cons 'formatted (number->string mode-byte-tbd-2-bit))))
        (cons 'mode-byte-run-idle (list (cons 'raw mode-byte-run-idle) (cons 'formatted (number->string mode-byte-run-idle))))
        (cons 'ack-byte (list (cons 'raw ack-byte) (cons 'formatted (fmt-hex ack-byte))))
        (cons 'mcast-byte (list (cons 'raw mcast-byte) (cons 'formatted (fmt-hex mcast-byte))))
        (cons 'mcast-byte-consumer-num (list (cons 'raw mcast-byte-consumer-num) (cons 'formatted (if (= mcast-byte-consumer-num 0) "Not set" "Set"))))
        (cons 'mcast-byte-reserved1 (list (cons 'raw mcast-byte-reserved1) (cons 'formatted (if (= mcast-byte-reserved1 0) "Not set" "Set"))))
        (cons 'mcast-byte-mai (list (cons 'raw mcast-byte-mai) (cons 'formatted (if (= mcast-byte-mai 0) "Not set" "Set"))))
        (cons 'mcast-byte-reserved2 (list (cons 'raw mcast-byte-reserved2) (cons 'formatted (if (= mcast-byte-reserved2 0) "Not set" "Set"))))
        (cons 'mcast-byte-parity-even (list (cons 'raw mcast-byte-parity-even) (cons 'formatted (if (= mcast-byte-parity-even 0) "Not set" "Set"))))
        (cons 'time-correction (list (cons 'raw time-correction) (cons 'formatted (number->string time-correction))))
        (cons 'mcast-byte2 (list (cons 'raw mcast-byte2) (cons 'formatted (fmt-hex mcast-byte2))))
        (cons 'crc-s3 (list (cons 'raw crc-s3) (cons 'formatted (fmt-hex crc-s3))))
        (cons 'crc-s5-0 (list (cons 'raw crc-s5-0) (cons 'formatted (fmt-hex crc-s5-0))))
        (cons 'crc-s5-1 (list (cons 'raw crc-s5-1) (cons 'formatted (fmt-hex crc-s5-1))))
        (cons 'crc-s5-2 (list (cons 'raw crc-s5-2) (cons 'formatted (fmt-hex crc-s5-2))))
        (cons 'sercosiii-link-error-count-p1 (list (cons 'raw sercosiii-link-error-count-p1) (cons 'formatted (number->string sercosiii-link-error-count-p1))))
        (cons 'sercosiii-link-error-count-p2 (list (cons 'raw sercosiii-link-error-count-p2) (cons 'formatted (number->string sercosiii-link-error-count-p2))))
        (cons 'sercosiii-link-snn (list (cons 'raw sercosiii-link-snn) (cons 'formatted (fmt-bytes sercosiii-link-snn))))
        (cons 'consumer-time-value (list (cons 'raw consumer-time-value) (cons 'formatted (number->string consumer-time-value))))
        (cons 'ack-byte2 (list (cons 'raw ack-byte2) (cons 'formatted (fmt-hex ack-byte2))))
        )))

    (catch (e)
      (err (str "CIPSAFETY parse error: " e)))))

;; dissect-cipsafety: parse CIPSAFETY from bytevector
;; Returns (ok fields-alist) or (err message)