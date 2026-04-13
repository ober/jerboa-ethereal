;; packet-nfapi.c
;; Routines for Network Function Application Platform Interface (nFAPI) dissection
;; Copyright 2017 Cisco Systems, Inc.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References:
;; SCF082.09.04  http://scf.io/en/documents/082_-_nFAPI_and_FAPI_specifications.php
;;
;;

;; jerboa-ethereal/dissectors/nfapi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nfapi.c

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
(def (dissect-nfapi buffer)
  "Nfapi"
  (try
    (let* (
           (p4-p5-message-header-phy-id (unwrap (read-u16be buffer 0)))
           (p7-message-header-phy-id (unwrap (read-u16be buffer 0)))
           (p4-p5-message-header-message-length (unwrap (read-u16be buffer 4)))
           (p4-p5-message-header-spare (unwrap (read-u16be buffer 6)))
           (p7-message-header-sequence-number (unwrap (read-u8 buffer 7)))
           (p7-message-header-checksum (unwrap (read-u32be buffer 8)))
           (num-tlv (unwrap (read-u8 buffer 17)))
           (dl-node-sync-delta-sfn-sf (unwrap (read-u32be buffer 32)))
           (timing-info-last-sfn-sf (unwrap (read-u32be buffer 36)))
           (timing-info-time-since-last-timing-info (unwrap (read-u32be buffer 40)))
           (timing-info-dl-config-jitter (unwrap (read-u32be buffer 44)))
           (timing-info-tx-request-jitter (unwrap (read-u32be buffer 48)))
           (timing-info-ul-config-jitter (unwrap (read-u32be buffer 52)))
           (timing-info-hi-dci0-jitter (unwrap (read-u32be buffer 56)))
           (timing-info-dl-config-latest-delay (unwrap (read-u32be buffer 60)))
           (timing-info-tx-request-latest-delay (unwrap (read-u32be buffer 64)))
           (timing-info-ul-config-latest-delay (unwrap (read-u32be buffer 68)))
           (timing-info-hi-dci0-latest-delay (unwrap (read-u32be buffer 72)))
           (timing-info-dl-config-earliest-arrival (unwrap (read-u32be buffer 76)))
           (timing-info-tx-request-earliest-arrival (unwrap (read-u32be buffer 80)))
           (timing-info-ul-config-earliest-arrival (unwrap (read-u32be buffer 84)))
           (timing-info-hi-dci0-earliest-arrival (unwrap (read-u32be buffer 88)))
           )

      (ok (list
        (cons 'p4-p5-message-header-phy-id (list (cons 'raw p4-p5-message-header-phy-id) (cons 'formatted (number->string p4-p5-message-header-phy-id))))
        (cons 'p7-message-header-phy-id (list (cons 'raw p7-message-header-phy-id) (cons 'formatted (number->string p7-message-header-phy-id))))
        (cons 'p4-p5-message-header-message-length (list (cons 'raw p4-p5-message-header-message-length) (cons 'formatted (number->string p4-p5-message-header-message-length))))
        (cons 'p4-p5-message-header-spare (list (cons 'raw p4-p5-message-header-spare) (cons 'formatted (number->string p4-p5-message-header-spare))))
        (cons 'p7-message-header-sequence-number (list (cons 'raw p7-message-header-sequence-number) (cons 'formatted (number->string p7-message-header-sequence-number))))
        (cons 'p7-message-header-checksum (list (cons 'raw p7-message-header-checksum) (cons 'formatted (fmt-hex p7-message-header-checksum))))
        (cons 'num-tlv (list (cons 'raw num-tlv) (cons 'formatted (number->string num-tlv))))
        (cons 'dl-node-sync-delta-sfn-sf (list (cons 'raw dl-node-sync-delta-sfn-sf) (cons 'formatted (number->string dl-node-sync-delta-sfn-sf))))
        (cons 'timing-info-last-sfn-sf (list (cons 'raw timing-info-last-sfn-sf) (cons 'formatted (number->string timing-info-last-sfn-sf))))
        (cons 'timing-info-time-since-last-timing-info (list (cons 'raw timing-info-time-since-last-timing-info) (cons 'formatted (number->string timing-info-time-since-last-timing-info))))
        (cons 'timing-info-dl-config-jitter (list (cons 'raw timing-info-dl-config-jitter) (cons 'formatted (number->string timing-info-dl-config-jitter))))
        (cons 'timing-info-tx-request-jitter (list (cons 'raw timing-info-tx-request-jitter) (cons 'formatted (number->string timing-info-tx-request-jitter))))
        (cons 'timing-info-ul-config-jitter (list (cons 'raw timing-info-ul-config-jitter) (cons 'formatted (number->string timing-info-ul-config-jitter))))
        (cons 'timing-info-hi-dci0-jitter (list (cons 'raw timing-info-hi-dci0-jitter) (cons 'formatted (number->string timing-info-hi-dci0-jitter))))
        (cons 'timing-info-dl-config-latest-delay (list (cons 'raw timing-info-dl-config-latest-delay) (cons 'formatted (number->string timing-info-dl-config-latest-delay))))
        (cons 'timing-info-tx-request-latest-delay (list (cons 'raw timing-info-tx-request-latest-delay) (cons 'formatted (number->string timing-info-tx-request-latest-delay))))
        (cons 'timing-info-ul-config-latest-delay (list (cons 'raw timing-info-ul-config-latest-delay) (cons 'formatted (number->string timing-info-ul-config-latest-delay))))
        (cons 'timing-info-hi-dci0-latest-delay (list (cons 'raw timing-info-hi-dci0-latest-delay) (cons 'formatted (number->string timing-info-hi-dci0-latest-delay))))
        (cons 'timing-info-dl-config-earliest-arrival (list (cons 'raw timing-info-dl-config-earliest-arrival) (cons 'formatted (number->string timing-info-dl-config-earliest-arrival))))
        (cons 'timing-info-tx-request-earliest-arrival (list (cons 'raw timing-info-tx-request-earliest-arrival) (cons 'formatted (number->string timing-info-tx-request-earliest-arrival))))
        (cons 'timing-info-ul-config-earliest-arrival (list (cons 'raw timing-info-ul-config-earliest-arrival) (cons 'formatted (number->string timing-info-ul-config-earliest-arrival))))
        (cons 'timing-info-hi-dci0-earliest-arrival (list (cons 'raw timing-info-hi-dci0-earliest-arrival) (cons 'formatted (number->string timing-info-hi-dci0-earliest-arrival))))
        )))

    (catch (e)
      (err (str "NFAPI parse error: " e)))))

;; dissect-nfapi: parse NFAPI from bytevector
;; Returns (ok fields-alist) or (err message)