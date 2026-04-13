;; packet-rdpudp.c
;; Routines for UDP RDP packet dissection
;; Copyright 2021, David Fort
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rdpudp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rdpudp.c

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
(def (dissect-rdpudp buffer)
  "UDP Remote Desktop Protocol"
  (try
    (let* (
           (snSourceAck (unwrap (read-u32be buffer 0)))
           (ReceiveWindowSize (unwrap (read-u16be buffer 4)))
           (flags (unwrap (read-u16be buffer 6)))
           (flag-syn (extract-bits flags 0x0 0))
           (flag-fin (extract-bits flags 0x0 0))
           (flag-ack (extract-bits flags 0x0 0))
           (flag-data (extract-bits flags 0x0 0))
           (flag-fec (extract-bits flags 0x0 0))
           (flag-cn (extract-bits flags 0x0 0))
           (flag-cwr (extract-bits flags 0x0 0))
           (flag-aoa (extract-bits flags 0x0 0))
           (flag-synlossy (extract-bits flags 0x0 0))
           (flag-ackdelayed (extract-bits flags 0x0 0))
           (flag-correlationId (extract-bits flags 0x0 0))
           (flag-synex (extract-bits flags 0x0 0))
           (snInitialSequenceNumber (unwrap (read-u32be buffer 8)))
           (upstreamMtu (unwrap (read-u16be buffer 12)))
           (downstreamMtu (unwrap (read-u16be buffer 14)))
           (correlationId (unwrap (slice buffer 16 16)))
           (synex-flags (unwrap (read-u16be buffer 48)))
           (synex-flag-version (unwrap (read-u8 buffer 48)))
           (synex-cookiehash (unwrap (slice buffer 52 32)))
           (ack-item (unwrap (read-u8 buffer 86)))
           (ack-item-rle (unwrap (read-u8 buffer 86)))
           (fec-coded (unwrap (read-u32be buffer 86)))
           (fec-sourcestart (unwrap (read-u32be buffer 90)))
           (fec-range (unwrap (read-u8 buffer 94)))
           (fec-fecindex (unwrap (read-u8 buffer 95)))
           (resetseqenum (unwrap (read-u32be buffer 96)))
           (source-sncoded (unwrap (read-u32be buffer 100)))
           (source-snSourceStart (unwrap (read-u32be buffer 104)))
           )

      (ok (list
        (cons 'snSourceAck (list (cons 'raw snSourceAck) (cons 'formatted (fmt-hex snSourceAck))))
        (cons 'ReceiveWindowSize (list (cons 'raw ReceiveWindowSize) (cons 'formatted (number->string ReceiveWindowSize))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flag-syn (list (cons 'raw flag-syn) (cons 'formatted (if (= flag-syn 0) "Not set" "Set"))))
        (cons 'flag-fin (list (cons 'raw flag-fin) (cons 'formatted (if (= flag-fin 0) "Not set" "Set"))))
        (cons 'flag-ack (list (cons 'raw flag-ack) (cons 'formatted (if (= flag-ack 0) "Not set" "Set"))))
        (cons 'flag-data (list (cons 'raw flag-data) (cons 'formatted (if (= flag-data 0) "Not set" "Set"))))
        (cons 'flag-fec (list (cons 'raw flag-fec) (cons 'formatted (if (= flag-fec 0) "Not set" "Set"))))
        (cons 'flag-cn (list (cons 'raw flag-cn) (cons 'formatted (if (= flag-cn 0) "Not set" "Set"))))
        (cons 'flag-cwr (list (cons 'raw flag-cwr) (cons 'formatted (if (= flag-cwr 0) "Not set" "Set"))))
        (cons 'flag-aoa (list (cons 'raw flag-aoa) (cons 'formatted (if (= flag-aoa 0) "Not set" "Set"))))
        (cons 'flag-synlossy (list (cons 'raw flag-synlossy) (cons 'formatted (if (= flag-synlossy 0) "Not set" "Set"))))
        (cons 'flag-ackdelayed (list (cons 'raw flag-ackdelayed) (cons 'formatted (if (= flag-ackdelayed 0) "Not set" "Set"))))
        (cons 'flag-correlationId (list (cons 'raw flag-correlationId) (cons 'formatted (if (= flag-correlationId 0) "Not set" "Set"))))
        (cons 'flag-synex (list (cons 'raw flag-synex) (cons 'formatted (if (= flag-synex 0) "Not set" "Set"))))
        (cons 'snInitialSequenceNumber (list (cons 'raw snInitialSequenceNumber) (cons 'formatted (fmt-hex snInitialSequenceNumber))))
        (cons 'upstreamMtu (list (cons 'raw upstreamMtu) (cons 'formatted (number->string upstreamMtu))))
        (cons 'downstreamMtu (list (cons 'raw downstreamMtu) (cons 'formatted (number->string downstreamMtu))))
        (cons 'correlationId (list (cons 'raw correlationId) (cons 'formatted (fmt-bytes correlationId))))
        (cons 'synex-flags (list (cons 'raw synex-flags) (cons 'formatted (fmt-hex synex-flags))))
        (cons 'synex-flag-version (list (cons 'raw synex-flag-version) (cons 'formatted (number->string synex-flag-version))))
        (cons 'synex-cookiehash (list (cons 'raw synex-cookiehash) (cons 'formatted (fmt-bytes synex-cookiehash))))
        (cons 'ack-item (list (cons 'raw ack-item) (cons 'formatted (fmt-hex ack-item))))
        (cons 'ack-item-rle (list (cons 'raw ack-item-rle) (cons 'formatted (number->string ack-item-rle))))
        (cons 'fec-coded (list (cons 'raw fec-coded) (cons 'formatted (fmt-hex fec-coded))))
        (cons 'fec-sourcestart (list (cons 'raw fec-sourcestart) (cons 'formatted (fmt-hex fec-sourcestart))))
        (cons 'fec-range (list (cons 'raw fec-range) (cons 'formatted (number->string fec-range))))
        (cons 'fec-fecindex (list (cons 'raw fec-fecindex) (cons 'formatted (number->string fec-fecindex))))
        (cons 'resetseqenum (list (cons 'raw resetseqenum) (cons 'formatted (fmt-hex resetseqenum))))
        (cons 'source-sncoded (list (cons 'raw source-sncoded) (cons 'formatted (fmt-hex source-sncoded))))
        (cons 'source-snSourceStart (list (cons 'raw source-snSourceStart) (cons 'formatted (fmt-hex source-snSourceStart))))
        )))

    (catch (e)
      (err (str "RDPUDP parse error: " e)))))

;; dissect-rdpudp: parse RDPUDP from bytevector
;; Returns (ok fields-alist) or (err message)