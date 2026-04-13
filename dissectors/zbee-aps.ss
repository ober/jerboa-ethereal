;; packet-zbee-aps.c
;; Dissector routines for the ZigBee Application Support Sub-layer (APS)
;; By Owen Kirby <osk@exegin.com>
;; Copyright 2009 Exegin Technologies Limited
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/zbee-aps.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zbee_aps.c

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
(def (dissect-zbee-aps buffer)
  "ZigBee Application Support Layer"
  (try
    (let* (
           (aps-fcf-ack-format (unwrap (read-u8 buffer 0)))
           (aps-fcf-indirect-mode (unwrap (read-u8 buffer 0)))
           (aps-fcf-security (unwrap (read-u8 buffer 0)))
           (aps-fcf-ack-req (unwrap (read-u8 buffer 0)))
           (aps-fcf-ext-header (unwrap (read-u8 buffer 0)))
           (apf-count (unwrap (read-u8 buffer 0)))
           (aps-t2-btres-octet-sequence-length-requested (unwrap (read-u8 buffer 0)))
           (aps-dst (unwrap (read-u8 buffer 1)))
           (aps-group (unwrap (read-u16be buffer 2)))
           (aps-t2-btres-octet-sequence (unwrap (slice buffer 2 1)))
           (aps-t2-btreq-octet-sequence-length (unwrap (read-u8 buffer 2)))
           (aps-zdp-cluster (unwrap (read-u16be buffer 4)))
           (aps-src (unwrap (read-u8 buffer 9)))
           (aps-counter (unwrap (read-u8 buffer 10)))
           (aps-block-number (unwrap (read-u8 buffer 12)))
           (aps-block-ack (unwrap (read-u8 buffer 13)))
           (aps-block-ack1 (extract-bits aps-block-ack 0x0 0))
           (aps-block-ack2 (extract-bits aps-block-ack 0x0 0))
           (aps-block-ack3 (extract-bits aps-block-ack 0x0 0))
           (aps-block-ack4 (extract-bits aps-block-ack 0x0 0))
           (aps-block-ack5 (extract-bits aps-block-ack 0x0 0))
           (aps-block-ack6 (extract-bits aps-block-ack 0x0 0))
           (aps-block-ack7 (extract-bits aps-block-ack 0x0 0))
           (aps-block-ack8 (extract-bits aps-block-ack 0x0 0))
           (aps-cmd-key (unwrap (slice buffer 34 1)))
           (aps-cmd-initiator-flag (unwrap (read-u8 buffer 75)))
           (aps-cmd-key-hash (unwrap (slice buffer 85 1)))
           (aps-cmd-short-addr (unwrap (read-u16be buffer 103)))
           (aps-cmd-seqno (unwrap (read-u8 buffer 125)))
           (aps-cmd-challenge (unwrap (slice buffer 142 1)))
           (aps-cmd-mac (unwrap (slice buffer 142 1)))
           (aps-cmd-ea-data (unwrap (slice buffer 143 1)))
           )

      (ok (list
        (cons 'aps-fcf-ack-format (list (cons 'raw aps-fcf-ack-format) (cons 'formatted (number->string aps-fcf-ack-format))))
        (cons 'aps-fcf-indirect-mode (list (cons 'raw aps-fcf-indirect-mode) (cons 'formatted (number->string aps-fcf-indirect-mode))))
        (cons 'aps-fcf-security (list (cons 'raw aps-fcf-security) (cons 'formatted (number->string aps-fcf-security))))
        (cons 'aps-fcf-ack-req (list (cons 'raw aps-fcf-ack-req) (cons 'formatted (number->string aps-fcf-ack-req))))
        (cons 'aps-fcf-ext-header (list (cons 'raw aps-fcf-ext-header) (cons 'formatted (number->string aps-fcf-ext-header))))
        (cons 'apf-count (list (cons 'raw apf-count) (cons 'formatted (number->string apf-count))))
        (cons 'aps-t2-btres-octet-sequence-length-requested (list (cons 'raw aps-t2-btres-octet-sequence-length-requested) (cons 'formatted (number->string aps-t2-btres-octet-sequence-length-requested))))
        (cons 'aps-dst (list (cons 'raw aps-dst) (cons 'formatted (number->string aps-dst))))
        (cons 'aps-group (list (cons 'raw aps-group) (cons 'formatted (fmt-hex aps-group))))
        (cons 'aps-t2-btres-octet-sequence (list (cons 'raw aps-t2-btres-octet-sequence) (cons 'formatted (fmt-bytes aps-t2-btres-octet-sequence))))
        (cons 'aps-t2-btreq-octet-sequence-length (list (cons 'raw aps-t2-btreq-octet-sequence-length) (cons 'formatted (number->string aps-t2-btreq-octet-sequence-length))))
        (cons 'aps-zdp-cluster (list (cons 'raw aps-zdp-cluster) (cons 'formatted (fmt-hex aps-zdp-cluster))))
        (cons 'aps-src (list (cons 'raw aps-src) (cons 'formatted (number->string aps-src))))
        (cons 'aps-counter (list (cons 'raw aps-counter) (cons 'formatted (number->string aps-counter))))
        (cons 'aps-block-number (list (cons 'raw aps-block-number) (cons 'formatted (number->string aps-block-number))))
        (cons 'aps-block-ack (list (cons 'raw aps-block-ack) (cons 'formatted (fmt-hex aps-block-ack))))
        (cons 'aps-block-ack1 (list (cons 'raw aps-block-ack1) (cons 'formatted (if (= aps-block-ack1 0) "Not set" "Set"))))
        (cons 'aps-block-ack2 (list (cons 'raw aps-block-ack2) (cons 'formatted (if (= aps-block-ack2 0) "Not set" "Set"))))
        (cons 'aps-block-ack3 (list (cons 'raw aps-block-ack3) (cons 'formatted (if (= aps-block-ack3 0) "Not set" "Set"))))
        (cons 'aps-block-ack4 (list (cons 'raw aps-block-ack4) (cons 'formatted (if (= aps-block-ack4 0) "Not set" "Set"))))
        (cons 'aps-block-ack5 (list (cons 'raw aps-block-ack5) (cons 'formatted (if (= aps-block-ack5 0) "Not set" "Set"))))
        (cons 'aps-block-ack6 (list (cons 'raw aps-block-ack6) (cons 'formatted (if (= aps-block-ack6 0) "Not set" "Set"))))
        (cons 'aps-block-ack7 (list (cons 'raw aps-block-ack7) (cons 'formatted (if (= aps-block-ack7 0) "Not set" "Set"))))
        (cons 'aps-block-ack8 (list (cons 'raw aps-block-ack8) (cons 'formatted (if (= aps-block-ack8 0) "Not set" "Set"))))
        (cons 'aps-cmd-key (list (cons 'raw aps-cmd-key) (cons 'formatted (fmt-bytes aps-cmd-key))))
        (cons 'aps-cmd-initiator-flag (list (cons 'raw aps-cmd-initiator-flag) (cons 'formatted (number->string aps-cmd-initiator-flag))))
        (cons 'aps-cmd-key-hash (list (cons 'raw aps-cmd-key-hash) (cons 'formatted (fmt-bytes aps-cmd-key-hash))))
        (cons 'aps-cmd-short-addr (list (cons 'raw aps-cmd-short-addr) (cons 'formatted (fmt-hex aps-cmd-short-addr))))
        (cons 'aps-cmd-seqno (list (cons 'raw aps-cmd-seqno) (cons 'formatted (number->string aps-cmd-seqno))))
        (cons 'aps-cmd-challenge (list (cons 'raw aps-cmd-challenge) (cons 'formatted (fmt-bytes aps-cmd-challenge))))
        (cons 'aps-cmd-mac (list (cons 'raw aps-cmd-mac) (cons 'formatted (fmt-bytes aps-cmd-mac))))
        (cons 'aps-cmd-ea-data (list (cons 'raw aps-cmd-ea-data) (cons 'formatted (fmt-bytes aps-cmd-ea-data))))
        )))

    (catch (e)
      (err (str "ZBEE-APS parse error: " e)))))

;; dissect-zbee-aps: parse ZBEE-APS from bytevector
;; Returns (ok fields-alist) or (err message)