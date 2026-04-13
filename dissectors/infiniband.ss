;; packet-infiniband.c
;; Routines for Infiniband/ERF Dissection
;; Copyright 2008 Endace Technology Limited
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Modified 2010 by Mellanox Technologies Ltd.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/infiniband.ss
;; Auto-generated from wireshark/epan/dissectors/packet-infiniband.c

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
(def (dissect-infiniband buffer)
  "InfiniBand"
  (try
    (let* (
           (payload (unwrap (slice buffer 0 1)))
           (LRH (unwrap (slice buffer 0 8)))
           (virtual-lane (unwrap (read-u8 buffer 0)))
           (link-version (unwrap (read-u8 buffer 0)))
           (link-fctbs (unwrap (read-u16be buffer 0)))
           (ver (unwrap (read-u16be buffer 0)))
           (tcp-chk (unwrap (read-u16be buffer 0)))
           (ip-chk (unwrap (read-u16be buffer 0)))
           (fcs (unwrap (read-u8 buffer 0)))
           (ms (unwrap (read-u8 buffer 0)))
           (seg-off (unwrap (read-u16be buffer 0)))
           (service-level (unwrap (read-u8 buffer 1)))
           (reserved2 (unwrap (read-u8 buffer 1)))
           (link-next-header (unwrap (read-u8 buffer 1)))
           (destination-local-id (unwrap (read-u16be buffer 2)))
           (link-vl (unwrap (read-u16be buffer 2)))
           (link-fccl (unwrap (read-u16be buffer 2)))
           (seg-id (unwrap (read-u16be buffer 2)))
           (reserved5 (unwrap (read-u16be buffer 4)))
           (packet-length (unwrap (read-u16be buffer 4)))
           (link-lpcrc (unwrap (read-u16be buffer 4)))
           (source-local-id (unwrap (read-u16be buffer 6)))
           (GRH (unwrap (slice buffer 8 40)))
           (ip-version (unwrap (read-u8 buffer 8)))
           (traffic-class (unwrap (read-u16be buffer 8)))
           (flow-label (unwrap (read-u32be buffer 8)))
           (payload-length (unwrap (read-u16be buffer 12)))
           (next-header (unwrap (read-u8 buffer 14)))
           (hop-limit (unwrap (read-u8 buffer 15)))
           (source-gid (unwrap (slice buffer 16 16)))
           (destination-gid (unwrap (slice buffer 32 16)))
           (BTH (unwrap (slice buffer 48 1)))
           (solicited-event (unwrap (read-u8 buffer 49)))
           (migreq (unwrap (read-u8 buffer 49)))
           (pad-count (unwrap (read-u8 buffer 49)))
           (transport-header-version (unwrap (read-u8 buffer 49)))
           (partition-key (unwrap (read-u16be buffer 50)))
           (reserved (unwrap (slice buffer 52 1)))
           (destination-qp (unwrap (read-u24be buffer 53)))
           (acknowledge-request (unwrap (read-u8 buffer 56)))
           (reserved7 (unwrap (read-u8 buffer 56)))
           (packet-sequence-number (unwrap (read-u24be buffer 57)))
           (raw-data (unwrap (slice buffer 60 1)))
           (invariant-crc (unwrap (read-u32be buffer 66)))
           (variant-crc (unwrap (read-u16be buffer 70)))
           )

      (ok (list
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'LRH (list (cons 'raw LRH) (cons 'formatted (fmt-bytes LRH))))
        (cons 'virtual-lane (list (cons 'raw virtual-lane) (cons 'formatted (fmt-hex virtual-lane))))
        (cons 'link-version (list (cons 'raw link-version) (cons 'formatted (number->string link-version))))
        (cons 'link-fctbs (list (cons 'raw link-fctbs) (cons 'formatted (number->string link-fctbs))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (fmt-hex ver))))
        (cons 'tcp-chk (list (cons 'raw tcp-chk) (cons 'formatted (fmt-hex tcp-chk))))
        (cons 'ip-chk (list (cons 'raw ip-chk) (cons 'formatted (fmt-hex ip-chk))))
        (cons 'fcs (list (cons 'raw fcs) (cons 'formatted (number->string fcs))))
        (cons 'ms (list (cons 'raw ms) (cons 'formatted (number->string ms))))
        (cons 'seg-off (list (cons 'raw seg-off) (cons 'formatted (number->string seg-off))))
        (cons 'service-level (list (cons 'raw service-level) (cons 'formatted (number->string service-level))))
        (cons 'reserved2 (list (cons 'raw reserved2) (cons 'formatted (number->string reserved2))))
        (cons 'link-next-header (list (cons 'raw link-next-header) (cons 'formatted (fmt-hex link-next-header))))
        (cons 'destination-local-id (list (cons 'raw destination-local-id) (cons 'formatted (number->string destination-local-id))))
        (cons 'link-vl (list (cons 'raw link-vl) (cons 'formatted (number->string link-vl))))
        (cons 'link-fccl (list (cons 'raw link-fccl) (cons 'formatted (number->string link-fccl))))
        (cons 'seg-id (list (cons 'raw seg-id) (cons 'formatted (number->string seg-id))))
        (cons 'reserved5 (list (cons 'raw reserved5) (cons 'formatted (number->string reserved5))))
        (cons 'packet-length (list (cons 'raw packet-length) (cons 'formatted (number->string packet-length))))
        (cons 'link-lpcrc (list (cons 'raw link-lpcrc) (cons 'formatted (fmt-hex link-lpcrc))))
        (cons 'source-local-id (list (cons 'raw source-local-id) (cons 'formatted (number->string source-local-id))))
        (cons 'GRH (list (cons 'raw GRH) (cons 'formatted (fmt-bytes GRH))))
        (cons 'ip-version (list (cons 'raw ip-version) (cons 'formatted (number->string ip-version))))
        (cons 'traffic-class (list (cons 'raw traffic-class) (cons 'formatted (number->string traffic-class))))
        (cons 'flow-label (list (cons 'raw flow-label) (cons 'formatted (number->string flow-label))))
        (cons 'payload-length (list (cons 'raw payload-length) (cons 'formatted (number->string payload-length))))
        (cons 'next-header (list (cons 'raw next-header) (cons 'formatted (number->string next-header))))
        (cons 'hop-limit (list (cons 'raw hop-limit) (cons 'formatted (number->string hop-limit))))
        (cons 'source-gid (list (cons 'raw source-gid) (cons 'formatted (fmt-ipv6-address source-gid))))
        (cons 'destination-gid (list (cons 'raw destination-gid) (cons 'formatted (fmt-ipv6-address destination-gid))))
        (cons 'BTH (list (cons 'raw BTH) (cons 'formatted (fmt-bytes BTH))))
        (cons 'solicited-event (list (cons 'raw solicited-event) (cons 'formatted (number->string solicited-event))))
        (cons 'migreq (list (cons 'raw migreq) (cons 'formatted (number->string migreq))))
        (cons 'pad-count (list (cons 'raw pad-count) (cons 'formatted (number->string pad-count))))
        (cons 'transport-header-version (list (cons 'raw transport-header-version) (cons 'formatted (number->string transport-header-version))))
        (cons 'partition-key (list (cons 'raw partition-key) (cons 'formatted (number->string partition-key))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'destination-qp (list (cons 'raw destination-qp) (cons 'formatted (fmt-hex destination-qp))))
        (cons 'acknowledge-request (list (cons 'raw acknowledge-request) (cons 'formatted (number->string acknowledge-request))))
        (cons 'reserved7 (list (cons 'raw reserved7) (cons 'formatted (number->string reserved7))))
        (cons 'packet-sequence-number (list (cons 'raw packet-sequence-number) (cons 'formatted (number->string packet-sequence-number))))
        (cons 'raw-data (list (cons 'raw raw-data) (cons 'formatted (fmt-bytes raw-data))))
        (cons 'invariant-crc (list (cons 'raw invariant-crc) (cons 'formatted (fmt-hex invariant-crc))))
        (cons 'variant-crc (list (cons 'raw variant-crc) (cons 'formatted (fmt-hex variant-crc))))
        )))

    (catch (e)
      (err (str "INFINIBAND parse error: " e)))))

;; dissect-infiniband: parse INFINIBAND from bytevector
;; Returns (ok fields-alist) or (err message)