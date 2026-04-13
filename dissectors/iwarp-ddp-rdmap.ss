;; packet-iwarp-ddp-rdmap.c
;; Routines for Direct Data Placement (DDP) and
;; Remote Direct Memory Access Protocol (RDMAP) dissection
;; According to IETF RFC 5041 and RFC 5040
;; Copyright 2008, Yves Geissbuehler <yves.geissbuehler@gmx.net>
;; Copyright 2008, Philip Frey <frey.philip@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/iwarp-ddp-rdmap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iwarp_ddp_rdmap.c
;; RFC 5041

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
(def (dissect-iwarp-ddp-rdmap buffer)
  "iWARP Direct Data Placement and Remote Direct Memory Access Protocol"
  (try
    (let* (
           (rdma-sinkstag (unwrap (read-u32be buffer 0)))
           (rdma-sinkto (unwrap (read-u64be buffer 0)))
           (rdma-srcstag (unwrap (read-u32be buffer 0)))
           (rdma-srcto (unwrap (read-u64be buffer 0)))
           (ddp-t-flag (unwrap (read-u8 buffer 0)))
           (ddp-l-flag (unwrap (read-u8 buffer 0)))
           (ddp-rsvd (unwrap (read-u8 buffer 0)))
           (ddp-dv (unwrap (read-u8 buffer 0)))
           (ddp-rsvdulp (unwrap (slice buffer 0 1)))
           (rdma-version (unwrap (read-u8 buffer 0)))
           (rdma-rsvd (unwrap (read-u8 buffer 0)))
           (rdma-reserved (unwrap (slice buffer 0 1)))
           (rdma-inval-stag (unwrap (read-u32be buffer 0)))
           (ddp-stag (unwrap (read-u32be buffer 0)))
           (ddp-to (unwrap (read-u64be buffer 0)))
           (ddp-qn (unwrap (read-u32be buffer 0)))
           (ddp-msn (unwrap (read-u32be buffer 0)))
           (ddp-mo (unwrap (read-u32be buffer 0)))
           (rdma-term-etype (unwrap (read-u8 buffer 8)))
           (rdma-term-errcode (unwrap (read-u8 buffer 9)))
           (rdma-term-hdrct-m (unwrap (read-u8 buffer 10)))
           (rdma-term-hdrct-d (unwrap (read-u8 buffer 10)))
           (rdma-term-hdrct-r (unwrap (read-u8 buffer 10)))
           (rdma-term-rsvd (unwrap (read-u16be buffer 10)))
           (rdma-term-ddp-seg-len (unwrap (slice buffer 12 1)))
           (rdma-term-ddp-h (unwrap (slice buffer 12 1)))
           (rdma-term-rdma-h (unwrap (slice buffer 12 1)))
           (rdma-atomic-reserved (unwrap (read-u32be buffer 12)))
           (rdma-atomic-request-identifier (unwrap (read-u32be buffer 16)))
           (rdma-atomic-remote-stag (unwrap (read-u32be buffer 20)))
           (rdma-atomic-remote-tagged-offset (unwrap (read-u64be buffer 24)))
           (rdma-atomic-add-data (unwrap (read-u64be buffer 32)))
           (rdma-atomic-add-mask (unwrap (read-u64be buffer 40)))
           (rdma-atomic-swap-data (unwrap (read-u64be buffer 48)))
           (rdma-atomic-swap-mask (unwrap (read-u64be buffer 56)))
           (rdma-atomic-compare-data (unwrap (read-u64be buffer 64)))
           (rdma-atomic-compare-mask (unwrap (read-u64be buffer 72)))
           (rdma-atomic-original-request-identifier (unwrap (read-u32be buffer 80)))
           (rdma-atomic-original-remote-data-value (unwrap (read-u64be buffer 84)))
           )

      (ok (list
        (cons 'rdma-sinkstag (list (cons 'raw rdma-sinkstag) (cons 'formatted (fmt-hex rdma-sinkstag))))
        (cons 'rdma-sinkto (list (cons 'raw rdma-sinkto) (cons 'formatted (fmt-hex rdma-sinkto))))
        (cons 'rdma-srcstag (list (cons 'raw rdma-srcstag) (cons 'formatted (fmt-hex rdma-srcstag))))
        (cons 'rdma-srcto (list (cons 'raw rdma-srcto) (cons 'formatted (fmt-hex rdma-srcto))))
        (cons 'ddp-t-flag (list (cons 'raw ddp-t-flag) (cons 'formatted (number->string ddp-t-flag))))
        (cons 'ddp-l-flag (list (cons 'raw ddp-l-flag) (cons 'formatted (number->string ddp-l-flag))))
        (cons 'ddp-rsvd (list (cons 'raw ddp-rsvd) (cons 'formatted (fmt-hex ddp-rsvd))))
        (cons 'ddp-dv (list (cons 'raw ddp-dv) (cons 'formatted (number->string ddp-dv))))
        (cons 'ddp-rsvdulp (list (cons 'raw ddp-rsvdulp) (cons 'formatted (fmt-bytes ddp-rsvdulp))))
        (cons 'rdma-version (list (cons 'raw rdma-version) (cons 'formatted (number->string rdma-version))))
        (cons 'rdma-rsvd (list (cons 'raw rdma-rsvd) (cons 'formatted (fmt-hex rdma-rsvd))))
        (cons 'rdma-reserved (list (cons 'raw rdma-reserved) (cons 'formatted (fmt-bytes rdma-reserved))))
        (cons 'rdma-inval-stag (list (cons 'raw rdma-inval-stag) (cons 'formatted (number->string rdma-inval-stag))))
        (cons 'ddp-stag (list (cons 'raw ddp-stag) (cons 'formatted (fmt-hex ddp-stag))))
        (cons 'ddp-to (list (cons 'raw ddp-to) (cons 'formatted (fmt-hex ddp-to))))
        (cons 'ddp-qn (list (cons 'raw ddp-qn) (cons 'formatted (number->string ddp-qn))))
        (cons 'ddp-msn (list (cons 'raw ddp-msn) (cons 'formatted (number->string ddp-msn))))
        (cons 'ddp-mo (list (cons 'raw ddp-mo) (cons 'formatted (number->string ddp-mo))))
        (cons 'rdma-term-etype (list (cons 'raw rdma-term-etype) (cons 'formatted (fmt-hex rdma-term-etype))))
        (cons 'rdma-term-errcode (list (cons 'raw rdma-term-errcode) (cons 'formatted (fmt-hex rdma-term-errcode))))
        (cons 'rdma-term-hdrct-m (list (cons 'raw rdma-term-hdrct-m) (cons 'formatted (if (= rdma-term-hdrct-m 0) "False" "True"))))
        (cons 'rdma-term-hdrct-d (list (cons 'raw rdma-term-hdrct-d) (cons 'formatted (if (= rdma-term-hdrct-d 0) "False" "True"))))
        (cons 'rdma-term-hdrct-r (list (cons 'raw rdma-term-hdrct-r) (cons 'formatted (if (= rdma-term-hdrct-r 0) "False" "True"))))
        (cons 'rdma-term-rsvd (list (cons 'raw rdma-term-rsvd) (cons 'formatted (fmt-hex rdma-term-rsvd))))
        (cons 'rdma-term-ddp-seg-len (list (cons 'raw rdma-term-ddp-seg-len) (cons 'formatted (fmt-bytes rdma-term-ddp-seg-len))))
        (cons 'rdma-term-ddp-h (list (cons 'raw rdma-term-ddp-h) (cons 'formatted (fmt-bytes rdma-term-ddp-h))))
        (cons 'rdma-term-rdma-h (list (cons 'raw rdma-term-rdma-h) (cons 'formatted (fmt-bytes rdma-term-rdma-h))))
        (cons 'rdma-atomic-reserved (list (cons 'raw rdma-atomic-reserved) (cons 'formatted (number->string rdma-atomic-reserved))))
        (cons 'rdma-atomic-request-identifier (list (cons 'raw rdma-atomic-request-identifier) (cons 'formatted (number->string rdma-atomic-request-identifier))))
        (cons 'rdma-atomic-remote-stag (list (cons 'raw rdma-atomic-remote-stag) (cons 'formatted (number->string rdma-atomic-remote-stag))))
        (cons 'rdma-atomic-remote-tagged-offset (list (cons 'raw rdma-atomic-remote-tagged-offset) (cons 'formatted (number->string rdma-atomic-remote-tagged-offset))))
        (cons 'rdma-atomic-add-data (list (cons 'raw rdma-atomic-add-data) (cons 'formatted (number->string rdma-atomic-add-data))))
        (cons 'rdma-atomic-add-mask (list (cons 'raw rdma-atomic-add-mask) (cons 'formatted (fmt-hex rdma-atomic-add-mask))))
        (cons 'rdma-atomic-swap-data (list (cons 'raw rdma-atomic-swap-data) (cons 'formatted (number->string rdma-atomic-swap-data))))
        (cons 'rdma-atomic-swap-mask (list (cons 'raw rdma-atomic-swap-mask) (cons 'formatted (fmt-hex rdma-atomic-swap-mask))))
        (cons 'rdma-atomic-compare-data (list (cons 'raw rdma-atomic-compare-data) (cons 'formatted (number->string rdma-atomic-compare-data))))
        (cons 'rdma-atomic-compare-mask (list (cons 'raw rdma-atomic-compare-mask) (cons 'formatted (fmt-hex rdma-atomic-compare-mask))))
        (cons 'rdma-atomic-original-request-identifier (list (cons 'raw rdma-atomic-original-request-identifier) (cons 'formatted (number->string rdma-atomic-original-request-identifier))))
        (cons 'rdma-atomic-original-remote-data-value (list (cons 'raw rdma-atomic-original-remote-data-value) (cons 'formatted (number->string rdma-atomic-original-remote-data-value))))
        )))

    (catch (e)
      (err (str "IWARP-DDP-RDMAP parse error: " e)))))

;; dissect-iwarp-ddp-rdmap: parse IWARP-DDP-RDMAP from bytevector
;; Returns (ok fields-alist) or (err message)