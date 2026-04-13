;; packet-lnet.c
;; Routines for lnet dissection
;; Copyright (c) 2012, 2013, 2017 Intel Corporation.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lnet.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lnet.c

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
(def (dissect-lnet buffer)
  "Lustre Network"
  (try
    (let* (
           (o2ib-connparam-qdepth (unwrap (read-u16be buffer 0)))
           (o2ib-src-cookie (unwrap (read-u64be buffer 0)))
           (o2ib-connparam-max-frags (unwrap (read-u16be buffer 2)))
           (o2ib-connparam-max-size (unwrap (read-u32be buffer 4)))
           (rdma-desc-key (unwrap (read-u32be buffer 8)))
           (o2ib-dest-cookie (unwrap (read-u64be buffer 8)))
           (rdma-desc-nfrags (unwrap (read-u32be buffer 12)))
           (rdma-frag-size (unwrap (read-u32be buffer 16)))
           (rdma-frag-addr (unwrap (read-u64be buffer 20)))
           (o2ib-status (unwrap (read-u32be buffer 24)))
           (nid-addr (unwrap (read-u32be buffer 28)))
           (src-pid (unwrap (read-u32be buffer 28)))
           (nid-interface (unwrap (read-u16be buffer 32)))
           (dest-pid (unwrap (read-u32be buffer 32)))
           (ib-csum (unwrap (read-u32be buffer 36)))
           (ksm-csum (unwrap (read-u32be buffer 36)))
           (payload-length (unwrap (read-u32be buffer 40)))
           (o2ib-cookie (unwrap (read-u64be buffer 52)))
           (data (unwrap (read-u64be buffer 60)))
           (hf-offset (unwrap (read-u32be buffer 72)))
           (offset (unwrap (read-u32be buffer 104)))
           (length (unwrap (read-u32be buffer 108)))
           (incarnation (unwrap (read-u64be buffer 128)))
           (type (unwrap (read-u32be buffer 136)))
           (wmd-interface (unwrap (read-u64be buffer 140)))
           (wmd-object (unwrap (read-u64be buffer 148)))
           (bits (unwrap (read-u64be buffer 156)))
           (hf-mlength (unwrap (read-u32be buffer 164)))
           (ksm-zc-req-cookie (unwrap (read-u64be buffer 172)))
           (ksm-zc-ack-cookie (unwrap (read-u64be buffer 180)))
           (ib-credits (unwrap (read-u8 buffer 195)))
           (ib-nob (unwrap (read-u32be buffer 196)))
           )

      (ok (list
        (cons 'o2ib-connparam-qdepth (list (cons 'raw o2ib-connparam-qdepth) (cons 'formatted (number->string o2ib-connparam-qdepth))))
        (cons 'o2ib-src-cookie (list (cons 'raw o2ib-src-cookie) (cons 'formatted (fmt-hex o2ib-src-cookie))))
        (cons 'o2ib-connparam-max-frags (list (cons 'raw o2ib-connparam-max-frags) (cons 'formatted (number->string o2ib-connparam-max-frags))))
        (cons 'o2ib-connparam-max-size (list (cons 'raw o2ib-connparam-max-size) (cons 'formatted (number->string o2ib-connparam-max-size))))
        (cons 'rdma-desc-key (list (cons 'raw rdma-desc-key) (cons 'formatted (fmt-hex rdma-desc-key))))
        (cons 'o2ib-dest-cookie (list (cons 'raw o2ib-dest-cookie) (cons 'formatted (fmt-hex o2ib-dest-cookie))))
        (cons 'rdma-desc-nfrags (list (cons 'raw rdma-desc-nfrags) (cons 'formatted (number->string rdma-desc-nfrags))))
        (cons 'rdma-frag-size (list (cons 'raw rdma-frag-size) (cons 'formatted (number->string rdma-frag-size))))
        (cons 'rdma-frag-addr (list (cons 'raw rdma-frag-addr) (cons 'formatted (fmt-hex rdma-frag-addr))))
        (cons 'o2ib-status (list (cons 'raw o2ib-status) (cons 'formatted (number->string o2ib-status))))
        (cons 'nid-addr (list (cons 'raw nid-addr) (cons 'formatted (fmt-ipv4 nid-addr))))
        (cons 'src-pid (list (cons 'raw src-pid) (cons 'formatted (number->string src-pid))))
        (cons 'nid-interface (list (cons 'raw nid-interface) (cons 'formatted (number->string nid-interface))))
        (cons 'dest-pid (list (cons 'raw dest-pid) (cons 'formatted (number->string dest-pid))))
        (cons 'ib-csum (list (cons 'raw ib-csum) (cons 'formatted (number->string ib-csum))))
        (cons 'ksm-csum (list (cons 'raw ksm-csum) (cons 'formatted (number->string ksm-csum))))
        (cons 'payload-length (list (cons 'raw payload-length) (cons 'formatted (number->string payload-length))))
        (cons 'o2ib-cookie (list (cons 'raw o2ib-cookie) (cons 'formatted (fmt-hex o2ib-cookie))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-hex data))))
        (cons 'hf-offset (list (cons 'raw hf-offset) (cons 'formatted (number->string hf-offset))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (number->string offset))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'incarnation (list (cons 'raw incarnation) (cons 'formatted (fmt-hex incarnation))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (number->string type))))
        (cons 'wmd-interface (list (cons 'raw wmd-interface) (cons 'formatted (fmt-hex wmd-interface))))
        (cons 'wmd-object (list (cons 'raw wmd-object) (cons 'formatted (fmt-hex wmd-object))))
        (cons 'bits (list (cons 'raw bits) (cons 'formatted (fmt-hex bits))))
        (cons 'hf-mlength (list (cons 'raw hf-mlength) (cons 'formatted (number->string hf-mlength))))
        (cons 'ksm-zc-req-cookie (list (cons 'raw ksm-zc-req-cookie) (cons 'formatted (fmt-hex ksm-zc-req-cookie))))
        (cons 'ksm-zc-ack-cookie (list (cons 'raw ksm-zc-ack-cookie) (cons 'formatted (fmt-hex ksm-zc-ack-cookie))))
        (cons 'ib-credits (list (cons 'raw ib-credits) (cons 'formatted (number->string ib-credits))))
        (cons 'ib-nob (list (cons 'raw ib-nob) (cons 'formatted (number->string ib-nob))))
        )))

    (catch (e)
      (err (str "LNET parse error: " e)))))

;; dissect-lnet: parse LNET from bytevector
;; Returns (ok fields-alist) or (err message)