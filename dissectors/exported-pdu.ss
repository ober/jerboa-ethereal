;; packet-exported_pdu.c
;; Routines for exported_pdu dissection
;; Copyright 2013, Anders Broman <anders-broman@ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/exported-pdu.ss
;; Auto-generated from wireshark/epan/dissectors/packet-exported_pdu.c

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
(def (dissect-exported-pdu buffer)
  "EXPORTED_PDU"
  (try
    (let* (
           (pdu-tag-len (unwrap (read-u16be buffer 2)))
           (pdu-prot-name (unwrap (slice buffer 4 1)))
           (pdu-heur-prot-name (unwrap (slice buffer 4 1)))
           (pdu-dis-table-name (unwrap (slice buffer 4 1)))
           (pdu-ipv4-src (unwrap (read-u32be buffer 4)))
           (pdu-ipv4-dst (unwrap (read-u32be buffer 4)))
           (pdu-ipv6-src (unwrap (slice buffer 4 16)))
           (pdu-ipv6-dst (unwrap (slice buffer 4 16)))
           (pdu-src-port (unwrap (read-u32be buffer 4)))
           (pdu-dst-port (unwrap (read-u32be buffer 4)))
           (pdu-ss7-opc (unwrap (read-u32be buffer 4)))
           (pdu-ss7-dpc (unwrap (read-u32be buffer 4)))
           (pdu-orig-fno (unwrap (read-u32be buffer 4)))
           (pdu-dis-table-val (unwrap (read-u32be buffer 4)))
           (pdu-col-proto-str (unwrap (slice buffer 4 1)))
           (pdu-dissector-data (unwrap (slice buffer 4 1)))
           (pdu-ddata-version (unwrap (read-u16be buffer 4)))
           (pdu-ddata-seq (unwrap (read-u32be buffer 4)))
           (pdu-ddata-nxtseq (unwrap (read-u32be buffer 4)))
           (pdu-ddata-lastackseq (unwrap (read-u32be buffer 4)))
           (pdu-ddata-is-reassembled (unwrap (read-u8 buffer 4)))
           (pdu-ddata-flags (unwrap (read-u16be buffer 4)))
           (pdu-ddata-urgent-pointer (unwrap (read-u16be buffer 4)))
           (pdu-col-info-str (unwrap (slice buffer 4 1)))
           (pdu-unknown-tag-val (unwrap (slice buffer 4 1)))
           )

      (ok (list
        (cons 'pdu-tag-len (list (cons 'raw pdu-tag-len) (cons 'formatted (number->string pdu-tag-len))))
        (cons 'pdu-prot-name (list (cons 'raw pdu-prot-name) (cons 'formatted (utf8->string pdu-prot-name))))
        (cons 'pdu-heur-prot-name (list (cons 'raw pdu-heur-prot-name) (cons 'formatted (utf8->string pdu-heur-prot-name))))
        (cons 'pdu-dis-table-name (list (cons 'raw pdu-dis-table-name) (cons 'formatted (utf8->string pdu-dis-table-name))))
        (cons 'pdu-ipv4-src (list (cons 'raw pdu-ipv4-src) (cons 'formatted (fmt-ipv4 pdu-ipv4-src))))
        (cons 'pdu-ipv4-dst (list (cons 'raw pdu-ipv4-dst) (cons 'formatted (fmt-ipv4 pdu-ipv4-dst))))
        (cons 'pdu-ipv6-src (list (cons 'raw pdu-ipv6-src) (cons 'formatted (fmt-ipv6-address pdu-ipv6-src))))
        (cons 'pdu-ipv6-dst (list (cons 'raw pdu-ipv6-dst) (cons 'formatted (fmt-ipv6-address pdu-ipv6-dst))))
        (cons 'pdu-src-port (list (cons 'raw pdu-src-port) (cons 'formatted (number->string pdu-src-port))))
        (cons 'pdu-dst-port (list (cons 'raw pdu-dst-port) (cons 'formatted (number->string pdu-dst-port))))
        (cons 'pdu-ss7-opc (list (cons 'raw pdu-ss7-opc) (cons 'formatted (number->string pdu-ss7-opc))))
        (cons 'pdu-ss7-dpc (list (cons 'raw pdu-ss7-dpc) (cons 'formatted (number->string pdu-ss7-dpc))))
        (cons 'pdu-orig-fno (list (cons 'raw pdu-orig-fno) (cons 'formatted (number->string pdu-orig-fno))))
        (cons 'pdu-dis-table-val (list (cons 'raw pdu-dis-table-val) (cons 'formatted (number->string pdu-dis-table-val))))
        (cons 'pdu-col-proto-str (list (cons 'raw pdu-col-proto-str) (cons 'formatted (utf8->string pdu-col-proto-str))))
        (cons 'pdu-dissector-data (list (cons 'raw pdu-dissector-data) (cons 'formatted (fmt-bytes pdu-dissector-data))))
        (cons 'pdu-ddata-version (list (cons 'raw pdu-ddata-version) (cons 'formatted (number->string pdu-ddata-version))))
        (cons 'pdu-ddata-seq (list (cons 'raw pdu-ddata-seq) (cons 'formatted (number->string pdu-ddata-seq))))
        (cons 'pdu-ddata-nxtseq (list (cons 'raw pdu-ddata-nxtseq) (cons 'formatted (number->string pdu-ddata-nxtseq))))
        (cons 'pdu-ddata-lastackseq (list (cons 'raw pdu-ddata-lastackseq) (cons 'formatted (number->string pdu-ddata-lastackseq))))
        (cons 'pdu-ddata-is-reassembled (list (cons 'raw pdu-ddata-is-reassembled) (cons 'formatted (number->string pdu-ddata-is-reassembled))))
        (cons 'pdu-ddata-flags (list (cons 'raw pdu-ddata-flags) (cons 'formatted (fmt-hex pdu-ddata-flags))))
        (cons 'pdu-ddata-urgent-pointer (list (cons 'raw pdu-ddata-urgent-pointer) (cons 'formatted (number->string pdu-ddata-urgent-pointer))))
        (cons 'pdu-col-info-str (list (cons 'raw pdu-col-info-str) (cons 'formatted (utf8->string pdu-col-info-str))))
        (cons 'pdu-unknown-tag-val (list (cons 'raw pdu-unknown-tag-val) (cons 'formatted (fmt-bytes pdu-unknown-tag-val))))
        )))

    (catch (e)
      (err (str "EXPORTED-PDU parse error: " e)))))

;; dissect-exported-pdu: parse EXPORTED-PDU from bytevector
;; Returns (ok fields-alist) or (err message)