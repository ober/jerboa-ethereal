;; packet-umts_rlc.c
;; Routines for UMTS RLC (Radio Link Control) v9.3.0 disassembly
;; http://www.3gpp.org/ftp/Specs/archive/25_series/25.322/
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/umts-rlc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-umts_rlc.c

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
(def (dissect-umts-rlc buffer)
  "Radio Link Control"
  (try
    (let* (
           (dc (unwrap (read-u8 buffer 0)))
           (duplicate-of (unwrap (read-u32be buffer 0)))
           (header-only (unwrap (read-u8 buffer 0)))
           (seq (unwrap (read-u16be buffer 0)))
           (data (unwrap (slice buffer 0 1)))
           (reassembled-in (unwrap (read-u32be buffer 0)))
           (frag (unwrap (read-u32be buffer 0)))
           (reassembled-data (unwrap (slice buffer 0 1)))
           (rsn (unwrap (read-u8 buffer 4)))
           (r1 (unwrap (read-u8 buffer 5)))
           (ext (unwrap (read-u8 buffer 7)))
           (hfni (unwrap (read-u24be buffer 8)))
           (p (unwrap (read-u8 buffer 13)))
           )

      (ok (list
        (cons 'dc (list (cons 'raw dc) (cons 'formatted (if (= dc 0) "Control" "Data"))))
        (cons 'duplicate-of (list (cons 'raw duplicate-of) (cons 'formatted (number->string duplicate-of))))
        (cons 'header-only (list (cons 'raw header-only) (cons 'formatted (if (= header-only 0) "RLC PDU header and body present" "RLC PDU header only"))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'reassembled-in (list (cons 'raw reassembled-in) (cons 'formatted (number->string reassembled-in))))
        (cons 'frag (list (cons 'raw frag) (cons 'formatted (number->string frag))))
        (cons 'reassembled-data (list (cons 'raw reassembled-data) (cons 'formatted (fmt-bytes reassembled-data))))
        (cons 'rsn (list (cons 'raw rsn) (cons 'formatted (number->string rsn))))
        (cons 'r1 (list (cons 'raw r1) (cons 'formatted (number->string r1))))
        (cons 'ext (list (cons 'raw ext) (cons 'formatted (if (= ext 0) "Next field is data, piggybacked STATUS PDU or padding" "Next field is Length Indicator and E Bit"))))
        (cons 'hfni (list (cons 'raw hfni) (cons 'formatted (number->string hfni))))
        (cons 'p (list (cons 'raw p) (cons 'formatted (if (= p 0) "Status report not requested" "Request a status report"))))
        )))

    (catch (e)
      (err (str "UMTS-RLC parse error: " e)))))

;; dissect-umts-rlc: parse UMTS-RLC from bytevector
;; Returns (ok fields-alist) or (err message)