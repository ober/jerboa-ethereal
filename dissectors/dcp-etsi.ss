;; packet-dcp-etsi.c
;; Routines for ETSI Distribution & Communication Protocol
;; Copyright 2006, British Broadcasting Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Protocol info
;; Ref: ETSI DCP (ETSI TS 102 821)
;;

;; jerboa-ethereal/dissectors/dcp-etsi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dcp_etsi.c

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
(def (dissect-dcp-etsi buffer)
  "ETSI Distribution & Communication Protocol (for DRM)"
  (try
    (let* (
           (rs-ok (unwrap (read-u8 buffer 0)))
           (sync (unwrap (slice buffer 0 2)))
           (tlv (unwrap (slice buffer 0 8)))
           (pseq (unwrap (read-u16be buffer 2)))
           (len (unwrap (read-u32be buffer 2)))
           (findex (unwrap (read-u24be buffer 4)))
           (seq (unwrap (read-u16be buffer 6)))
           (fcount (unwrap (read-u24be buffer 7)))
           (crcflag (unwrap (read-u8 buffer 8)))
           (maj (unwrap (read-u8 buffer 8)))
           (min (unwrap (read-u8 buffer 8)))
           (fecflag (unwrap (read-u8 buffer 10)))
           (addrflag (unwrap (read-u8 buffer 10)))
           (plen (unwrap (read-u16be buffer 10)))
           (rsk (unwrap (read-u8 buffer 12)))
           (rsz (unwrap (read-u8 buffer 13)))
           (source (unwrap (read-u16be buffer 14)))
           (dest (unwrap (read-u16be buffer 16)))
           (pft-payload (unwrap (slice buffer 20 1)))
           )

      (ok (list
        (cons 'rs-ok (list (cons 'raw rs-ok) (cons 'formatted (number->string rs-ok))))
        (cons 'sync (list (cons 'raw sync) (cons 'formatted (utf8->string sync))))
        (cons 'tlv (list (cons 'raw tlv) (cons 'formatted (fmt-bytes tlv))))
        (cons 'pseq (list (cons 'raw pseq) (cons 'formatted (number->string pseq))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'findex (list (cons 'raw findex) (cons 'formatted (number->string findex))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'fcount (list (cons 'raw fcount) (cons 'formatted (number->string fcount))))
        (cons 'crcflag (list (cons 'raw crcflag) (cons 'formatted (number->string crcflag))))
        (cons 'maj (list (cons 'raw maj) (cons 'formatted (number->string maj))))
        (cons 'min (list (cons 'raw min) (cons 'formatted (number->string min))))
        (cons 'fecflag (list (cons 'raw fecflag) (cons 'formatted (number->string fecflag))))
        (cons 'addrflag (list (cons 'raw addrflag) (cons 'formatted (number->string addrflag))))
        (cons 'plen (list (cons 'raw plen) (cons 'formatted (number->string plen))))
        (cons 'rsk (list (cons 'raw rsk) (cons 'formatted (number->string rsk))))
        (cons 'rsz (list (cons 'raw rsz) (cons 'formatted (number->string rsz))))
        (cons 'source (list (cons 'raw source) (cons 'formatted (number->string source))))
        (cons 'dest (list (cons 'raw dest) (cons 'formatted (number->string dest))))
        (cons 'pft-payload (list (cons 'raw pft-payload) (cons 'formatted (fmt-bytes pft-payload))))
        )))

    (catch (e)
      (err (str "DCP-ETSI parse error: " e)))))

;; dissect-dcp-etsi: parse DCP-ETSI from bytevector
;; Returns (ok fields-alist) or (err message)