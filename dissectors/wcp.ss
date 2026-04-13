;; packet-wcp.c
;; Routines for Wellfleet Compression frame disassembly
;; Copyright 2001, Jeffrey C. Foster <jfoste@woodward.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; ToDo:
;; Add preference to allow/disallow decompression
;; Calculate and verify check byte (last byte), if only we knew how!
;; Handle Wellfleet compression over PPP links.
;; - This will require changing the sub-dissector call
;; routine to determine if layer 2 is frame relay or
;; or PPP and different sub-dissector routines for each.
;;
;; Based upon information in the Nortel TCL based Pcaptap code.
;; http://www.mynetworkforum.com/tools/PCAPTAP/pcaptap-Win32-3.00.exe
;;
;; And lzss algorithm
;; http://www.rasip.fer.hr/research/compress/algorithms/fund/lz/lzss.html
;;

;; jerboa-ethereal/dissectors/wcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wcp.c

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
(def (dissect-wcp buffer)
  "Wellfleet Compression"
  (try
    (let* (
           (seq (unwrap (read-u16be buffer 0)))
           (tid (unwrap (read-u16be buffer 0)))
           (rev (unwrap (read-u8 buffer 0)))
           (init (unwrap (read-u8 buffer 0)))
           (seq-size (unwrap (read-u8 buffer 0)))
           (alg-cnt (unwrap (read-u8 buffer 0)))
           (alg-a (unwrap (read-u8 buffer 0)))
           (alg-b (unwrap (read-u8 buffer 0)))
           (alg-c (unwrap (read-u8 buffer 0)))
           (alg-d (unwrap (read-u8 buffer 0)))
           (alg (unwrap (read-u8 buffer 0)))
           (hist-size (unwrap (read-u8 buffer 0)))
           (ppc (unwrap (read-u8 buffer 0)))
           (pib (unwrap (read-u8 buffer 0)))
           )

      (ok (list
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (fmt-hex seq))))
        (cons 'tid (list (cons 'raw tid) (cons 'formatted (number->string tid))))
        (cons 'rev (list (cons 'raw rev) (cons 'formatted (number->string rev))))
        (cons 'init (list (cons 'raw init) (cons 'formatted (number->string init))))
        (cons 'seq-size (list (cons 'raw seq-size) (cons 'formatted (number->string seq-size))))
        (cons 'alg-cnt (list (cons 'raw alg-cnt) (cons 'formatted (number->string alg-cnt))))
        (cons 'alg-a (list (cons 'raw alg-a) (cons 'formatted (number->string alg-a))))
        (cons 'alg-b (list (cons 'raw alg-b) (cons 'formatted (number->string alg-b))))
        (cons 'alg-c (list (cons 'raw alg-c) (cons 'formatted (number->string alg-c))))
        (cons 'alg-d (list (cons 'raw alg-d) (cons 'formatted (number->string alg-d))))
        (cons 'alg (list (cons 'raw alg) (cons 'formatted (number->string alg))))
        (cons 'hist-size (list (cons 'raw hist-size) (cons 'formatted (number->string hist-size))))
        (cons 'ppc (list (cons 'raw ppc) (cons 'formatted (number->string ppc))))
        (cons 'pib (list (cons 'raw pib) (cons 'formatted (number->string pib))))
        )))

    (catch (e)
      (err (str "WCP parse error: " e)))))

;; dissect-wcp: parse WCP from bytevector
;; Returns (ok fields-alist) or (err message)