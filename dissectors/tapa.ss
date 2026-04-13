;; packet-tapa.c
;; Routines for the disassembly of the Trapeze TAPA protocol
;;
;; Copyright 2007 Joerg Mayer (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tapa.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tapa.c

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
(def (dissect-tapa buffer)
  "Trapeze Access Point Access Protocol"
  (try
    (let* (
           (discover-reply-switchip (unwrap (read-u32be buffer 0)))
           (tunnel-version (unwrap (read-u8 buffer 0)))
           (tunnel-five (unwrap (read-u8 buffer 0)))
           (discover-flags (unwrap (read-u8 buffer 1)))
           (discover-length (unwrap (read-u16be buffer 2)))
           (tunnel-zero (unwrap (slice buffer 2 8)))
           (discover-reply-unused (unwrap (read-u8 buffer 4)))
           (discover-unknown (unwrap (slice buffer 4 1)))
           (discover-reply-bias (unwrap (read-u8 buffer 5)))
           (discover-reply-pad (unwrap (slice buffer 6 1)))
           (discover-req-pad (unwrap (read-u8 buffer 7)))
           (discover-req-length (unwrap (read-u16be buffer 8)))
           (discover-req-value (unwrap (slice buffer 10 1)))
           (tunnel-dmac (unwrap (slice buffer 10 6)))
           (discover-newtlv-pad (unwrap (read-u8 buffer 11)))
           (discover-newtlv-length (unwrap (read-u16be buffer 12)))
           (discover-newtlv-valuetext (unwrap (slice buffer 14 1)))
           (discover-newtlv-valuehex (unwrap (slice buffer 14 1)))
           (tunnel-smac (unwrap (slice buffer 16 6)))
           (tunnel-0804 (unwrap (read-u16be buffer 22)))
           (tunnel-tagsetc (unwrap (slice buffer 24 6)))
           (tunnel-seqno (unwrap (read-u16be buffer 30)))
           (tunnel-length (unwrap (read-u16be buffer 32)))
           (tunnel-remaining (unwrap (slice buffer 34 1)))
           )

      (ok (list
        (cons 'discover-reply-switchip (list (cons 'raw discover-reply-switchip) (cons 'formatted (fmt-ipv4 discover-reply-switchip))))
        (cons 'tunnel-version (list (cons 'raw tunnel-version) (cons 'formatted (fmt-hex tunnel-version))))
        (cons 'tunnel-five (list (cons 'raw tunnel-five) (cons 'formatted (fmt-hex tunnel-five))))
        (cons 'discover-flags (list (cons 'raw discover-flags) (cons 'formatted (fmt-hex discover-flags))))
        (cons 'discover-length (list (cons 'raw discover-length) (cons 'formatted (number->string discover-length))))
        (cons 'tunnel-zero (list (cons 'raw tunnel-zero) (cons 'formatted (fmt-bytes tunnel-zero))))
        (cons 'discover-reply-unused (list (cons 'raw discover-reply-unused) (cons 'formatted (number->string discover-reply-unused))))
        (cons 'discover-unknown (list (cons 'raw discover-unknown) (cons 'formatted (fmt-bytes discover-unknown))))
        (cons 'discover-reply-bias (list (cons 'raw discover-reply-bias) (cons 'formatted (number->string discover-reply-bias))))
        (cons 'discover-reply-pad (list (cons 'raw discover-reply-pad) (cons 'formatted (fmt-bytes discover-reply-pad))))
        (cons 'discover-req-pad (list (cons 'raw discover-req-pad) (cons 'formatted (number->string discover-req-pad))))
        (cons 'discover-req-length (list (cons 'raw discover-req-length) (cons 'formatted (number->string discover-req-length))))
        (cons 'discover-req-value (list (cons 'raw discover-req-value) (cons 'formatted (fmt-bytes discover-req-value))))
        (cons 'tunnel-dmac (list (cons 'raw tunnel-dmac) (cons 'formatted (fmt-mac tunnel-dmac))))
        (cons 'discover-newtlv-pad (list (cons 'raw discover-newtlv-pad) (cons 'formatted (number->string discover-newtlv-pad))))
        (cons 'discover-newtlv-length (list (cons 'raw discover-newtlv-length) (cons 'formatted (number->string discover-newtlv-length))))
        (cons 'discover-newtlv-valuetext (list (cons 'raw discover-newtlv-valuetext) (cons 'formatted (utf8->string discover-newtlv-valuetext))))
        (cons 'discover-newtlv-valuehex (list (cons 'raw discover-newtlv-valuehex) (cons 'formatted (fmt-bytes discover-newtlv-valuehex))))
        (cons 'tunnel-smac (list (cons 'raw tunnel-smac) (cons 'formatted (fmt-mac tunnel-smac))))
        (cons 'tunnel-0804 (list (cons 'raw tunnel-0804) (cons 'formatted (fmt-hex tunnel-0804))))
        (cons 'tunnel-tagsetc (list (cons 'raw tunnel-tagsetc) (cons 'formatted (fmt-bytes tunnel-tagsetc))))
        (cons 'tunnel-seqno (list (cons 'raw tunnel-seqno) (cons 'formatted (number->string tunnel-seqno))))
        (cons 'tunnel-length (list (cons 'raw tunnel-length) (cons 'formatted (number->string tunnel-length))))
        (cons 'tunnel-remaining (list (cons 'raw tunnel-remaining) (cons 'formatted (fmt-bytes tunnel-remaining))))
        )))

    (catch (e)
      (err (str "TAPA parse error: " e)))))

;; dissect-tapa: parse TAPA from bytevector
;; Returns (ok fields-alist) or (err message)