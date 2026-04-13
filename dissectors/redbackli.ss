;; packet-redbackli.c
;;
;; Redback Lawful Intercept Packet dissector
;;
;; Copyright 2008 Florian Lohoff <flo[AT]rfc822.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald[AT]wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/redbackli.ss
;; Auto-generated from wireshark/epan/dissectors/packet-redbackli.c

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
(def (dissect-redbackli buffer)
  "Redback Lawful Intercept"
  (try
    (let* (
           (avptype (unwrap (read-u8 buffer 0)))
           (avplen (unwrap (read-u8 buffer 0)))
           (seqno (unwrap (read-u32be buffer 0)))
           (liid (unwrap (read-u32be buffer 0)))
           (sessid (unwrap (read-u32be buffer 0)))
           (label (unwrap (slice buffer 0 1)))
           (eohpad (unwrap (slice buffer 0 1)))
           (dir (unwrap (slice buffer 0 1)))
           (acctid (unwrap (slice buffer 0 1)))
           (unknownavp (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'avptype (list (cons 'raw avptype) (cons 'formatted (number->string avptype))))
        (cons 'avplen (list (cons 'raw avplen) (cons 'formatted (number->string avplen))))
        (cons 'seqno (list (cons 'raw seqno) (cons 'formatted (number->string seqno))))
        (cons 'liid (list (cons 'raw liid) (cons 'formatted (number->string liid))))
        (cons 'sessid (list (cons 'raw sessid) (cons 'formatted (number->string sessid))))
        (cons 'label (list (cons 'raw label) (cons 'formatted (utf8->string label))))
        (cons 'eohpad (list (cons 'raw eohpad) (cons 'formatted (fmt-bytes eohpad))))
        (cons 'dir (list (cons 'raw dir) (cons 'formatted (fmt-bytes dir))))
        (cons 'acctid (list (cons 'raw acctid) (cons 'formatted (fmt-bytes acctid))))
        (cons 'unknownavp (list (cons 'raw unknownavp) (cons 'formatted (fmt-bytes unknownavp))))
        )))

    (catch (e)
      (err (str "REDBACKLI parse error: " e)))))

;; dissect-redbackli: parse REDBACKLI from bytevector
;; Returns (ok fields-alist) or (err message)