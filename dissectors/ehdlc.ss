;; packet-ehdlc.c
;; Routines for packet dissection of Ericsson HDLC as used in A-bis over IP
;; Copyright 2010-2012, 2016 by Harald Welte <laforge@gnumonks.org>
;;
;; This code is based on pure educational guesses while looking at protocol
;; traces, as there is no publicly available protocol description by Ericsson.
;; Even the name is a guess, since it looks quite a bit like HDLC and is used
;; by Ericsson, I called it EHDLC.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ehdlc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ehdlc.c

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
(def (dissect-ehdlc buffer)
  "Ericsson HDLC"
  (try
    (let* (
           (csapi (unwrap (read-u8 buffer 4)))
           (ctei (unwrap (read-u8 buffer 4)))
           (c-r (unwrap (read-u8 buffer 4)))
           (sapi (unwrap (read-u8 buffer 4)))
           (tei (unwrap (read-u8 buffer 4)))
           (data-len (unwrap (read-u16be buffer 4)))
           )

      (ok (list
        (cons 'csapi (list (cons 'raw csapi) (cons 'formatted (number->string csapi))))
        (cons 'ctei (list (cons 'raw ctei) (cons 'formatted (number->string ctei))))
        (cons 'c-r (list (cons 'raw c-r) (cons 'formatted (number->string c-r))))
        (cons 'sapi (list (cons 'raw sapi) (cons 'formatted (number->string sapi))))
        (cons 'tei (list (cons 'raw tei) (cons 'formatted (number->string tei))))
        (cons 'data-len (list (cons 'raw data-len) (cons 'formatted (number->string data-len))))
        )))

    (catch (e)
      (err (str "EHDLC parse error: " e)))))

;; dissect-ehdlc: parse EHDLC from bytevector
;; Returns (ok fields-alist) or (err message)