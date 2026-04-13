;; packet-dect.c
;;
;; Dissector for the Digital Enhanced Cordless Telecommunications
;; protocol.
;;
;; Copyright 2008-2009:
;; - Andreas Schuler <andreas (A) schulerdev.de>
;; - Matthias Wenzel <dect (A) mazzoo.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dect.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dect.c

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
(def (dissect-dect buffer)
  "DECT Protocol"
  (try
    (let* (
           (cc-BField (unwrap (slice buffer 0 1)))
           (B (unwrap (slice buffer 0 1)))
           (B-XCRC (unwrap (read-u8 buffer 0)))
           (A (unwrap (slice buffer 0 1)))
           (A-Head (unwrap (read-u8 buffer 0)))
           (A-Head-Q1 (unwrap (read-u8 buffer 0)))
           (A-Head-Q2 (unwrap (read-u8 buffer 0)))
           (A-Tail-Nt (unwrap (slice buffer 0 5)))
           (channel (unwrap (read-u8 buffer 0)))
           (slot (unwrap (read-u16be buffer 0)))
           (A-Tail-Qt-6-Spare (unwrap (read-u16be buffer 2)))
           (framenumber (unwrap (read-u16be buffer 2)))
           (rssi (unwrap (read-u8 buffer 2)))
           (preamble (unwrap (slice buffer 2 3)))
           (A-Tail-Qt-6-Mfn (unwrap (slice buffer 4 3)))
           (type (unwrap (slice buffer 5 2)))
           (A-Tail-Mt-Mh-fmid (unwrap (read-u16be buffer 14)))
           (A-Tail-Mt-Mh-pmid (unwrap (read-u24be buffer 14)))
           (cc-TA (unwrap (slice buffer 17 1)))
           (cc-AField (unwrap (slice buffer 45 1)))
           (A-RCRC (unwrap (read-u8 buffer 50)))
           )

      (ok (list
        (cons 'cc-BField (list (cons 'raw cc-BField) (cons 'formatted (utf8->string cc-BField))))
        (cons 'B (list (cons 'raw B) (cons 'formatted (fmt-bytes B))))
        (cons 'B-XCRC (list (cons 'raw B-XCRC) (cons 'formatted (number->string B-XCRC))))
        (cons 'A (list (cons 'raw A) (cons 'formatted (fmt-bytes A))))
        (cons 'A-Head (list (cons 'raw A-Head) (cons 'formatted (fmt-hex A-Head))))
        (cons 'A-Head-Q1 (list (cons 'raw A-Head-Q1) (cons 'formatted (number->string A-Head-Q1))))
        (cons 'A-Head-Q2 (list (cons 'raw A-Head-Q2) (cons 'formatted (number->string A-Head-Q2))))
        (cons 'A-Tail-Nt (list (cons 'raw A-Tail-Nt) (cons 'formatted (fmt-bytes A-Tail-Nt))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (number->string channel))))
        (cons 'slot (list (cons 'raw slot) (cons 'formatted (number->string slot))))
        (cons 'A-Tail-Qt-6-Spare (list (cons 'raw A-Tail-Qt-6-Spare) (cons 'formatted (fmt-hex A-Tail-Qt-6-Spare))))
        (cons 'framenumber (list (cons 'raw framenumber) (cons 'formatted (number->string framenumber))))
        (cons 'rssi (list (cons 'raw rssi) (cons 'formatted (number->string rssi))))
        (cons 'preamble (list (cons 'raw preamble) (cons 'formatted (fmt-bytes preamble))))
        (cons 'A-Tail-Qt-6-Mfn (list (cons 'raw A-Tail-Qt-6-Mfn) (cons 'formatted (fmt-bytes A-Tail-Qt-6-Mfn))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (fmt-bytes type))))
        (cons 'A-Tail-Mt-Mh-fmid (list (cons 'raw A-Tail-Mt-Mh-fmid) (cons 'formatted (fmt-hex A-Tail-Mt-Mh-fmid))))
        (cons 'A-Tail-Mt-Mh-pmid (list (cons 'raw A-Tail-Mt-Mh-pmid) (cons 'formatted (fmt-hex A-Tail-Mt-Mh-pmid))))
        (cons 'cc-TA (list (cons 'raw cc-TA) (cons 'formatted (utf8->string cc-TA))))
        (cons 'cc-AField (list (cons 'raw cc-AField) (cons 'formatted (utf8->string cc-AField))))
        (cons 'A-RCRC (list (cons 'raw A-RCRC) (cons 'formatted (number->string A-RCRC))))
        )))

    (catch (e)
      (err (str "DECT parse error: " e)))))

;; dissect-dect: parse DECT from bytevector
;; Returns (ok fields-alist) or (err message)