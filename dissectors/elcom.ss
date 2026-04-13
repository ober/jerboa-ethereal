;; packet-elcom.c
;; Routines for elcom packet dissection
;; Copyright 2008, 2011 juha.takala@iki.fi (Juha Takala)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-imap.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; I found the protocol specification at
;; http://www.sintef.no/upload/Energiforskning/Energisystemer/ELCOM%2090.pdf
;;

;; jerboa-ethereal/dissectors/elcom.ss
;; Auto-generated from wireshark/epan/dissectors/packet-elcom.c

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
(def (dissect-elcom buffer)
  "ELCOM Communication Protocol"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 0)))
           (release-reason (unwrap (read-u8 buffer 0)))
           (release-result (unwrap (read-u8 buffer 1)))
           (strangeleftover (unwrap (slice buffer 2 1)))
           (userdata-length (unwrap (read-u8 buffer 18)))
           (userdata-restmark (unwrap (read-u8 buffer 18)))
           (datarequest-groupnumber (unwrap (read-u8 buffer 32)))
           (datarequest-grouppriority (unwrap (read-u8 buffer 33)))
           (datarequest-groupsize (unwrap (read-u8 buffer 34)))
           (datarequest-groupindex1 (unwrap (read-u16be buffer 35)))
           (datarequest-groupindex2 (unwrap (read-u16be buffer 37)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'release-reason (list (cons 'raw release-reason) (cons 'formatted (number->string release-reason))))
        (cons 'release-result (list (cons 'raw release-result) (cons 'formatted (number->string release-result))))
        (cons 'strangeleftover (list (cons 'raw strangeleftover) (cons 'formatted (fmt-bytes strangeleftover))))
        (cons 'userdata-length (list (cons 'raw userdata-length) (cons 'formatted (number->string userdata-length))))
        (cons 'userdata-restmark (list (cons 'raw userdata-restmark) (cons 'formatted (number->string userdata-restmark))))
        (cons 'datarequest-groupnumber (list (cons 'raw datarequest-groupnumber) (cons 'formatted (number->string datarequest-groupnumber))))
        (cons 'datarequest-grouppriority (list (cons 'raw datarequest-grouppriority) (cons 'formatted (number->string datarequest-grouppriority))))
        (cons 'datarequest-groupsize (list (cons 'raw datarequest-groupsize) (cons 'formatted (number->string datarequest-groupsize))))
        (cons 'datarequest-groupindex1 (list (cons 'raw datarequest-groupindex1) (cons 'formatted (number->string datarequest-groupindex1))))
        (cons 'datarequest-groupindex2 (list (cons 'raw datarequest-groupindex2) (cons 'formatted (number->string datarequest-groupindex2))))
        )))

    (catch (e)
      (err (str "ELCOM parse error: " e)))))

;; dissect-elcom: parse ELCOM from bytevector
;; Returns (ok fields-alist) or (err message)