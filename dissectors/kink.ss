;; packet-kink.c
;; Routines for KINK packet disassembly
;; It is referenced draft-ietf-kink-kink-jp-04.txt,v 1.14 2003/02/10
;;
;; Copyright 2004, Takeshi Nakashima <T.Nakashima@jp.yokogawa.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/kink.ss
;; Auto-generated from wireshark/epan/dissectors/packet-kink.c

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
(def (dissect-kink buffer)
  "Kerberized Internet Negotiation of Key"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 0)))
           (reserved24 (unwrap (read-u24be buffer 0)))
           (domain-of-interpretation (unwrap (read-u32be buffer 2)))
           (reserved8 (unwrap (read-u8 buffer 5)))
           (payload-length (unwrap (read-u16be buffer 5)))
           (transactionId (unwrap (read-u32be buffer 6)))
           (checkSumLength (unwrap (read-u8 buffer 10)))
           (reserved15 (unwrap (read-u16be buffer 10)))
           (checkSum (unwrap (slice buffer 12 1)))
           (realm-name-length (unwrap (read-u16be buffer 28)))
           (realm-name (unwrap (slice buffer 30 1)))
           (princ-name-length (unwrap (read-u16be buffer 32)))
           (princ-name (unwrap (slice buffer 34 1)))
           (tgt-length (unwrap (read-u16be buffer 34)))
           (tgt (unwrap (slice buffer 36 1)))
           (reserved16 (unwrap (read-u16be buffer 40)))
           (inner-next-pload (unwrap (read-u8 buffer 44)))
           (payload (unwrap (slice buffer 48 1)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'reserved24 (list (cons 'raw reserved24) (cons 'formatted (number->string reserved24))))
        (cons 'domain-of-interpretation (list (cons 'raw domain-of-interpretation) (cons 'formatted (number->string domain-of-interpretation))))
        (cons 'reserved8 (list (cons 'raw reserved8) (cons 'formatted (number->string reserved8))))
        (cons 'payload-length (list (cons 'raw payload-length) (cons 'formatted (number->string payload-length))))
        (cons 'transactionId (list (cons 'raw transactionId) (cons 'formatted (number->string transactionId))))
        (cons 'checkSumLength (list (cons 'raw checkSumLength) (cons 'formatted (number->string checkSumLength))))
        (cons 'reserved15 (list (cons 'raw reserved15) (cons 'formatted (number->string reserved15))))
        (cons 'checkSum (list (cons 'raw checkSum) (cons 'formatted (fmt-bytes checkSum))))
        (cons 'realm-name-length (list (cons 'raw realm-name-length) (cons 'formatted (number->string realm-name-length))))
        (cons 'realm-name (list (cons 'raw realm-name) (cons 'formatted (utf8->string realm-name))))
        (cons 'princ-name-length (list (cons 'raw princ-name-length) (cons 'formatted (number->string princ-name-length))))
        (cons 'princ-name (list (cons 'raw princ-name) (cons 'formatted (utf8->string princ-name))))
        (cons 'tgt-length (list (cons 'raw tgt-length) (cons 'formatted (number->string tgt-length))))
        (cons 'tgt (list (cons 'raw tgt) (cons 'formatted (utf8->string tgt))))
        (cons 'reserved16 (list (cons 'raw reserved16) (cons 'formatted (number->string reserved16))))
        (cons 'inner-next-pload (list (cons 'raw inner-next-pload) (cons 'formatted (number->string inner-next-pload))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        )))

    (catch (e)
      (err (str "KINK parse error: " e)))))

;; dissect-kink: parse KINK from bytevector
;; Returns (ok fields-alist) or (err message)