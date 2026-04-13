;; packet-sctp.c
;; Routines for Stream Control Transmission Protocol dissection
;; Copyright 2000-2012 Michael Tuexen <tuexen [AT] fh-muenster.de>
;; Copyright 2011-2021 Thomas Dreibholz <dreibh [AT] iem.uni-due.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sctp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sctp.c
;; RFC 2960

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
(def (dissect-sctp buffer)
  "Stream Control Transmission Protocol"
  (try
    (let* (
           (assoc-index (unwrap (read-u16be buffer 0)))
           (reassembled-in (unwrap (read-u32be buffer 0)))
           (duplicate (unwrap (read-u32be buffer 0)))
           (ack-tsn (unwrap (read-u32be buffer 0)))
           (acked (unwrap (read-u32be buffer 0)))
           (retransmitted (unwrap (read-u32be buffer 0)))
           (retransmitted-count (unwrap (read-u32be buffer 0)))
           (retransmitted-after-ack (unwrap (read-u32be buffer 0)))
           (retransmission (unwrap (read-u32be buffer 0)))
           )

      (ok (list
        (cons 'assoc-index (list (cons 'raw assoc-index) (cons 'formatted (number->string assoc-index))))
        (cons 'reassembled-in (list (cons 'raw reassembled-in) (cons 'formatted (number->string reassembled-in))))
        (cons 'duplicate (list (cons 'raw duplicate) (cons 'formatted (number->string duplicate))))
        (cons 'ack-tsn (list (cons 'raw ack-tsn) (cons 'formatted (number->string ack-tsn))))
        (cons 'acked (list (cons 'raw acked) (cons 'formatted (number->string acked))))
        (cons 'retransmitted (list (cons 'raw retransmitted) (cons 'formatted (number->string retransmitted))))
        (cons 'retransmitted-count (list (cons 'raw retransmitted-count) (cons 'formatted (number->string retransmitted-count))))
        (cons 'retransmitted-after-ack (list (cons 'raw retransmitted-after-ack) (cons 'formatted (number->string retransmitted-after-ack))))
        (cons 'retransmission (list (cons 'raw retransmission) (cons 'formatted (number->string retransmission))))
        )))

    (catch (e)
      (err (str "SCTP parse error: " e)))))

;; dissect-sctp: parse SCTP from bytevector
;; Returns (ok fields-alist) or (err message)