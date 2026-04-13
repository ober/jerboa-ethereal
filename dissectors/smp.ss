;; packet-smp.c
;; Routines for Session Multiplex Protocol (SMP) dissection
;; January 2017 Uli Heilmeier with the help of Michael Mann
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/smp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-smp.c

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
(def (dissect-smp buffer)
  "Session Multiplex Protocol"
  (try
    (let* (
           (flags (unwrap (read-u8 buffer 1)))
           (flags-syn (extract-bits flags 0x0 0))
           (flags-ack (extract-bits flags 0x0 0))
           (flags-fin (extract-bits flags 0x0 0))
           (flags-data (extract-bits flags 0x0 0))
           (sid (unwrap (read-u16be buffer 2)))
           (length (unwrap (read-u32be buffer 4)))
           (seqnum (unwrap (read-u32be buffer 8)))
           (wndw (unwrap (read-u32be buffer 12)))
           (data (unwrap (slice buffer 16 1)))
           (smid (unwrap (read-u8 buffer 17)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-syn (list (cons 'raw flags-syn) (cons 'formatted (if (= flags-syn 0) "Not set" "Set"))))
        (cons 'flags-ack (list (cons 'raw flags-ack) (cons 'formatted (if (= flags-ack 0) "Not set" "Set"))))
        (cons 'flags-fin (list (cons 'raw flags-fin) (cons 'formatted (if (= flags-fin 0) "Not set" "Set"))))
        (cons 'flags-data (list (cons 'raw flags-data) (cons 'formatted (if (= flags-data 0) "Not set" "Set"))))
        (cons 'sid (list (cons 'raw sid) (cons 'formatted (number->string sid))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'seqnum (list (cons 'raw seqnum) (cons 'formatted (fmt-hex seqnum))))
        (cons 'wndw (list (cons 'raw wndw) (cons 'formatted (fmt-hex wndw))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'smid (list (cons 'raw smid) (cons 'formatted (fmt-hex smid))))
        )))

    (catch (e)
      (err (str "SMP parse error: " e)))))

;; dissect-smp: parse SMP from bytevector
;; Returns (ok fields-alist) or (err message)