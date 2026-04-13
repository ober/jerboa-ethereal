;; packet-udpcp.c
;;
;; Routines for UDPCP packet dissection (UDP-based reliable communication protocol).
;; Described in the Open Base Station Initiative Reference Point 1 Specification
;; (see https://web.archive.org/web/20171206005927/http://www.obsai.com/specs/RP1%20Spec%20v2_1.pdf, Appendix A)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/udpcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-udpcp.c

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
(def (dissect-udpcp buffer)
  "UDPCP"
  (try
    (let* (
           (sn-frame (unwrap (read-u32be buffer 0)))
           (ack-frame (unwrap (read-u32be buffer 0)))
           (checksum (unwrap (read-u32be buffer 0)))
           (version (unwrap (read-u8 buffer 4)))
           (packet-transfer-options (unwrap (slice buffer 4 2)))
           (n (unwrap (read-u8 buffer 4)))
           (c (unwrap (read-u8 buffer 4)))
           (s (unwrap (read-u8 buffer 4)))
           (d (unwrap (read-u8 buffer 4)))
           (reserved (unwrap (read-u8 buffer 4)))
           (fragment-amount (unwrap (read-u8 buffer 4)))
           (fragment-number (unwrap (read-u8 buffer 4)))
           (message-id (unwrap (read-u16be buffer 4)))
           (message-data-length (unwrap (read-u16be buffer 6)))
           (payload (unwrap (slice buffer 8 1)))
           )

      (ok (list
        (cons 'sn-frame (list (cons 'raw sn-frame) (cons 'formatted (number->string sn-frame))))
        (cons 'ack-frame (list (cons 'raw ack-frame) (cons 'formatted (number->string ack-frame))))
        (cons 'checksum (list (cons 'raw checksum) (cons 'formatted (fmt-hex checksum))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'packet-transfer-options (list (cons 'raw packet-transfer-options) (cons 'formatted (utf8->string packet-transfer-options))))
        (cons 'n (list (cons 'raw n) (cons 'formatted (fmt-hex n))))
        (cons 'c (list (cons 'raw c) (cons 'formatted (fmt-hex c))))
        (cons 's (list (cons 'raw s) (cons 'formatted (fmt-hex s))))
        (cons 'd (list (cons 'raw d) (cons 'formatted (fmt-hex d))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'fragment-amount (list (cons 'raw fragment-amount) (cons 'formatted (number->string fragment-amount))))
        (cons 'fragment-number (list (cons 'raw fragment-number) (cons 'formatted (number->string fragment-number))))
        (cons 'message-id (list (cons 'raw message-id) (cons 'formatted (number->string message-id))))
        (cons 'message-data-length (list (cons 'raw message-data-length) (cons 'formatted (number->string message-data-length))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        )))

    (catch (e)
      (err (str "UDPCP parse error: " e)))))

;; dissect-udpcp: parse UDPCP from bytevector
;; Returns (ok fields-alist) or (err message)