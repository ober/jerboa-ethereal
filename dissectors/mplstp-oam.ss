;; packet-mplstp-oam.c
;;
;; Routines for MPLS-TP Lock Instruct Protocol    : RFC 6435
;; MPLS-TP Fault-Management Protocol : RFC 6427
;;
;; Authors:
;; Krishnamurthy Mayya <krishnamurthymayya@gmail.com>
;; Nikitha Malgi <nikitha01@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mplstp-oam.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mplstp_oam.c
;; RFC 6435

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
(def (dissect-mplstp-oam buffer)
  "MPLS-TP Lock-Instruct"
  (try
    (let* (
           (fm-tlv-len (unwrap (read-u8 buffer 0)))
           (fm-node-id (unwrap (read-u32be buffer 0)))
           (fm-if-num (unwrap (read-u32be buffer 0)))
           (fm-global-tlv-type (unwrap (read-u8 buffer 0)))
           (fm-global-id (unwrap (read-u32be buffer 0)))
           (lock-version (unwrap (read-u8 buffer 0)))
           (lock-reserved (unwrap (read-u24be buffer 0)))
           (lock-refresh-timer (unwrap (read-u8 buffer 0)))
           (fm-version (unwrap (read-u8 buffer 0)))
           (fm-reserved (unwrap (read-u8 buffer 0)))
           (fm-flags (unwrap (read-u8 buffer 0)))
           (fm-flags-l (unwrap (read-u8 buffer 0)))
           (fm-flags-r (unwrap (read-u8 buffer 0)))
           (fm-refresh-timer (unwrap (read-u8 buffer 0)))
           (fm-total-tlv-len (unwrap (read-u8 buffer 0)))
           (fm-if-tlv-type (unwrap (read-u8 buffer 4)))
           )

      (ok (list
        (cons 'fm-tlv-len (list (cons 'raw fm-tlv-len) (cons 'formatted (number->string fm-tlv-len))))
        (cons 'fm-node-id (list (cons 'raw fm-node-id) (cons 'formatted (fmt-ipv4 fm-node-id))))
        (cons 'fm-if-num (list (cons 'raw fm-if-num) (cons 'formatted (number->string fm-if-num))))
        (cons 'fm-global-tlv-type (list (cons 'raw fm-global-tlv-type) (cons 'formatted (number->string fm-global-tlv-type))))
        (cons 'fm-global-id (list (cons 'raw fm-global-id) (cons 'formatted (number->string fm-global-id))))
        (cons 'lock-version (list (cons 'raw lock-version) (cons 'formatted (fmt-hex lock-version))))
        (cons 'lock-reserved (list (cons 'raw lock-reserved) (cons 'formatted (fmt-hex lock-reserved))))
        (cons 'lock-refresh-timer (list (cons 'raw lock-refresh-timer) (cons 'formatted (number->string lock-refresh-timer))))
        (cons 'fm-version (list (cons 'raw fm-version) (cons 'formatted (fmt-hex fm-version))))
        (cons 'fm-reserved (list (cons 'raw fm-reserved) (cons 'formatted (fmt-hex fm-reserved))))
        (cons 'fm-flags (list (cons 'raw fm-flags) (cons 'formatted (fmt-hex fm-flags))))
        (cons 'fm-flags-l (list (cons 'raw fm-flags-l) (cons 'formatted (number->string fm-flags-l))))
        (cons 'fm-flags-r (list (cons 'raw fm-flags-r) (cons 'formatted (number->string fm-flags-r))))
        (cons 'fm-refresh-timer (list (cons 'raw fm-refresh-timer) (cons 'formatted (number->string fm-refresh-timer))))
        (cons 'fm-total-tlv-len (list (cons 'raw fm-total-tlv-len) (cons 'formatted (number->string fm-total-tlv-len))))
        (cons 'fm-if-tlv-type (list (cons 'raw fm-if-tlv-type) (cons 'formatted (number->string fm-if-tlv-type))))
        )))

    (catch (e)
      (err (str "MPLSTP-OAM parse error: " e)))))

;; dissect-mplstp-oam: parse MPLSTP-OAM from bytevector
;; Returns (ok fields-alist) or (err message)