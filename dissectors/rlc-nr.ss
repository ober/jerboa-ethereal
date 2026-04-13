;; Routines for NR RLC disassembly
;;
;; Pascal Quantin
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rlc-nr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rlc_nr.c

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
(def (dissect-rlc-nr buffer)
  "RLC-NR"
  (try
    (let* (
           (nr-context-sn-length (unwrap (read-u8 buffer 0)))
           (nr-context-pdu-length (unwrap (read-u16be buffer 0)))
           (nr-context-bearer-id (unwrap (read-u16be buffer 0)))
           (nr-context-ueid (unwrap (read-u16be buffer 0)))
           (nr-am-nacks (unwrap (read-u32be buffer 0)))
           (nr-header-only (unwrap (read-u8 buffer 0)))
           (nr-tm (unwrap (slice buffer 0 1)))
           (nr-tm-data (unwrap (slice buffer 0 1)))
           (nr-um (unwrap (slice buffer 0 1)))
           (nr-um-header (unwrap (slice buffer 0 1)))
           (nr-um-sn6 (unwrap (read-u8 buffer 0)))
           (nr-um-sn12 (unwrap (read-u16be buffer 0)))
           (nr-context (unwrap (slice buffer 0 1)))
           (nr-um-so (unwrap (read-u16be buffer 2)))
           (nr-am (unwrap (slice buffer 48 1)))
           (nr-am-header (unwrap (slice buffer 48 1)))
           (nr-am-data-control (unwrap (read-u8 buffer 48)))
           (nr-am-p (unwrap (read-u8 buffer 48)))
           (nr-am-sn12 (unwrap (read-u16be buffer 48)))
           (nr-am-sn18 (unwrap (read-u24be buffer 50)))
           (nr-am-so (unwrap (read-u16be buffer 53)))
           )

      (ok (list
        (cons 'nr-context-sn-length (list (cons 'raw nr-context-sn-length) (cons 'formatted (number->string nr-context-sn-length))))
        (cons 'nr-context-pdu-length (list (cons 'raw nr-context-pdu-length) (cons 'formatted (number->string nr-context-pdu-length))))
        (cons 'nr-context-bearer-id (list (cons 'raw nr-context-bearer-id) (cons 'formatted (number->string nr-context-bearer-id))))
        (cons 'nr-context-ueid (list (cons 'raw nr-context-ueid) (cons 'formatted (number->string nr-context-ueid))))
        (cons 'nr-am-nacks (list (cons 'raw nr-am-nacks) (cons 'formatted (number->string nr-am-nacks))))
        (cons 'nr-header-only (list (cons 'raw nr-header-only) (cons 'formatted (if (= nr-header-only 0) "RLC PDU Headers and body present" "RLC PDU Headers only"))))
        (cons 'nr-tm (list (cons 'raw nr-tm) (cons 'formatted (utf8->string nr-tm))))
        (cons 'nr-tm-data (list (cons 'raw nr-tm-data) (cons 'formatted (fmt-bytes nr-tm-data))))
        (cons 'nr-um (list (cons 'raw nr-um) (cons 'formatted (utf8->string nr-um))))
        (cons 'nr-um-header (list (cons 'raw nr-um-header) (cons 'formatted (utf8->string nr-um-header))))
        (cons 'nr-um-sn6 (list (cons 'raw nr-um-sn6) (cons 'formatted (number->string nr-um-sn6))))
        (cons 'nr-um-sn12 (list (cons 'raw nr-um-sn12) (cons 'formatted (number->string nr-um-sn12))))
        (cons 'nr-context (list (cons 'raw nr-context) (cons 'formatted (utf8->string nr-context))))
        (cons 'nr-um-so (list (cons 'raw nr-um-so) (cons 'formatted (number->string nr-um-so))))
        (cons 'nr-am (list (cons 'raw nr-am) (cons 'formatted (utf8->string nr-am))))
        (cons 'nr-am-header (list (cons 'raw nr-am-header) (cons 'formatted (utf8->string nr-am-header))))
        (cons 'nr-am-data-control (list (cons 'raw nr-am-data-control) (cons 'formatted (if (= nr-am-data-control 0) "False" "True"))))
        (cons 'nr-am-p (list (cons 'raw nr-am-p) (cons 'formatted (if (= nr-am-p 0) "Status report not requested" "Status report is requested"))))
        (cons 'nr-am-sn12 (list (cons 'raw nr-am-sn12) (cons 'formatted (number->string nr-am-sn12))))
        (cons 'nr-am-sn18 (list (cons 'raw nr-am-sn18) (cons 'formatted (number->string nr-am-sn18))))
        (cons 'nr-am-so (list (cons 'raw nr-am-so) (cons 'formatted (number->string nr-am-so))))
        )))

    (catch (e)
      (err (str "RLC-NR parse error: " e)))))

;; dissect-rlc-nr: parse RLC-NR from bytevector
;; Returns (ok fields-alist) or (err message)