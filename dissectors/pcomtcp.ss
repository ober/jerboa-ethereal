;; packet-pcomtcp.c
;; Routines for PCOM/TCP dissection
;; Copyright 2018, Luis Rosa <lmrosa@dei.uc.pt>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pcomtcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pcomtcp.c

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
(def (dissect-pcomtcp buffer)
  "PCOM/TCP"
  (try
    (let* (
           (transid (unwrap (read-u16be buffer 0)))
           (stx (unwrap (slice buffer 0 6)))
           (reserved (unwrap (read-u8 buffer 3)))
           (unitid (unwrap (read-u16be buffer 3)))
           (command-code (unwrap (slice buffer 5 1)))
           (address (unwrap (slice buffer 5 4)))
           (id (unwrap (read-u8 buffer 7)))
           (length (unwrap (slice buffer 9 2)))
           (reserved1 (unwrap (read-u8 buffer 9)))
           (reserved2 (unwrap (read-u8 buffer 10)))
           (address-value (unwrap (slice buffer 11 1)))
           (checksum (unwrap (read-u16be buffer 11)))
           (reserved3 (unwrap (read-u24be buffer 11)))
           (command (unwrap (read-u8 buffer 14)))
           (reserved4 (unwrap (read-u8 buffer 15)))
           (command-specific (unwrap (slice buffer 16 6)))
           (data-length (unwrap (read-u16be buffer 22)))
           (header-checksum (unwrap (read-u16be buffer 24)))
           (data (unwrap (slice buffer 26 1)))
           (footer-checksum (unwrap (read-u16be buffer 26)))
           (etx (unwrap (slice buffer 28 1)))
           )

      (ok (list
        (cons 'transid (list (cons 'raw transid) (cons 'formatted (number->string transid))))
        (cons 'stx (list (cons 'raw stx) (cons 'formatted (utf8->string stx))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'unitid (list (cons 'raw unitid) (cons 'formatted (fmt-hex unitid))))
        (cons 'command-code (list (cons 'raw command-code) (cons 'formatted (utf8->string command-code))))
        (cons 'address (list (cons 'raw address) (cons 'formatted (utf8->string address))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (utf8->string length))))
        (cons 'reserved1 (list (cons 'raw reserved1) (cons 'formatted (fmt-hex reserved1))))
        (cons 'reserved2 (list (cons 'raw reserved2) (cons 'formatted (fmt-hex reserved2))))
        (cons 'address-value (list (cons 'raw address-value) (cons 'formatted (utf8->string address-value))))
        (cons 'checksum (list (cons 'raw checksum) (cons 'formatted (fmt-hex checksum))))
        (cons 'reserved3 (list (cons 'raw reserved3) (cons 'formatted (fmt-hex reserved3))))
        (cons 'command (list (cons 'raw command) (cons 'formatted (fmt-hex command))))
        (cons 'reserved4 (list (cons 'raw reserved4) (cons 'formatted (fmt-hex reserved4))))
        (cons 'command-specific (list (cons 'raw command-specific) (cons 'formatted (fmt-bytes command-specific))))
        (cons 'data-length (list (cons 'raw data-length) (cons 'formatted (number->string data-length))))
        (cons 'header-checksum (list (cons 'raw header-checksum) (cons 'formatted (fmt-hex header-checksum))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'footer-checksum (list (cons 'raw footer-checksum) (cons 'formatted (fmt-hex footer-checksum))))
        (cons 'etx (list (cons 'raw etx) (cons 'formatted (utf8->string etx))))
        )))

    (catch (e)
      (err (str "PCOMTCP parse error: " e)))))

;; dissect-pcomtcp: parse PCOMTCP from bytevector
;; Returns (ok fields-alist) or (err message)