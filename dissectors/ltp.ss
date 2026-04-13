;; packet-ltp.c
;; Routines for LTP dissection
;; References:
;; Licklider Transmission Protocol - RFC 5326: https://www.rfc-editor.org/rfc/rfc5326.html
;; RFC 7122: https://www.rfc-editor.org/rfc/rfc7122.html
;; CCSDS 734.2-B-1 - BPv6 blue book
;; CCSDS 734.20-O-1 - BPv7 orange book
;; IANA LTP Registry Group: https://www.iana.org/assignments/ltp-parameters/ltp-parameters.xhtml
;; SANA Client Service ID Registry: https://sanaregistry.org/r/ltp_serviceid/
;;
;; Copyright 2009, Mithun Roy <mithunroy13@gmail.com>
;; Copyright 2017, Krishnamurthy Mayya <krishnamurthymayya@gmail.com>
;; Revision: Minor modifications to Header and Trailer extensions
;; by correcting the offset handling.
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ltp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ltp.c
;; RFC 5326

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
(def (dissect-ltp buffer)
  "Licklider Transmission Protocol"
  (try
    (let* (
           (rpt-clm-lst (unwrap (read-u64be buffer 0)))
           (rpt-clm-fst (unwrap (read-u64be buffer 0)))
           (block-bundle-cnt (unwrap (read-u64be buffer 0)))
           )

      (ok (list
        (cons 'rpt-clm-lst (list (cons 'raw rpt-clm-lst) (cons 'formatted (number->string rpt-clm-lst))))
        (cons 'rpt-clm-fst (list (cons 'raw rpt-clm-fst) (cons 'formatted (number->string rpt-clm-fst))))
        (cons 'block-bundle-cnt (list (cons 'raw block-bundle-cnt) (cons 'formatted (number->string block-bundle-cnt))))
        )))

    (catch (e)
      (err (str "LTP parse error: " e)))))

;; dissect-ltp: parse LTP from bytevector
;; Returns (ok fields-alist) or (err message)