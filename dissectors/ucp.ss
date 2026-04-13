;; packet-ucp.c
;; Routines for Universal Computer Protocol dissection
;; Copyright 2001, Tom Uijldert <tom.uijldert@cmg.nl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; ----------
;;
;; Dissector of a UCP (Universal Computer Protocol) PDU, as defined for the
;; ERMES paging system in ETS 300 133-3 (2nd final draft, September 1997,
;; www.etsi.org).
;; Includes the extension of EMI-UCP interface
;; (V4.0, May 2001, www.advox.se/download/protocols/EMI_UCP.pdf)
;;
;; Support for statistics using the Stats Tree API added by
;; Abhik Sarkar <sarkar.abhik@gmail.com>
;;
;;

;; jerboa-ethereal/dissectors/ucp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ucp.c

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
(def (dissect-ucp buffer)
  "Universal Computer Protocol"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 0)))
           (data (unwrap (slice buffer 0 1)))
           (hdr-TRN (unwrap (read-u8 buffer 0)))
           (hdr-LEN (unwrap (read-u16be buffer 0)))
           (parm-CPg (unwrap (slice buffer 1 1)))
           (parm-RPLy (unwrap (slice buffer 1 1)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (utf8->string data))))
        (cons 'hdr-TRN (list (cons 'raw hdr-TRN) (cons 'formatted (number->string hdr-TRN))))
        (cons 'hdr-LEN (list (cons 'raw hdr-LEN) (cons 'formatted (number->string hdr-LEN))))
        (cons 'parm-CPg (list (cons 'raw parm-CPg) (cons 'formatted (utf8->string parm-CPg))))
        (cons 'parm-RPLy (list (cons 'raw parm-RPLy) (cons 'formatted (utf8->string parm-RPLy))))
        )))

    (catch (e)
      (err (str "UCP parse error: " e)))))

;; dissect-ucp: parse UCP from bytevector
;; Returns (ok fields-alist) or (err message)