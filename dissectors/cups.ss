;; packet-cups.c
;; Routines for Common Unix Printing System (CUPS) Browsing Protocol
;; packet disassembly for the Wireshark network traffic analyzer.
;;
;; Charles Levert <charles@comm.polymtl.ca>
;; Copyright 2001 Charles Levert
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;

;; jerboa-ethereal/dissectors/cups.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cups.c

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
(def (dissect-cups buffer)
  "Common Unix Printing System (CUPS) Browsing Protocol"
  (try
    (let* (
           (ptype (unwrap (read-u32be buffer 0)))
           (ptype-default (unwrap (read-u8 buffer 0)))
           (ptype-implicit (unwrap (read-u8 buffer 0)))
           (ptype-variable (unwrap (read-u8 buffer 0)))
           (ptype-large (unwrap (read-u8 buffer 0)))
           (ptype-medium (unwrap (read-u8 buffer 0)))
           (ptype-small (unwrap (read-u8 buffer 0)))
           (ptype-sort (unwrap (read-u8 buffer 0)))
           (ptype-bind (unwrap (read-u8 buffer 0)))
           (ptype-cover (unwrap (read-u8 buffer 0)))
           (ptype-punch (unwrap (read-u8 buffer 0)))
           (ptype-collate (unwrap (read-u8 buffer 0)))
           (ptype-copies (unwrap (read-u8 buffer 0)))
           (ptype-staple (unwrap (read-u8 buffer 0)))
           (ptype-duplex (unwrap (read-u8 buffer 0)))
           (ptype-color (unwrap (read-u8 buffer 0)))
           (ptype-bw (unwrap (read-u8 buffer 0)))
           (ptype-remote (unwrap (read-u8 buffer 0)))
           (ptype-class (unwrap (read-u8 buffer 0)))
           (uri (unwrap (slice buffer 0 1)))
           (location (unwrap (slice buffer 0 1)))
           (information (unwrap (slice buffer 0 1)))
           (make-model (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'ptype (list (cons 'raw ptype) (cons 'formatted (fmt-hex ptype))))
        (cons 'ptype-default (list (cons 'raw ptype-default) (cons 'formatted (if (= ptype-default 0) "False" "True"))))
        (cons 'ptype-implicit (list (cons 'raw ptype-implicit) (cons 'formatted (if (= ptype-implicit 0) "Explicit class" "Implicit class"))))
        (cons 'ptype-variable (list (cons 'raw ptype-variable) (cons 'formatted (if (= ptype-variable 0) "False" "True"))))
        (cons 'ptype-large (list (cons 'raw ptype-large) (cons 'formatted (if (= ptype-large 0) "False" "True"))))
        (cons 'ptype-medium (list (cons 'raw ptype-medium) (cons 'formatted (if (= ptype-medium 0) "False" "True"))))
        (cons 'ptype-small (list (cons 'raw ptype-small) (cons 'formatted (if (= ptype-small 0) "False" "True"))))
        (cons 'ptype-sort (list (cons 'raw ptype-sort) (cons 'formatted (if (= ptype-sort 0) "False" "True"))))
        (cons 'ptype-bind (list (cons 'raw ptype-bind) (cons 'formatted (if (= ptype-bind 0) "False" "True"))))
        (cons 'ptype-cover (list (cons 'raw ptype-cover) (cons 'formatted (if (= ptype-cover 0) "False" "True"))))
        (cons 'ptype-punch (list (cons 'raw ptype-punch) (cons 'formatted (if (= ptype-punch 0) "False" "True"))))
        (cons 'ptype-collate (list (cons 'raw ptype-collate) (cons 'formatted (if (= ptype-collate 0) "False" "True"))))
        (cons 'ptype-copies (list (cons 'raw ptype-copies) (cons 'formatted (if (= ptype-copies 0) "False" "True"))))
        (cons 'ptype-staple (list (cons 'raw ptype-staple) (cons 'formatted (if (= ptype-staple 0) "False" "True"))))
        (cons 'ptype-duplex (list (cons 'raw ptype-duplex) (cons 'formatted (if (= ptype-duplex 0) "False" "True"))))
        (cons 'ptype-color (list (cons 'raw ptype-color) (cons 'formatted (if (= ptype-color 0) "False" "True"))))
        (cons 'ptype-bw (list (cons 'raw ptype-bw) (cons 'formatted (if (= ptype-bw 0) "False" "True"))))
        (cons 'ptype-remote (list (cons 'raw ptype-remote) (cons 'formatted (if (= ptype-remote 0) "False" "True"))))
        (cons 'ptype-class (list (cons 'raw ptype-class) (cons 'formatted (if (= ptype-class 0) "Single printer" "Printer class"))))
        (cons 'uri (list (cons 'raw uri) (cons 'formatted (utf8->string uri))))
        (cons 'location (list (cons 'raw location) (cons 'formatted (utf8->string location))))
        (cons 'information (list (cons 'raw information) (cons 'formatted (utf8->string information))))
        (cons 'make-model (list (cons 'raw make-model) (cons 'formatted (utf8->string make-model))))
        )))

    (catch (e)
      (err (str "CUPS parse error: " e)))))

;; dissect-cups: parse CUPS from bytevector
;; Returns (ok fields-alist) or (err message)