;; packet-dec-dnart.c
;;
;; Routines for DECnet NSP/RT  disassembly
;;
;; Copyright 2003-2005 Philips Medical Systems
;; Copyright 2003-2005 Fred Hoekstra, Philips Medical Systems.
;; (fred.hoekstra@philips.com)
;;
;; Use was made of the following documentation:
;;
;; DECnet DIGITAL Network Architecture
;; Routing Layer Functional Specification
;; Version 2.0.0 May, 1983
;;
;; DECnet DIGITAL Network Architecture
;; NSP Functional Specification
;; Phase IV, Version 4.0.1, July 1984
;;
;; DNA FS SESSION CONTROL
;; SECON.RNO [31,1]
;; EDITED 10/17/80
;;
;; See
;;
;; http://h71000.www7.hp.com/wizard/decnet/
;;
;; for some DECnet specifications.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dec-dnart.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dec_dnart.c

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
(def (dissect-dec-dnart buffer)
  "DEC DNA Routing Protocol"
  (try
    (let* (
           (rt-ctrl-msg (unwrap (read-u8 buffer 2)))
           (rt-dst-addr (unwrap (slice buffer 5 6)))
           (rt-src-addr (unwrap (slice buffer 13 6)))
           (rt-nl2 (unwrap (read-u8 buffer 19)))
           (rt-visit-count (unwrap (read-u8 buffer 19)))
           (rt-service-class (unwrap (read-u8 buffer 19)))
           (rt-protocol-type (unwrap (read-u8 buffer 19)))
           (rt-short-msg (unwrap (read-u8 buffer 19)))
           (rt-rqr (unwrap (read-u8 buffer 19)))
           (rt-rts (unwrap (read-u8 buffer 19)))
           (rt-visited-nodes (unwrap (read-u8 buffer 23)))
           (rt-dst-node (unwrap (read-u16be buffer 23)))
           (rt-src-node (unwrap (read-u16be buffer 25)))
           (routing-flags (unwrap (read-u8 buffer 27)))
           )

      (ok (list
        (cons 'rt-ctrl-msg (list (cons 'raw rt-ctrl-msg) (cons 'formatted (if (= rt-ctrl-msg 0) "False" "True"))))
        (cons 'rt-dst-addr (list (cons 'raw rt-dst-addr) (cons 'formatted (fmt-mac rt-dst-addr))))
        (cons 'rt-src-addr (list (cons 'raw rt-src-addr) (cons 'formatted (fmt-mac rt-src-addr))))
        (cons 'rt-nl2 (list (cons 'raw rt-nl2) (cons 'formatted (fmt-hex rt-nl2))))
        (cons 'rt-visit-count (list (cons 'raw rt-visit-count) (cons 'formatted (fmt-hex rt-visit-count))))
        (cons 'rt-service-class (list (cons 'raw rt-service-class) (cons 'formatted (fmt-hex rt-service-class))))
        (cons 'rt-protocol-type (list (cons 'raw rt-protocol-type) (cons 'formatted (fmt-hex rt-protocol-type))))
        (cons 'rt-short-msg (list (cons 'raw rt-short-msg) (cons 'formatted (fmt-hex rt-short-msg))))
        (cons 'rt-rqr (list (cons 'raw rt-rqr) (cons 'formatted (if (= rt-rqr 0) "False" "True"))))
        (cons 'rt-rts (list (cons 'raw rt-rts) (cons 'formatted (if (= rt-rts 0) "False" "True"))))
        (cons 'rt-visited-nodes (list (cons 'raw rt-visited-nodes) (cons 'formatted (number->string rt-visited-nodes))))
        (cons 'rt-dst-node (list (cons 'raw rt-dst-node) (cons 'formatted (fmt-hex rt-dst-node))))
        (cons 'rt-src-node (list (cons 'raw rt-src-node) (cons 'formatted (fmt-hex rt-src-node))))
        (cons 'routing-flags (list (cons 'raw routing-flags) (cons 'formatted (fmt-hex routing-flags))))
        )))

    (catch (e)
      (err (str "DEC-DNART parse error: " e)))))

;; dissect-dec-dnart: parse DEC-DNART from bytevector
;; Returns (ok fields-alist) or (err message)