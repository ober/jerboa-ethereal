;; packet-uma.c
;; Routines for Unlicensed Mobile Access(UMA) dissection
;; Copyright 2005-2006,2009, Anders Broman <anders.broman[at]ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References:
;; http://www.umatechnology.org/
;; UMA Protocols (Stage 3) R1.0.4 (5/16/2005)
;;
;; 3GPP TS 44.318 version 8.4.0 Release 8
;;
;; https://www.3gpp.org/specifications/specification-numbering
;; 3GPP TS 24.008 V6.2.0 (2003-09)
;; Technical Specification
;; 3rd Generation Partnership Project;
;; Technical Specification Group Core Network;
;; Mobile radio interface Layer 3 specification;
;; Core network protocols; Stage 3
;; (Release 6)
;;
;; 3GPP TS 44.018 V6.11.0 (2005-01)
;; 3rd Generation Partnership Project;
;; Technical Specification Group GSM/EDGE Radio Access Network;
;; Mobile radio interface layer 3 specification;
;; Radio Resource Control (RRC) protocol
;; (Release 6)
;;
;; 3GPP TS 45.009 V6.1.0 (2004-02)
;; 3rd Generation Partnership Project;
;; Technical Specification Group GSM/EDGE
;; Radio Access Network;
;; Link adaptation
;; (Release 6)
;;
;;

;; jerboa-ethereal/dissectors/uma.ss
;; Auto-generated from wireshark/epan/dissectors/packet-uma.c

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
(def (dissect-uma buffer)
  "Unlicensed Mobile Access"
  (try
    (let* (
           (urr-IE-len (unwrap (read-u16be buffer 0)))
           (length-indicator (unwrap (read-u16be buffer 0)))
           (skip-ind (unwrap (read-u8 buffer 0)))
           (urlc-TLLI (unwrap (slice buffer 0 4)))
           (urlc-seq-nr (unwrap (slice buffer 0 2)))
           )

      (ok (list
        (cons 'urr-IE-len (list (cons 'raw urr-IE-len) (cons 'formatted (number->string urr-IE-len))))
        (cons 'length-indicator (list (cons 'raw length-indicator) (cons 'formatted (number->string length-indicator))))
        (cons 'skip-ind (list (cons 'raw skip-ind) (cons 'formatted (number->string skip-ind))))
        (cons 'urlc-TLLI (list (cons 'raw urlc-TLLI) (cons 'formatted (fmt-bytes urlc-TLLI))))
        (cons 'urlc-seq-nr (list (cons 'raw urlc-seq-nr) (cons 'formatted (fmt-bytes urlc-seq-nr))))
        )))

    (catch (e)
      (err (str "UMA parse error: " e)))))

;; dissect-uma: parse UMA from bytevector
;; Returns (ok fields-alist) or (err message)