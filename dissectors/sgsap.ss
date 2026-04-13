;; packet-sgsap.c
;; Routines for SGs Application Part (SGsAP) protocol dissection
;;
;; Copyright 2010 - 2017, Anders Broman <anders.broman@ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References: 3GPP TS 29.118 V10.2.0 (2010-12)
;;

;; jerboa-ethereal/dissectors/sgsap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sgsap.c

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
(def (dissect-sgsap buffer)
  "SGs Application Part (SGsAP)"
  (try
    (let* (
           (mme-name (unwrap (slice buffer 0 1)))
           (vlr-name (unwrap (slice buffer 0 1)))
           (csri (unwrap (read-u8 buffer 0)))
           (sel-cs-dmn-op (unwrap (slice buffer 0 1)))
           (unknown-msg (unwrap (read-u8 buffer 0)))
           (message-elements (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'mme-name (list (cons 'raw mme-name) (cons 'formatted (utf8->string mme-name))))
        (cons 'vlr-name (list (cons 'raw vlr-name) (cons 'formatted (utf8->string vlr-name))))
        (cons 'csri (list (cons 'raw csri) (cons 'formatted (if (= csri 0) "False" "True"))))
        (cons 'sel-cs-dmn-op (list (cons 'raw sel-cs-dmn-op) (cons 'formatted (fmt-bytes sel-cs-dmn-op))))
        (cons 'unknown-msg (list (cons 'raw unknown-msg) (cons 'formatted (fmt-hex unknown-msg))))
        (cons 'message-elements (list (cons 'raw message-elements) (cons 'formatted (fmt-bytes message-elements))))
        )))

    (catch (e)
      (err (str "SGSAP parse error: " e)))))

;; dissect-sgsap: parse SGSAP from bytevector
;; Returns (ok fields-alist) or (err message)