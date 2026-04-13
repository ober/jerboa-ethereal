;; packet-amr.c
;; Routines for AMR dissection
;; Copyright 2005-2008, Anders Broman <anders.broman[at]ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References:
;; RFC 3267  https://tools.ietf.org/html/rfc3267
;; RFC 4867  https://tools.ietf.org/html/rfc4867
;; 3GPP TS 26.101 for AMR-NB, 3GPP TS 26.201 for AMR-WB
;;

;; jerboa-ethereal/dissectors/amr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-amr.c
;; RFC 3267

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
(def (dissect-amr buffer)
  "Adaptive Multi-Rate"
  (try
    (let* (
           (if1-fqi (unwrap (read-u8 buffer 0)))
           (if1-sti (unwrap (read-u8 buffer 0)))
           (if2-sti (unwrap (read-u8 buffer 0)))
           (reserved (unwrap (read-u8 buffer 0)))
           (speech-data (unwrap (slice buffer 2 1)))
           (frame-data (unwrap (slice buffer 18 1)))
           )

      (ok (list
        (cons 'if1-fqi (list (cons 'raw if1-fqi) (cons 'formatted (if (= if1-fqi 0) "Severely damaged frame" "Ok"))))
        (cons 'if1-sti (list (cons 'raw if1-sti) (cons 'formatted (if (= if1-sti 0) "SID_FIRST" "SID_UPDATE"))))
        (cons 'if2-sti (list (cons 'raw if2-sti) (cons 'formatted (if (= if2-sti 0) "SID_FIRST" "SID_UPDATE"))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'speech-data (list (cons 'raw speech-data) (cons 'formatted (fmt-bytes speech-data))))
        (cons 'frame-data (list (cons 'raw frame-data) (cons 'formatted (fmt-bytes frame-data))))
        )))

    (catch (e)
      (err (str "AMR parse error: " e)))))

;; dissect-amr: parse AMR from bytevector
;; Returns (ok fields-alist) or (err message)