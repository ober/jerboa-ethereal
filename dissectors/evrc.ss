;; packet-evrc.c
;; Routines for:
;; EVRC EVRC-B EVRC-WB EVRC-NW EVRC-NW2K
;; RTP payload header dissection
;;
;; Copyright 2008, Michael Lum <michael.lum [AT] shaw.ca>
;; In association with Star Solutions
;;
;; Title                3GPP2                   Other
;;
;; Enhanced Variable Rate Codec, Speech Service Options 3, 68, 70, 73 and 77
;; for Wideband Spread Spectrum Digital Systems
;; 3GPP2 C.S0014-E v1.0      TIA-127-?
;;
;; RFC 3558  https://tools.ietf.org/html/rfc3558
;; RFC 4788  https://tools.ietf.org/html/rfc4788
;; RFC 5188  https://tools.ietf.org/html/rfc5188
;; draft-agupta-payload-rtp-evrc-nw2k-00
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/evrc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-evrc.c
;; RFC 3558

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
(def (dissect-evrc buffer)
  "Enhanced Variable Rate Codec"
  (try
    (let* (
           (reserved (unwrap (read-u8 buffer 0)))
           (interleave-length (unwrap (read-u8 buffer 0)))
           (interleave-index (unwrap (read-u8 buffer 0)))
           (legacy-toc-fe-ind (unwrap (read-u8 buffer 0)))
           (legacy-toc-reduc-rate (unwrap (read-u8 buffer 0)))
           (reserved-2k (unwrap (read-u8 buffer 0)))
           (enc-capability-2k (unwrap (read-u8 buffer 0)))
           (frame-count (unwrap (read-u8 buffer 0)))
           (padding (unwrap (read-u8 buffer 0)))
           (speech-data (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'interleave-length (list (cons 'raw interleave-length) (cons 'formatted (number->string interleave-length))))
        (cons 'interleave-index (list (cons 'raw interleave-index) (cons 'formatted (number->string interleave-index))))
        (cons 'legacy-toc-fe-ind (list (cons 'raw legacy-toc-fe-ind) (cons 'formatted (if (= legacy-toc-fe-ind 0) "End of ToC entries" "More ToC entries follow"))))
        (cons 'legacy-toc-reduc-rate (list (cons 'raw legacy-toc-reduc-rate) (cons 'formatted (number->string legacy-toc-reduc-rate))))
        (cons 'reserved-2k (list (cons 'raw reserved-2k) (cons 'formatted (fmt-hex reserved-2k))))
        (cons 'enc-capability-2k (list (cons 'raw enc-capability-2k) (cons 'formatted (if (= enc-capability-2k 0) "Mode-0 wideband encoding incapable (i.e. narrowband encoding only)" "Mode-0 wideband encoding capable"))))
        (cons 'frame-count (list (cons 'raw frame-count) (cons 'formatted (number->string frame-count))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (number->string padding))))
        (cons 'speech-data (list (cons 'raw speech-data) (cons 'formatted (fmt-bytes speech-data))))
        )))

    (catch (e)
      (err (str "EVRC parse error: " e)))))

;; dissect-evrc: parse EVRC from bytevector
;; Returns (ok fields-alist) or (err message)