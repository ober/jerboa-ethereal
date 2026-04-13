;; packet-rdp_ecam.c
;; Routines for the CONCTRL RDP channel
;; Copyright 2025, David Fort <contact@hardening-consulting.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rdp-ecam.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rdp_ecam.c

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
(def (dissect-rdp-ecam buffer)
  "RDP Video Capture Virtual Channel Extension"
  (try
    (let* (
           (stream-frameSource (unwrap (read-u16be buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (streamIndex (unwrap (read-u8 buffer 1)))
           (stream-category (unwrap (read-u8 buffer 2)))
           (stream-selected (unwrap (read-u8 buffer 2)))
           (stream-canBeShared (unwrap (read-u8 buffer 2)))
           (media-width (unwrap (read-u32be buffer 2)))
           (media-height (unwrap (read-u32be buffer 6)))
           (media-framerate-numerator (unwrap (read-u32be buffer 10)))
           (media-framerate-denominator (unwrap (read-u32be buffer 14)))
           (media-aspect-ratio-numerator (unwrap (read-u32be buffer 18)))
           (media-aspect-ratio-denominator (unwrap (read-u32be buffer 22)))
           (media-flags (unwrap (read-u8 buffer 26)))
           )

      (ok (list
        (cons 'stream-frameSource (list (cons 'raw stream-frameSource) (cons 'formatted (fmt-hex stream-frameSource))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'streamIndex (list (cons 'raw streamIndex) (cons 'formatted (number->string streamIndex))))
        (cons 'stream-category (list (cons 'raw stream-category) (cons 'formatted (fmt-hex stream-category))))
        (cons 'stream-selected (list (cons 'raw stream-selected) (cons 'formatted (fmt-hex stream-selected))))
        (cons 'stream-canBeShared (list (cons 'raw stream-canBeShared) (cons 'formatted (fmt-hex stream-canBeShared))))
        (cons 'media-width (list (cons 'raw media-width) (cons 'formatted (number->string media-width))))
        (cons 'media-height (list (cons 'raw media-height) (cons 'formatted (number->string media-height))))
        (cons 'media-framerate-numerator (list (cons 'raw media-framerate-numerator) (cons 'formatted (number->string media-framerate-numerator))))
        (cons 'media-framerate-denominator (list (cons 'raw media-framerate-denominator) (cons 'formatted (number->string media-framerate-denominator))))
        (cons 'media-aspect-ratio-numerator (list (cons 'raw media-aspect-ratio-numerator) (cons 'formatted (number->string media-aspect-ratio-numerator))))
        (cons 'media-aspect-ratio-denominator (list (cons 'raw media-aspect-ratio-denominator) (cons 'formatted (number->string media-aspect-ratio-denominator))))
        (cons 'media-flags (list (cons 'raw media-flags) (cons 'formatted (fmt-hex media-flags))))
        )))

    (catch (e)
      (err (str "RDP-ECAM parse error: " e)))))

;; dissect-rdp-ecam: parse RDP-ECAM from bytevector
;; Returns (ok fields-alist) or (err message)