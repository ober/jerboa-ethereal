;; packet-hdmi.c
;; Routines for HDMI dissection
;; Copyright 2014 Martin Kaiser <martin@kaiser.cx>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hdmi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hdmi.c

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
(def (dissect-hdmi buffer)
  "High-Definition Multimedia Interface"
  (try
    (let* (
           (edid-hdr (unwrap (read-u64be buffer 0)))
           (edid-offset (unwrap (read-u8 buffer 1)))
           (edid-manf-id (unwrap (slice buffer 8 2)))
           (edid-manf-prod-code (unwrap (read-u16be buffer 10)))
           (edid-manf-serial (unwrap (read-u32be buffer 12)))
           (edid-manf-week (unwrap (read-u8 buffer 16)))
           )

      (ok (list
        (cons 'edid-hdr (list (cons 'raw edid-hdr) (cons 'formatted (fmt-hex edid-hdr))))
        (cons 'edid-offset (list (cons 'raw edid-offset) (cons 'formatted (fmt-hex edid-offset))))
        (cons 'edid-manf-id (list (cons 'raw edid-manf-id) (cons 'formatted (utf8->string edid-manf-id))))
        (cons 'edid-manf-prod-code (list (cons 'raw edid-manf-prod-code) (cons 'formatted (fmt-hex edid-manf-prod-code))))
        (cons 'edid-manf-serial (list (cons 'raw edid-manf-serial) (cons 'formatted (number->string edid-manf-serial))))
        (cons 'edid-manf-week (list (cons 'raw edid-manf-week) (cons 'formatted (number->string edid-manf-week))))
        )))

    (catch (e)
      (err (str "HDMI parse error: " e)))))

;; dissect-hdmi: parse HDMI from bytevector
;; Returns (ok fields-alist) or (err message)