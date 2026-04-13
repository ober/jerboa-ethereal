;; packet-mpeg-pat.c
;; Routines for MPEG2 (ISO/ISO 13818-1) Program Associate Table (PAT) dissection
;; Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mpeg-pat.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mpeg_pat.c

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
(def (dissect-mpeg-pat buffer)
  "MPEG2 Program Association Table"
  (try
    (let* (
           (pat-reserved (unwrap (read-u8 buffer 2)))
           (pat-version-number (unwrap (read-u8 buffer 2)))
           (pat-current-next-indicator (unwrap (read-u8 buffer 2)))
           (pat-section-number (unwrap (read-u8 buffer 3)))
           (pat-last-section-number (unwrap (read-u8 buffer 4)))
           (pat-program-number (unwrap (read-u16be buffer 5)))
           (pat-program-reserved (unwrap (read-u16be buffer 7)))
           (pat-program-map-pid (unwrap (read-u16be buffer 7)))
           (pat-transport-stream-id (unwrap (read-u16be buffer 9)))
           )

      (ok (list
        (cons 'pat-reserved (list (cons 'raw pat-reserved) (cons 'formatted (fmt-hex pat-reserved))))
        (cons 'pat-version-number (list (cons 'raw pat-version-number) (cons 'formatted (fmt-hex pat-version-number))))
        (cons 'pat-current-next-indicator (list (cons 'raw pat-current-next-indicator) (cons 'formatted (if (= pat-current-next-indicator 0) "False" "True"))))
        (cons 'pat-section-number (list (cons 'raw pat-section-number) (cons 'formatted (number->string pat-section-number))))
        (cons 'pat-last-section-number (list (cons 'raw pat-last-section-number) (cons 'formatted (number->string pat-last-section-number))))
        (cons 'pat-program-number (list (cons 'raw pat-program-number) (cons 'formatted (fmt-hex pat-program-number))))
        (cons 'pat-program-reserved (list (cons 'raw pat-program-reserved) (cons 'formatted (fmt-hex pat-program-reserved))))
        (cons 'pat-program-map-pid (list (cons 'raw pat-program-map-pid) (cons 'formatted (fmt-hex pat-program-map-pid))))
        (cons 'pat-transport-stream-id (list (cons 'raw pat-transport-stream-id) (cons 'formatted (fmt-hex pat-transport-stream-id))))
        )))

    (catch (e)
      (err (str "MPEG-PAT parse error: " e)))))

;; dissect-mpeg-pat: parse MPEG-PAT from bytevector
;; Returns (ok fields-alist) or (err message)