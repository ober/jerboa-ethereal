;; packet-gsm_um.c
;; Routines for GSM Um packet disassembly
;; Duncan Salerno <duncan.salerno@googlemail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-um.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_um.c

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
(def (dissect-gsm-um buffer)
  "GSM Um Interface"
  (try
    (let* (
           (um-l2-pseudo-len (unwrap (read-u8 buffer 0)))
           (um-timeshift (unwrap (read-u16be buffer 0)))
           (um-error (unwrap (read-u8 buffer 0)))
           (um-frame (unwrap (read-u32be buffer 0)))
           (um-bsic (unwrap (read-u8 buffer 0)))
           (um-frequency (unwrap (read-u32be buffer 0)))
           (um-band (unwrap (slice buffer 0 1)))
           (um-arfcn (unwrap (read-u16be buffer 0)))
           (um-channel (unwrap (slice buffer 0 1)))
           (um-direction (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'um-l2-pseudo-len (list (cons 'raw um-l2-pseudo-len) (cons 'formatted (number->string um-l2-pseudo-len))))
        (cons 'um-timeshift (list (cons 'raw um-timeshift) (cons 'formatted (number->string um-timeshift))))
        (cons 'um-error (list (cons 'raw um-error) (cons 'formatted (number->string um-error))))
        (cons 'um-frame (list (cons 'raw um-frame) (cons 'formatted (number->string um-frame))))
        (cons 'um-bsic (list (cons 'raw um-bsic) (cons 'formatted (number->string um-bsic))))
        (cons 'um-frequency (list (cons 'raw um-frequency) (cons 'formatted (number->string um-frequency))))
        (cons 'um-band (list (cons 'raw um-band) (cons 'formatted (utf8->string um-band))))
        (cons 'um-arfcn (list (cons 'raw um-arfcn) (cons 'formatted (number->string um-arfcn))))
        (cons 'um-channel (list (cons 'raw um-channel) (cons 'formatted (utf8->string um-channel))))
        (cons 'um-direction (list (cons 'raw um-direction) (cons 'formatted (utf8->string um-direction))))
        )))

    (catch (e)
      (err (str "GSM-UM parse error: " e)))))

;; dissect-gsm-um: parse GSM-UM from bytevector
;; Returns (ok fields-alist) or (err message)