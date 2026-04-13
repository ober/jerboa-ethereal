;; packet-bthsp.c
;; Routines for Bluetooth Headset Profile (HSP)
;;
;; Copyright 2013, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bthsp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bthsp.c

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
(def (dissect-bthsp buffer)
  "Bluetooth HSP Profile"
  (try
    (let* (
           (hf-data (unwrap (slice buffer 0 1)))
           (hf-ckpd (unwrap (read-u8 buffer 0)))
           (ignored (unwrap (slice buffer 0 1)))
           (command-line-prefix (unwrap (slice buffer 0 2)))
           (hf-fragment (unwrap (slice buffer 0 1)))
           (cmd (unwrap (slice buffer 2 2)))
           (parameter (unwrap (slice buffer 8 1)))
           (hf-parameter (unwrap (slice buffer 8 1)))
           (in (unwrap (read-u32be buffer 11)))
           )

      (ok (list
        (cons 'hf-data (list (cons 'raw hf-data) (cons 'formatted (utf8->string hf-data))))
        (cons 'hf-ckpd (list (cons 'raw hf-ckpd) (cons 'formatted (number->string hf-ckpd))))
        (cons 'ignored (list (cons 'raw ignored) (cons 'formatted (fmt-bytes ignored))))
        (cons 'command-line-prefix (list (cons 'raw command-line-prefix) (cons 'formatted (utf8->string command-line-prefix))))
        (cons 'hf-fragment (list (cons 'raw hf-fragment) (cons 'formatted (utf8->string hf-fragment))))
        (cons 'cmd (list (cons 'raw cmd) (cons 'formatted (utf8->string cmd))))
        (cons 'parameter (list (cons 'raw parameter) (cons 'formatted (utf8->string parameter))))
        (cons 'hf-parameter (list (cons 'raw hf-parameter) (cons 'formatted (utf8->string hf-parameter))))
        (cons 'in (list (cons 'raw in) (cons 'formatted (number->string in))))
        )))

    (catch (e)
      (err (str "BTHSP parse error: " e)))))

;; dissect-bthsp: parse BTHSP from bytevector
;; Returns (ok fields-alist) or (err message)