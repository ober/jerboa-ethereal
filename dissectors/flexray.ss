;; packet-flexray.c
;; Routines for FlexRay dissection
;; Copyright 2016, Roman Leonhartsberger <ro.leonhartsberger@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/flexray.ss
;; Auto-generated from wireshark/epan/dissectors/packet-flexray.c

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
(def (dissect-flexray buffer)
  "FlexRay Protocol"
  (try
    (let* (
           (ch (unwrap (read-u8 buffer 0)))
           (measurement-header-field (unwrap (read-u8 buffer 0)))
           (fid (unwrap (read-u16be buffer 0)))
           (stfi (unwrap (read-u8 buffer 0)))
           (sfi (unwrap (read-u8 buffer 0)))
           (nfi (unwrap (read-u8 buffer 0)))
           (ppi (unwrap (read-u8 buffer 0)))
           (res (unwrap (read-u8 buffer 0)))
           (frame-header (unwrap (slice buffer 0 1)))
           (error-flags-field (unwrap (read-u8 buffer 1)))
           (fcrc-err (extract-bits error-flags-field 0x0 0))
           (hcrc-err (extract-bits error-flags-field 0x0 0))
           (fes-err (extract-bits error-flags-field 0x0 0))
           (cod-err (extract-bits error-flags-field 0x0 0))
           (tss-viol (extract-bits error-flags-field 0x0 0))
           (sl (unwrap (read-u8 buffer 1)))
           (hcrc (unwrap (read-u24be buffer 2)))
           (pl (unwrap (read-u8 buffer 2)))
           (cc (unwrap (read-u8 buffer 4)))
           )

      (ok (list
        (cons 'ch (list (cons 'raw ch) (cons 'formatted (if (= ch 0) "CHA" "CHB"))))
        (cons 'measurement-header-field (list (cons 'raw measurement-header-field) (cons 'formatted (fmt-hex measurement-header-field))))
        (cons 'fid (list (cons 'raw fid) (cons 'formatted (number->string fid))))
        (cons 'stfi (list (cons 'raw stfi) (cons 'formatted (number->string stfi))))
        (cons 'sfi (list (cons 'raw sfi) (cons 'formatted (number->string sfi))))
        (cons 'nfi (list (cons 'raw nfi) (cons 'formatted (if (= nfi 0) "True" "False"))))
        (cons 'ppi (list (cons 'raw ppi) (cons 'formatted (number->string ppi))))
        (cons 'res (list (cons 'raw res) (cons 'formatted (number->string res))))
        (cons 'frame-header (list (cons 'raw frame-header) (cons 'formatted (fmt-bytes frame-header))))
        (cons 'error-flags-field (list (cons 'raw error-flags-field) (cons 'formatted (fmt-hex error-flags-field))))
        (cons 'fcrc-err (list (cons 'raw fcrc-err) (cons 'formatted (if (= fcrc-err 0) "Not set" "Set"))))
        (cons 'hcrc-err (list (cons 'raw hcrc-err) (cons 'formatted (if (= hcrc-err 0) "Not set" "Set"))))
        (cons 'fes-err (list (cons 'raw fes-err) (cons 'formatted (if (= fes-err 0) "Not set" "Set"))))
        (cons 'cod-err (list (cons 'raw cod-err) (cons 'formatted (if (= cod-err 0) "Not set" "Set"))))
        (cons 'tss-viol (list (cons 'raw tss-viol) (cons 'formatted (if (= tss-viol 0) "Not set" "Set"))))
        (cons 'sl (list (cons 'raw sl) (cons 'formatted (number->string sl))))
        (cons 'hcrc (list (cons 'raw hcrc) (cons 'formatted (fmt-hex hcrc))))
        (cons 'pl (list (cons 'raw pl) (cons 'formatted (number->string pl))))
        (cons 'cc (list (cons 'raw cc) (cons 'formatted (number->string cc))))
        )))

    (catch (e)
      (err (str "FLEXRAY parse error: " e)))))

;; dissect-flexray: parse FLEXRAY from bytevector
;; Returns (ok fields-alist) or (err message)