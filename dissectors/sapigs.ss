;; packet-sapigs.c
;; Routines for SAP IGS (Internet Graphics Server) dissection
;; Copyright 2022, Yvan Genuer (@iggy38), Devoteam
;; Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
;; Code contributed by SecureAuth Corp.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sapigs.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sapigs.c

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
(def (dissect-sapigs buffer)
  "SAP Internet Graphic Server"
  (try
    (let* (
           (function (unwrap (slice buffer 0 32)))
           (listener (unwrap (slice buffer 32 32)))
           (hostname (unwrap (slice buffer 64 81)))
           (id (unwrap (slice buffer 145 4)))
           (padd1 (unwrap (slice buffer 149 15)))
           (flag1 (unwrap (slice buffer 164 1)))
           (padd2 (unwrap (slice buffer 165 20)))
           (flag2 (unwrap (slice buffer 185 1)))
           (padd3 (unwrap (slice buffer 186 6)))
           (portwatcher (unwrap (slice buffer 224 5)))
           (interpreter (unwrap (slice buffer 256 16)))
           (portwatcher-version (unwrap (slice buffer 288 16)))
           (portwatcher-info (unwrap (slice buffer 320 16)))
           (eye-catcher (unwrap (slice buffer 341 10)))
           (padd4 (unwrap (slice buffer 351 2)))
           (codepage (unwrap (slice buffer 353 4)))
           (offset-data (unwrap (slice buffer 357 16)))
           (data-size (unwrap (slice buffer 373 5)))
           (table-version (unwrap (slice buffer 389 40)))
           (table-name (unwrap (slice buffer 437 40)))
           (table-line-number (unwrap (slice buffer 485 40)))
           (table-width (unwrap (slice buffer 533 40)))
           (table-column-name (unwrap (slice buffer 581 40)))
           (table-column-number (unwrap (slice buffer 629 40)))
           (table-column-width (unwrap (slice buffer 677 40)))
           (chart-config (unwrap (slice buffer 725 32)))
           )

      (ok (list
        (cons 'function (list (cons 'raw function) (cons 'formatted (utf8->string function))))
        (cons 'listener (list (cons 'raw listener) (cons 'formatted (utf8->string listener))))
        (cons 'hostname (list (cons 'raw hostname) (cons 'formatted (utf8->string hostname))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (utf8->string id))))
        (cons 'padd1 (list (cons 'raw padd1) (cons 'formatted (utf8->string padd1))))
        (cons 'flag1 (list (cons 'raw flag1) (cons 'formatted (utf8->string flag1))))
        (cons 'padd2 (list (cons 'raw padd2) (cons 'formatted (utf8->string padd2))))
        (cons 'flag2 (list (cons 'raw flag2) (cons 'formatted (utf8->string flag2))))
        (cons 'padd3 (list (cons 'raw padd3) (cons 'formatted (utf8->string padd3))))
        (cons 'portwatcher (list (cons 'raw portwatcher) (cons 'formatted (utf8->string portwatcher))))
        (cons 'interpreter (list (cons 'raw interpreter) (cons 'formatted (utf8->string interpreter))))
        (cons 'portwatcher-version (list (cons 'raw portwatcher-version) (cons 'formatted (utf8->string portwatcher-version))))
        (cons 'portwatcher-info (list (cons 'raw portwatcher-info) (cons 'formatted (utf8->string portwatcher-info))))
        (cons 'eye-catcher (list (cons 'raw eye-catcher) (cons 'formatted (utf8->string eye-catcher))))
        (cons 'padd4 (list (cons 'raw padd4) (cons 'formatted (utf8->string padd4))))
        (cons 'codepage (list (cons 'raw codepage) (cons 'formatted (utf8->string codepage))))
        (cons 'offset-data (list (cons 'raw offset-data) (cons 'formatted (utf8->string offset-data))))
        (cons 'data-size (list (cons 'raw data-size) (cons 'formatted (utf8->string data-size))))
        (cons 'table-version (list (cons 'raw table-version) (cons 'formatted (utf8->string table-version))))
        (cons 'table-name (list (cons 'raw table-name) (cons 'formatted (utf8->string table-name))))
        (cons 'table-line-number (list (cons 'raw table-line-number) (cons 'formatted (utf8->string table-line-number))))
        (cons 'table-width (list (cons 'raw table-width) (cons 'formatted (utf8->string table-width))))
        (cons 'table-column-name (list (cons 'raw table-column-name) (cons 'formatted (utf8->string table-column-name))))
        (cons 'table-column-number (list (cons 'raw table-column-number) (cons 'formatted (utf8->string table-column-number))))
        (cons 'table-column-width (list (cons 'raw table-column-width) (cons 'formatted (utf8->string table-column-width))))
        (cons 'chart-config (list (cons 'raw chart-config) (cons 'formatted (utf8->string chart-config))))
        )))

    (catch (e)
      (err (str "SAPIGS parse error: " e)))))

;; dissect-sapigs: parse SAPIGS from bytevector
;; Returns (ok fields-alist) or (err message)