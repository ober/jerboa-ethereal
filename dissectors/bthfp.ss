;; packet-bthfp.c
;; Routines for Bluetooth Handsfree Profile (HFP)
;;
;; Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
;; Copyright 2006, Ronnie Sahlberg
;; - refactored for Wireshark checkin
;; Copyright 2013, Michal Labedzki for Tieto Corporation
;; - add reassembling
;; - dissection of HFP's AT-commands
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bthfp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bthfp.c

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
(def (dissect-bthfp buffer)
  "Bluetooth HFP Profile"
  (try
    (let* (
           (hf-data (unwrap (slice buffer 0 1)))
           (count (unwrap (read-u16be buffer 0)))
           (accessory-info (unwrap (slice buffer 0 1)))
           (accessory-info-vendor-id (unwrap (read-u32be buffer 0)))
           (host-info (unwrap (slice buffer 0 1)))
           (value (unwrap (read-u32be buffer 0)))
           (response (unwrap (slice buffer 0 1)))
           (mode-1x (unwrap (slice buffer 0 1)))
           (mode-2x (unwrap (slice buffer 0 1)))
           (supported-modes (unwrap (slice buffer 0 1)))
           (number (unwrap (slice buffer 0 1)))
           (alpha (unwrap (slice buffer 0 1)))
           (subaddress (unwrap (slice buffer 0 1)))
           (priority (unwrap (read-u8 buffer 0)))
           (mode (unwrap (read-u8 buffer 0)))
           (keyp (unwrap (read-u8 buffer 0)))
           (disp (unwrap (read-u8 buffer 0)))
           (ind (unwrap (read-u8 buffer 0)))
           (bfr (unwrap (read-u8 buffer 0)))
           (operator (unwrap (slice buffer 0 1)))
           (id (unwrap (read-u32be buffer 0)))
           (dtmf (unwrap (slice buffer 0 1)))
           (duration (unwrap (read-u32be buffer 0)))
           (indicator-index (unwrap (read-u8 buffer 0)))
           (ignored (unwrap (slice buffer 0 1)))
           (command-line-prefix (unwrap (slice buffer 0 2)))
           (hf-fragment (unwrap (slice buffer 0 1)))
           (cmd (unwrap (slice buffer 2 2)))
           (parameter (unwrap (slice buffer 8 1)))
           (hf-parameter (unwrap (slice buffer 8 1)))
           )

      (ok (list
        (cons 'hf-data (list (cons 'raw hf-data) (cons 'formatted (utf8->string hf-data))))
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'accessory-info (list (cons 'raw accessory-info) (cons 'formatted (utf8->string accessory-info))))
        (cons 'accessory-info-vendor-id (list (cons 'raw accessory-info-vendor-id) (cons 'formatted (fmt-hex accessory-info-vendor-id))))
        (cons 'host-info (list (cons 'raw host-info) (cons 'formatted (utf8->string host-info))))
        (cons 'value (list (cons 'raw value) (cons 'formatted (number->string value))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (utf8->string response))))
        (cons 'mode-1x (list (cons 'raw mode-1x) (cons 'formatted (utf8->string mode-1x))))
        (cons 'mode-2x (list (cons 'raw mode-2x) (cons 'formatted (utf8->string mode-2x))))
        (cons 'supported-modes (list (cons 'raw supported-modes) (cons 'formatted (utf8->string supported-modes))))
        (cons 'number (list (cons 'raw number) (cons 'formatted (utf8->string number))))
        (cons 'alpha (list (cons 'raw alpha) (cons 'formatted (utf8->string alpha))))
        (cons 'subaddress (list (cons 'raw subaddress) (cons 'formatted (utf8->string subaddress))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (number->string priority))))
        (cons 'mode (list (cons 'raw mode) (cons 'formatted (number->string mode))))
        (cons 'keyp (list (cons 'raw keyp) (cons 'formatted (number->string keyp))))
        (cons 'disp (list (cons 'raw disp) (cons 'formatted (number->string disp))))
        (cons 'ind (list (cons 'raw ind) (cons 'formatted (number->string ind))))
        (cons 'bfr (list (cons 'raw bfr) (cons 'formatted (number->string bfr))))
        (cons 'operator (list (cons 'raw operator) (cons 'formatted (utf8->string operator))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'dtmf (list (cons 'raw dtmf) (cons 'formatted (utf8->string dtmf))))
        (cons 'duration (list (cons 'raw duration) (cons 'formatted (number->string duration))))
        (cons 'indicator-index (list (cons 'raw indicator-index) (cons 'formatted (number->string indicator-index))))
        (cons 'ignored (list (cons 'raw ignored) (cons 'formatted (fmt-bytes ignored))))
        (cons 'command-line-prefix (list (cons 'raw command-line-prefix) (cons 'formatted (utf8->string command-line-prefix))))
        (cons 'hf-fragment (list (cons 'raw hf-fragment) (cons 'formatted (utf8->string hf-fragment))))
        (cons 'cmd (list (cons 'raw cmd) (cons 'formatted (utf8->string cmd))))
        (cons 'parameter (list (cons 'raw parameter) (cons 'formatted (utf8->string parameter))))
        (cons 'hf-parameter (list (cons 'raw hf-parameter) (cons 'formatted (utf8->string hf-parameter))))
        )))

    (catch (e)
      (err (str "BTHFP parse error: " e)))))

;; dissect-bthfp: parse BTHFP from bytevector
;; Returns (ok fields-alist) or (err message)