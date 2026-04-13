;; packet-tn5250.c
;; Routines for tn5250.packet dissection
;;
;; Reference:
;; 5494 Remote Control Unit - Functions Reference
;; Release 3.0 Document Number SC30-3533-04
;; Chapters 12, 15, 16
;; http://publibfp.dhe.ibm.com/cgi-bin/bookmgr/BOOKS/co2e2001/CCONTENTS
;; [Found in 2020 in https://archive.org/details/5494RemoteControlUnitFunctionsReferenceSC30353304]
;;
;; Copyright 2009, Robert Hogan <robert@roberthogan.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tn5250.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tn5250.c

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
(def (dissect-tn5250 buffer)
  "TN5250 Protocol"
  (try
    (let* (
           (buffer-x (unwrap (read-u8 buffer 0)))
           (buffer-y (unwrap (read-u8 buffer 0)))
           (wea-prim-attr (unwrap (read-u8 buffer 2)))
           (ds-output-error (extract-bits wea-prim-attr 0x80 7))
           (attn-key (extract-bits wea-prim-attr 0x40 6))
           (sys-request-key (extract-bits wea-prim-attr 0x4 2))
           (test-request-key (extract-bits wea-prim-attr 0x2 1))
           (error-state (extract-bits wea-prim-attr 0x1 0))
           (wdsf-ds-ct-numeric-onebyte (unwrap (read-u8 buffer 6)))
           (wdsf-ds-ct-numeric-twobyte (unwrap (read-u16be buffer 6)))
           (wssf-ifd-imagefax-name (unwrap (slice buffer 12 1)))
           (vac-prefix (unwrap (read-u16be buffer 12)))
           (length (unwrap (read-u8 buffer 17)))
           (dpt-ec (unwrap (slice buffer 17 4)))
           (fa (unwrap (read-u8 buffer 21)))
           (wectw-start-column (unwrap (read-u8 buffer 21)))
           (wectw-end-column (unwrap (read-u8 buffer 21)))
           (length-twobyte (unwrap (read-u16be buffer 21)))
           (ctp-lsid (unwrap (read-u8 buffer 21)))
           (ctp-mlpp (unwrap (read-u8 buffer 21)))
           (unknown-data (unwrap (slice buffer 29 1)))
           (field-data (unwrap (slice buffer 29 1)))
           )

      (ok (list
        (cons 'buffer-x (list (cons 'raw buffer-x) (cons 'formatted (number->string buffer-x))))
        (cons 'buffer-y (list (cons 'raw buffer-y) (cons 'formatted (number->string buffer-y))))
        (cons 'wea-prim-attr (list (cons 'raw wea-prim-attr) (cons 'formatted (fmt-hex wea-prim-attr))))
        (cons 'ds-output-error (list (cons 'raw ds-output-error) (cons 'formatted (if (= ds-output-error 0) "Not set" "Set"))))
        (cons 'attn-key (list (cons 'raw attn-key) (cons 'formatted (if (= attn-key 0) "Not set" "Set"))))
        (cons 'sys-request-key (list (cons 'raw sys-request-key) (cons 'formatted (if (= sys-request-key 0) "Not set" "Set"))))
        (cons 'test-request-key (list (cons 'raw test-request-key) (cons 'formatted (if (= test-request-key 0) "Not set" "Set"))))
        (cons 'error-state (list (cons 'raw error-state) (cons 'formatted (if (= error-state 0) "Not set" "Set"))))
        (cons 'wdsf-ds-ct-numeric-onebyte (list (cons 'raw wdsf-ds-ct-numeric-onebyte) (cons 'formatted (fmt-hex wdsf-ds-ct-numeric-onebyte))))
        (cons 'wdsf-ds-ct-numeric-twobyte (list (cons 'raw wdsf-ds-ct-numeric-twobyte) (cons 'formatted (fmt-hex wdsf-ds-ct-numeric-twobyte))))
        (cons 'wssf-ifd-imagefax-name (list (cons 'raw wssf-ifd-imagefax-name) (cons 'formatted (utf8->string wssf-ifd-imagefax-name))))
        (cons 'vac-prefix (list (cons 'raw vac-prefix) (cons 'formatted (fmt-hex vac-prefix))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'dpt-ec (list (cons 'raw dpt-ec) (cons 'formatted (utf8->string dpt-ec))))
        (cons 'fa (list (cons 'raw fa) (cons 'formatted (fmt-hex fa))))
        (cons 'wectw-start-column (list (cons 'raw wectw-start-column) (cons 'formatted (number->string wectw-start-column))))
        (cons 'wectw-end-column (list (cons 'raw wectw-end-column) (cons 'formatted (number->string wectw-end-column))))
        (cons 'length-twobyte (list (cons 'raw length-twobyte) (cons 'formatted (number->string length-twobyte))))
        (cons 'ctp-lsid (list (cons 'raw ctp-lsid) (cons 'formatted (fmt-hex ctp-lsid))))
        (cons 'ctp-mlpp (list (cons 'raw ctp-mlpp) (cons 'formatted (number->string ctp-mlpp))))
        (cons 'unknown-data (list (cons 'raw unknown-data) (cons 'formatted (fmt-bytes unknown-data))))
        (cons 'field-data (list (cons 'raw field-data) (cons 'formatted (utf8->string field-data))))
        )))

    (catch (e)
      (err (str "TN5250 parse error: " e)))))

;; dissect-tn5250: parse TN5250 from bytevector
;; Returns (ok fields-alist) or (err message)