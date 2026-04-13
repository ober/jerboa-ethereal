;; packet-dcm.c
;; Routines for DICOM dissection
;; Copyright 2003, Rich Coe <richcoe2@gmail.com>
;; Copyright 2008-2019, David Aggeler <david_aggeler@hispeed.ch>
;;
;; DICOM communication protocol: https://www.dicomstandard.org/current/
;;
;; Part  5: Data Structures and Encoding
;; Part  6: Data Dictionary
;; Part  7: Message Exchange
;; Part  8: Network Communication Support for Message Exchange
;; Part 10: Media Storage and File Format
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dcm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dcm.c

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
(def (dissect-dcm buffer)
  "DICOM"
  (try
    (let* (
           (pdu-len (unwrap (read-u32be buffer 2)))
           (assoc-version (unwrap (read-u16be buffer 212)))
           (assoc-called (unwrap (slice buffer 216 16)))
           (assoc-calling (unwrap (slice buffer 232 16)))
           (assoc-reject-result (unwrap (read-u8 buffer 281)))
           (assoc-reject-source (unwrap (read-u8 buffer 281)))
           (assoc-reject-reason (unwrap (read-u8 buffer 281)))
           (assoc-abort-source (unwrap (read-u8 buffer 290)))
           (assoc-abort-reason (unwrap (read-u8 buffer 290)))
           (info-extneg-sopclassuid-len (unwrap (read-u16be buffer 292)))
           (info-extneg-sopclassuid (unwrap (slice buffer 292 1)))
           (info-user-identify-response-requested (unwrap (read-u8 buffer 297)))
           (info-user-identify-primary-field-length (unwrap (read-u16be buffer 298)))
           (info-user-identify-primary-field (unwrap (slice buffer 300 1)))
           (info-user-identify-secondary-field-length (unwrap (read-u16be buffer 300)))
           (info-user-identify-secondary-field (unwrap (slice buffer 302 1)))
           (assoc-item-data (unwrap (slice buffer 306 1)))
           (info-rolesel-sopclassuid-len (unwrap (read-u16be buffer 306)))
           (info-rolesel-sopclassuid (unwrap (slice buffer 306 1)))
           (info-async-neg-max-num-ops-inv (unwrap (read-u16be buffer 306)))
           (info-async-neg-max-num-ops-per (unwrap (read-u16be buffer 306)))
           (pctx-id (unwrap (read-u8 buffer 306)))
           (pctx-result (unwrap (read-u8 buffer 306)))
           (assoc-item-len (unwrap (read-u16be buffer 314)))
           (pdv-ctx (unwrap (read-u8 buffer 322)))
           (pdv-flags (unwrap (read-u8 buffer 323)))
           (tag-value-str (unwrap (slice buffer 324 1)))
           (tag-value-32s (unwrap (read-u32be buffer 324)))
           (tag-value-16s (unwrap (read-u16be buffer 324)))
           (tag-value-32u (unwrap (read-u32be buffer 324)))
           (tag-value-16u (unwrap (read-u16be buffer 324)))
           (tag-value-byte (unwrap (slice buffer 336 1)))
           (data-tag (unwrap (slice buffer 336 1)))
           (pdv-len (unwrap (read-u32be buffer 336)))
           )

      (ok (list
        (cons 'pdu-len (list (cons 'raw pdu-len) (cons 'formatted (number->string pdu-len))))
        (cons 'assoc-version (list (cons 'raw assoc-version) (cons 'formatted (number->string assoc-version))))
        (cons 'assoc-called (list (cons 'raw assoc-called) (cons 'formatted (utf8->string assoc-called))))
        (cons 'assoc-calling (list (cons 'raw assoc-calling) (cons 'formatted (utf8->string assoc-calling))))
        (cons 'assoc-reject-result (list (cons 'raw assoc-reject-result) (cons 'formatted (number->string assoc-reject-result))))
        (cons 'assoc-reject-source (list (cons 'raw assoc-reject-source) (cons 'formatted (number->string assoc-reject-source))))
        (cons 'assoc-reject-reason (list (cons 'raw assoc-reject-reason) (cons 'formatted (number->string assoc-reject-reason))))
        (cons 'assoc-abort-source (list (cons 'raw assoc-abort-source) (cons 'formatted (number->string assoc-abort-source))))
        (cons 'assoc-abort-reason (list (cons 'raw assoc-abort-reason) (cons 'formatted (number->string assoc-abort-reason))))
        (cons 'info-extneg-sopclassuid-len (list (cons 'raw info-extneg-sopclassuid-len) (cons 'formatted (number->string info-extneg-sopclassuid-len))))
        (cons 'info-extneg-sopclassuid (list (cons 'raw info-extneg-sopclassuid) (cons 'formatted (utf8->string info-extneg-sopclassuid))))
        (cons 'info-user-identify-response-requested (list (cons 'raw info-user-identify-response-requested) (cons 'formatted (number->string info-user-identify-response-requested))))
        (cons 'info-user-identify-primary-field-length (list (cons 'raw info-user-identify-primary-field-length) (cons 'formatted (number->string info-user-identify-primary-field-length))))
        (cons 'info-user-identify-primary-field (list (cons 'raw info-user-identify-primary-field) (cons 'formatted (utf8->string info-user-identify-primary-field))))
        (cons 'info-user-identify-secondary-field-length (list (cons 'raw info-user-identify-secondary-field-length) (cons 'formatted (number->string info-user-identify-secondary-field-length))))
        (cons 'info-user-identify-secondary-field (list (cons 'raw info-user-identify-secondary-field) (cons 'formatted (utf8->string info-user-identify-secondary-field))))
        (cons 'assoc-item-data (list (cons 'raw assoc-item-data) (cons 'formatted (fmt-bytes assoc-item-data))))
        (cons 'info-rolesel-sopclassuid-len (list (cons 'raw info-rolesel-sopclassuid-len) (cons 'formatted (number->string info-rolesel-sopclassuid-len))))
        (cons 'info-rolesel-sopclassuid (list (cons 'raw info-rolesel-sopclassuid) (cons 'formatted (utf8->string info-rolesel-sopclassuid))))
        (cons 'info-async-neg-max-num-ops-inv (list (cons 'raw info-async-neg-max-num-ops-inv) (cons 'formatted (number->string info-async-neg-max-num-ops-inv))))
        (cons 'info-async-neg-max-num-ops-per (list (cons 'raw info-async-neg-max-num-ops-per) (cons 'formatted (number->string info-async-neg-max-num-ops-per))))
        (cons 'pctx-id (list (cons 'raw pctx-id) (cons 'formatted (fmt-hex pctx-id))))
        (cons 'pctx-result (list (cons 'raw pctx-result) (cons 'formatted (fmt-hex pctx-result))))
        (cons 'assoc-item-len (list (cons 'raw assoc-item-len) (cons 'formatted (number->string assoc-item-len))))
        (cons 'pdv-ctx (list (cons 'raw pdv-ctx) (cons 'formatted (number->string pdv-ctx))))
        (cons 'pdv-flags (list (cons 'raw pdv-flags) (cons 'formatted (fmt-hex pdv-flags))))
        (cons 'tag-value-str (list (cons 'raw tag-value-str) (cons 'formatted (utf8->string tag-value-str))))
        (cons 'tag-value-32s (list (cons 'raw tag-value-32s) (cons 'formatted (number->string tag-value-32s))))
        (cons 'tag-value-16s (list (cons 'raw tag-value-16s) (cons 'formatted (number->string tag-value-16s))))
        (cons 'tag-value-32u (list (cons 'raw tag-value-32u) (cons 'formatted (number->string tag-value-32u))))
        (cons 'tag-value-16u (list (cons 'raw tag-value-16u) (cons 'formatted (number->string tag-value-16u))))
        (cons 'tag-value-byte (list (cons 'raw tag-value-byte) (cons 'formatted (fmt-bytes tag-value-byte))))
        (cons 'data-tag (list (cons 'raw data-tag) (cons 'formatted (fmt-bytes data-tag))))
        (cons 'pdv-len (list (cons 'raw pdv-len) (cons 'formatted (number->string pdv-len))))
        )))

    (catch (e)
      (err (str "DCM parse error: " e)))))

;; dissect-dcm: parse DCM from bytevector
;; Returns (ok fields-alist) or (err message)