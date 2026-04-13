;; packet-tn3270.c
;; Routines for tn3270.packet dissection
;;
;; References:
;; 3270 Information Display System: Data Stream Programmer's Reference
;; GA23-0059-07
;; http://publib.boulder.ibm.com/cgi-bin/bookmgr_OS390/BOOKS/CN7P4000
;; (dead, not archived on the Wayback Machine)
;; http://bitsavers.trailing-edge.com/pdf/ibm/3174/GA23-0059-07_3270_Data_Stream_Programmers_Reference_199206.pdf
;; (some weird format)
;; http://bitsavers.trailing-edge.com/pdf/ibm/3270/GA23-0059-07_3270_Data_Stream_Programmers_Reference_199206.pdf
;; (straightforward scanned PDF, with OCR so searching might work)
;; (Paragraph references in the comments in this file (e.g., 6.15) are to the above document)
;;
;; 3174 Establishment Controller Functional Description
;; GA23-0218-11
;; http://publib.boulder.ibm.com/cgi-bin/bookmgr/BOOKS/cn7a7003
;;
;; RFC 1041: Telnet 3270 Regime Option
;; https://tools.ietf.org/html/rfc1041
;;
;; RFC 1576: TN3270 Current Practices
;; https://tools.ietf.org/html/rfc1576
;;
;; RFC 2355: TN3270 Enhancements
;; https://tools.ietf.org/html/rfc2355
;;
;;
;; Copyright 2009, Robert Hogan <robert@roberthogan.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tn3270.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tn3270.c
;; RFC 1041

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
(def (dissect-tn3270 buffer)
  "TN3270 Protocol"
  (try
    (let* (
           (field-attribute (unwrap (read-u8 buffer 1)))
           (ccc (unwrap (read-u8 buffer 2)))
           (c-prtblk (extract-bits ccc 0x40 6))
           (load-format-storage-format-data (unwrap (slice buffer 3 1)))
           (extended-ps-length (unwrap (read-u8 buffer 3)))
           (extended-ps-flags (unwrap (read-u8 buffer 4)))
           (outbound-text-header-lhdr (unwrap (read-u16be buffer 5)))
           (outbound-text-header-hdr (unwrap (slice buffer 7 1)))
           (bsc (unwrap (read-u16be buffer 9)))
           (fov (unwrap (read-u16be buffer 14)))
           (format-name (unwrap (slice buffer 17 1)))
           (start-page (unwrap (read-u16be buffer 23)))
           (start-line (unwrap (read-u16be buffer 25)))
           (scs-data (unwrap (slice buffer 27 1)))
           (type-1-text-outbound-data (unwrap (slice buffer 28 1)))
           (dia-nfs (unwrap (read-u8 buffer 35)))
           (dia-diafn (unwrap (read-u16be buffer 36)))
           (field-data (unwrap (slice buffer 37 1)))
           (fsad-size (unwrap (read-u16be buffer 37)))
           (pc-vo-thickness (unwrap (read-u8 buffer 43)))
           (rpq-rpql (unwrap (read-u8 buffer 45)))
           (spc-epc-flags (unwrap (read-u8 buffer 46)))
           (tp-ntt (unwrap (read-u8 buffer 49)))
           (tp-tlist (unwrap (read-u8 buffer 50)))
           (t-np (unwrap (read-u8 buffer 51)))
           (t-vi (unwrap (read-u8 buffer 52)))
           (t-ai (unwrap (read-u8 buffer 53)))
           (partition-rw (unwrap (read-u16be buffer 59)))
           (partition-cw (unwrap (read-u16be buffer 61)))
           (partition-id (unwrap (read-u8 buffer 63)))
           (begin-end-flags2 (unwrap (read-u8 buffer 65)))
           (load-color-command (unwrap (slice buffer 66 1)))
           (load-line-type-command (unwrap (slice buffer 66 1)))
           (color-command (unwrap (read-u16be buffer 67)))
           (interval (unwrap (read-u16be buffer 70)))
           (resbyte (unwrap (read-u8 buffer 73)))
           (destination-or-origin-doid (unwrap (read-u16be buffer 74)))
           (resbytes (unwrap (read-u16be buffer 76)))
           (sf-length (unwrap (read-u16be buffer 78)))
           (null (unwrap (read-u8 buffer 78)))
           (stop-address (unwrap (read-u16be buffer 79)))
           (all-character-attributes (unwrap (read-u8 buffer 84)))
           (number-of-attributes (unwrap (read-u8 buffer 90)))
           (character-code (unwrap (read-u8 buffer 92)))
           (tn3270e-response-flag-unused (unwrap (read-u8 buffer 93)))
           (tn3270e-seq-number (unwrap (read-u16be buffer 94)))
           (tn3270e-header-data (unwrap (slice buffer 96 1)))
           (unknown-data (unwrap (slice buffer 97 1)))
           )

      (ok (list
        (cons 'field-attribute (list (cons 'raw field-attribute) (cons 'formatted (fmt-hex field-attribute))))
        (cons 'ccc (list (cons 'raw ccc) (cons 'formatted (fmt-hex ccc))))
        (cons 'c-prtblk (list (cons 'raw c-prtblk) (cons 'formatted (if (= c-prtblk 0) "Not set" "Set"))))
        (cons 'load-format-storage-format-data (list (cons 'raw load-format-storage-format-data) (cons 'formatted (utf8->string load-format-storage-format-data))))
        (cons 'extended-ps-length (list (cons 'raw extended-ps-length) (cons 'formatted (fmt-hex extended-ps-length))))
        (cons 'extended-ps-flags (list (cons 'raw extended-ps-flags) (cons 'formatted (fmt-hex extended-ps-flags))))
        (cons 'outbound-text-header-lhdr (list (cons 'raw outbound-text-header-lhdr) (cons 'formatted (number->string outbound-text-header-lhdr))))
        (cons 'outbound-text-header-hdr (list (cons 'raw outbound-text-header-hdr) (cons 'formatted (fmt-bytes outbound-text-header-hdr))))
        (cons 'bsc (list (cons 'raw bsc) (cons 'formatted (fmt-hex bsc))))
        (cons 'fov (list (cons 'raw fov) (cons 'formatted (number->string fov))))
        (cons 'format-name (list (cons 'raw format-name) (cons 'formatted (utf8->string format-name))))
        (cons 'start-page (list (cons 'raw start-page) (cons 'formatted (number->string start-page))))
        (cons 'start-line (list (cons 'raw start-line) (cons 'formatted (number->string start-line))))
        (cons 'scs-data (list (cons 'raw scs-data) (cons 'formatted (fmt-bytes scs-data))))
        (cons 'type-1-text-outbound-data (list (cons 'raw type-1-text-outbound-data) (cons 'formatted (fmt-bytes type-1-text-outbound-data))))
        (cons 'dia-nfs (list (cons 'raw dia-nfs) (cons 'formatted (fmt-hex dia-nfs))))
        (cons 'dia-diafn (list (cons 'raw dia-diafn) (cons 'formatted (number->string dia-diafn))))
        (cons 'field-data (list (cons 'raw field-data) (cons 'formatted (utf8->string field-data))))
        (cons 'fsad-size (list (cons 'raw fsad-size) (cons 'formatted (number->string fsad-size))))
        (cons 'pc-vo-thickness (list (cons 'raw pc-vo-thickness) (cons 'formatted (number->string pc-vo-thickness))))
        (cons 'rpq-rpql (list (cons 'raw rpq-rpql) (cons 'formatted (number->string rpq-rpql))))
        (cons 'spc-epc-flags (list (cons 'raw spc-epc-flags) (cons 'formatted (fmt-hex spc-epc-flags))))
        (cons 'tp-ntt (list (cons 'raw tp-ntt) (cons 'formatted (number->string tp-ntt))))
        (cons 'tp-tlist (list (cons 'raw tp-tlist) (cons 'formatted (fmt-hex tp-tlist))))
        (cons 't-np (list (cons 'raw t-np) (cons 'formatted (number->string t-np))))
        (cons 't-vi (list (cons 'raw t-vi) (cons 'formatted (fmt-hex t-vi))))
        (cons 't-ai (list (cons 'raw t-ai) (cons 'formatted (fmt-hex t-ai))))
        (cons 'partition-rw (list (cons 'raw partition-rw) (cons 'formatted (number->string partition-rw))))
        (cons 'partition-cw (list (cons 'raw partition-cw) (cons 'formatted (number->string partition-cw))))
        (cons 'partition-id (list (cons 'raw partition-id) (cons 'formatted (fmt-hex partition-id))))
        (cons 'begin-end-flags2 (list (cons 'raw begin-end-flags2) (cons 'formatted (fmt-hex begin-end-flags2))))
        (cons 'load-color-command (list (cons 'raw load-color-command) (cons 'formatted (fmt-bytes load-color-command))))
        (cons 'load-line-type-command (list (cons 'raw load-line-type-command) (cons 'formatted (fmt-bytes load-line-type-command))))
        (cons 'color-command (list (cons 'raw color-command) (cons 'formatted (fmt-hex color-command))))
        (cons 'interval (list (cons 'raw interval) (cons 'formatted (fmt-hex interval))))
        (cons 'resbyte (list (cons 'raw resbyte) (cons 'formatted (fmt-hex resbyte))))
        (cons 'destination-or-origin-doid (list (cons 'raw destination-or-origin-doid) (cons 'formatted (fmt-hex destination-or-origin-doid))))
        (cons 'resbytes (list (cons 'raw resbytes) (cons 'formatted (fmt-hex resbytes))))
        (cons 'sf-length (list (cons 'raw sf-length) (cons 'formatted (number->string sf-length))))
        (cons 'null (list (cons 'raw null) (cons 'formatted (fmt-hex null))))
        (cons 'stop-address (list (cons 'raw stop-address) (cons 'formatted (number->string stop-address))))
        (cons 'all-character-attributes (list (cons 'raw all-character-attributes) (cons 'formatted (fmt-hex all-character-attributes))))
        (cons 'number-of-attributes (list (cons 'raw number-of-attributes) (cons 'formatted (fmt-hex number-of-attributes))))
        (cons 'character-code (list (cons 'raw character-code) (cons 'formatted (fmt-hex character-code))))
        (cons 'tn3270e-response-flag-unused (list (cons 'raw tn3270e-response-flag-unused) (cons 'formatted (fmt-hex tn3270e-response-flag-unused))))
        (cons 'tn3270e-seq-number (list (cons 'raw tn3270e-seq-number) (cons 'formatted (number->string tn3270e-seq-number))))
        (cons 'tn3270e-header-data (list (cons 'raw tn3270e-header-data) (cons 'formatted (utf8->string tn3270e-header-data))))
        (cons 'unknown-data (list (cons 'raw unknown-data) (cons 'formatted (fmt-bytes unknown-data))))
        )))

    (catch (e)
      (err (str "TN3270 parse error: " e)))))

;; dissect-tn3270: parse TN3270 from bytevector
;; Returns (ok fields-alist) or (err message)