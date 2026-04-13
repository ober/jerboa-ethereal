;; packet-gsm_sms_ud.c
;; Routines for GSM SMS TP-UD (GSM 03.40) dissection
;;
;; Refer to the AUTHORS file or the AUTHORS section in the man page
;; for contacting the author(s) of this file.
;;
;; Separated from the SMPP dissector by Chris Wilson.
;;
;; UDH and WSP dissection of SMS message, Short Message reassembly,
;; "Decode Short Message with Port Number UDH as CL-WSP" preference,
;; "Always try subdissection of 1st fragment" preference,
;; provided by Olivier Biot.
;;
;; Note on SMS Message reassembly
;; ------------------------------
;; The current Short Message reassembly is possible thanks to the
;; message identifier (8 or 16 bit identifier). It is able to reassemble
;; short messages that are sent over either the same SMPP connection or
;; distinct SMPP connections. Normally the reassembly code is able to deal
;; with duplicate message identifiers since the fragment_add_seq_check()
;; call is used.
;;
;; The SMS TP-UD preference "always try subdissection of 1st fragment" allows
;; a subdissector to be called for the first Short Message fragment,
;; even if reassembly is not possible. This way partial dissection
;; is still possible. This preference is switched off by default.
;;
;; Note on Short Message decoding as CL-WSP
;; ----------------------------------------
;; The SMS TP-UD preference "port_number_udh_means_wsp" is switched off
;; by default. If it is enabled, then any Short Message with a Port Number
;; UDH will be decoded as CL-WSP if:
;; -  The Short Message is not segmented
;; -  The entire segmented Short Message is reassembled
;; -  It is the 1st segment of an unreassembled Short Message (if the
;; "always try subdissection of 1st fragment" preference is enabled)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-sms-ud.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_sms_ud.c

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
(def (dissect-gsm-sms-ud buffer)
  "GSM Short Message Service User Data"
  (try
    ;; TODO: no extractable fields found for gsm-sms-ud
    (ok '())

    (catch (e)
      (err (str "GSM-SMS-UD parse error: " e)))))

;; dissect-gsm-sms-ud: parse GSM-SMS-UD from bytevector
;; Returns (ok fields-alist) or (err message)