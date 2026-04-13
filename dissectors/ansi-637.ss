;; packet-ansi_637.c
;; Routines for ANSI IS-637-A/D (SMS) dissection
;;
;; Copyright 2003, Michael Lum <mlum [AT] telostech.com>
;; In association with Telos Technology Inc.
;; Copyright 2013, Michael Lum <michael.lum [AT] starsolutions.com>
;; In association with Star Solutions, Inc. (Updated for some of IS-637-D and CMAS)
;;
;; Title                3GPP2                   Other
;;
;; Short Message Service
;; 3GPP2 C.S0015-0         TIA/EIA-637-A
;; 3GPP2 C.S0015-C v1.0    TIA/EIA-637-D
;; 3GPP2 C.R1001-H v1.0    TSB-58-I (or J?)
;;
;; For CMAS See:
;; TIA-1149.1 or
;; (520-10030206__Editor_TIA-1149-0-1_CMASoverCDMA_Publication.pdf)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ansi-637.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ansi_637.c

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
(def (dissect-ansi-637 buffer)
  "ANSI IS-637-A (SMS) Teleservice Layer"
  (try
    (let* (
           (637-tele-response-code (unwrap (read-u8 buffer 2)))
           (637-tele-reply-option-user-ack-req (unwrap (read-u8 buffer 2)))
           (637-tele-reply-option-dak-req (unwrap (read-u8 buffer 2)))
           (637-tele-reply-option-read-ack-req (unwrap (read-u8 buffer 2)))
           (637-tele-reply-option-report-req (unwrap (read-u8 buffer 2)))
           (637-tele-num-messages (unwrap (read-u8 buffer 2)))
           (637-tele-language (unwrap (read-u8 buffer 2)))
           (637-tele-cb-num-digit-mode (unwrap (read-u8 buffer 2)))
           (637-tele-cb-num-num-fields (unwrap (read-u8 buffer 3)))
           (637-tele-cb-num-number (unwrap (slice buffer 4 1)))
           (637-tele-msg-id (unwrap (read-u24be buffer 5)))
           (637-tele-msg-rsvd (unwrap (read-u24be buffer 5)))
           (637-tele-cmas-encoding (unwrap (read-u16be buffer 5)))
           (637-tele-cmas-num-fields (unwrap (read-u16be buffer 5)))
           (637-tele-cb-num-num-fields07f8 (unwrap (read-u16be buffer 5)))
           (637-reserved-bits-8-3f (unwrap (read-u8 buffer 7)))
           (637-tele-mult-enc-user-data-num-fields (unwrap (read-u8 buffer 12)))
           (637-tele-user-data-encoding (unwrap (read-u16be buffer 18)))
           (637-tele-user-data-message-type (unwrap (read-u16be buffer 18)))
           (637-tele-user-data-num-fields (unwrap (read-u16be buffer 19)))
           (637-tele-msg-deposit-idx (unwrap (read-u16be buffer 20)))
           (637-tele-srvc-cat-prog-data-max-messages (unwrap (read-u8 buffer 53)))
           (637-tele-srvc-cat-prog-data-num-fields (unwrap (read-u8 buffer 65)))
           (637-tele-msg-status-code (unwrap (read-u8 buffer 76)))
           (637-tele-tp-failure-cause-value (unwrap (read-u8 buffer 76)))
           (637-trans-tele-id (unwrap (read-u16be buffer 76)))
           (637-trans-srvc-cat (unwrap (read-u16be buffer 76)))
           (637-trans-addr-param-digit-mode (unwrap (read-u8 buffer 76)))
           (637-trans-addr-param-number-mode (unwrap (read-u8 buffer 76)))
           (637-reserved-bits-8-07 (unwrap (read-u8 buffer 77)))
           (637-trans-addr-param-ton (unwrap (read-u8 buffer 77)))
           (637-reserved-bits-8-7f (unwrap (read-u8 buffer 79)))
           (637-trans-subaddr-type (unwrap (read-u16be buffer 82)))
           (637-trans-subaddr-num-fields (unwrap (read-u16be buffer 82)))
           (637-reserved-bits-8-0f (unwrap (read-u8 buffer 83)))
           (637-trans-bearer-reply-seq-num (unwrap (read-u8 buffer 83)))
           (637-reserved-bits-8-03 (unwrap (read-u8 buffer 83)))
           (637-trans-cause-codes-seq-num (unwrap (read-u8 buffer 83)))
           (637-trans-cause-codes-code (unwrap (read-u8 buffer 84)))
           )

      (ok (list
        (cons '637-tele-response-code (list (cons 'raw 637-tele-response-code) (cons 'formatted (number->string 637-tele-response-code))))
        (cons '637-tele-reply-option-user-ack-req (list (cons 'raw 637-tele-reply-option-user-ack-req) (cons 'formatted (if (= 637-tele-reply-option-user-ack-req 0) "False" "True"))))
        (cons '637-tele-reply-option-dak-req (list (cons 'raw 637-tele-reply-option-dak-req) (cons 'formatted (if (= 637-tele-reply-option-dak-req 0) "False" "True"))))
        (cons '637-tele-reply-option-read-ack-req (list (cons 'raw 637-tele-reply-option-read-ack-req) (cons 'formatted (if (= 637-tele-reply-option-read-ack-req 0) "False" "True"))))
        (cons '637-tele-reply-option-report-req (list (cons 'raw 637-tele-reply-option-report-req) (cons 'formatted (if (= 637-tele-reply-option-report-req 0) "False" "True"))))
        (cons '637-tele-num-messages (list (cons 'raw 637-tele-num-messages) (cons 'formatted (number->string 637-tele-num-messages))))
        (cons '637-tele-language (list (cons 'raw 637-tele-language) (cons 'formatted (number->string 637-tele-language))))
        (cons '637-tele-cb-num-digit-mode (list (cons 'raw 637-tele-cb-num-digit-mode) (cons 'formatted (if (= 637-tele-cb-num-digit-mode 0) "4-bit DTMF" "8-bit ASCII"))))
        (cons '637-tele-cb-num-num-fields (list (cons 'raw 637-tele-cb-num-num-fields) (cons 'formatted (number->string 637-tele-cb-num-num-fields))))
        (cons '637-tele-cb-num-number (list (cons 'raw 637-tele-cb-num-number) (cons 'formatted (utf8->string 637-tele-cb-num-number))))
        (cons '637-tele-msg-id (list (cons 'raw 637-tele-msg-id) (cons 'formatted (number->string 637-tele-msg-id))))
        (cons '637-tele-msg-rsvd (list (cons 'raw 637-tele-msg-rsvd) (cons 'formatted (number->string 637-tele-msg-rsvd))))
        (cons '637-tele-cmas-encoding (list (cons 'raw 637-tele-cmas-encoding) (cons 'formatted (number->string 637-tele-cmas-encoding))))
        (cons '637-tele-cmas-num-fields (list (cons 'raw 637-tele-cmas-num-fields) (cons 'formatted (number->string 637-tele-cmas-num-fields))))
        (cons '637-tele-cb-num-num-fields07f8 (list (cons 'raw 637-tele-cb-num-num-fields07f8) (cons 'formatted (number->string 637-tele-cb-num-num-fields07f8))))
        (cons '637-reserved-bits-8-3f (list (cons 'raw 637-reserved-bits-8-3f) (cons 'formatted (number->string 637-reserved-bits-8-3f))))
        (cons '637-tele-mult-enc-user-data-num-fields (list (cons 'raw 637-tele-mult-enc-user-data-num-fields) (cons 'formatted (number->string 637-tele-mult-enc-user-data-num-fields))))
        (cons '637-tele-user-data-encoding (list (cons 'raw 637-tele-user-data-encoding) (cons 'formatted (number->string 637-tele-user-data-encoding))))
        (cons '637-tele-user-data-message-type (list (cons 'raw 637-tele-user-data-message-type) (cons 'formatted (number->string 637-tele-user-data-message-type))))
        (cons '637-tele-user-data-num-fields (list (cons 'raw 637-tele-user-data-num-fields) (cons 'formatted (number->string 637-tele-user-data-num-fields))))
        (cons '637-tele-msg-deposit-idx (list (cons 'raw 637-tele-msg-deposit-idx) (cons 'formatted (number->string 637-tele-msg-deposit-idx))))
        (cons '637-tele-srvc-cat-prog-data-max-messages (list (cons 'raw 637-tele-srvc-cat-prog-data-max-messages) (cons 'formatted (number->string 637-tele-srvc-cat-prog-data-max-messages))))
        (cons '637-tele-srvc-cat-prog-data-num-fields (list (cons 'raw 637-tele-srvc-cat-prog-data-num-fields) (cons 'formatted (number->string 637-tele-srvc-cat-prog-data-num-fields))))
        (cons '637-tele-msg-status-code (list (cons 'raw 637-tele-msg-status-code) (cons 'formatted (number->string 637-tele-msg-status-code))))
        (cons '637-tele-tp-failure-cause-value (list (cons 'raw 637-tele-tp-failure-cause-value) (cons 'formatted (number->string 637-tele-tp-failure-cause-value))))
        (cons '637-trans-tele-id (list (cons 'raw 637-trans-tele-id) (cons 'formatted (number->string 637-trans-tele-id))))
        (cons '637-trans-srvc-cat (list (cons 'raw 637-trans-srvc-cat) (cons 'formatted (number->string 637-trans-srvc-cat))))
        (cons '637-trans-addr-param-digit-mode (list (cons 'raw 637-trans-addr-param-digit-mode) (cons 'formatted (if (= 637-trans-addr-param-digit-mode 0) "4-bit DTMF" "8-bit ASCII"))))
        (cons '637-trans-addr-param-number-mode (list (cons 'raw 637-trans-addr-param-number-mode) (cons 'formatted (if (= 637-trans-addr-param-number-mode 0) "ANSI T1.607" "Data Network Address"))))
        (cons '637-reserved-bits-8-07 (list (cons 'raw 637-reserved-bits-8-07) (cons 'formatted (number->string 637-reserved-bits-8-07))))
        (cons '637-trans-addr-param-ton (list (cons 'raw 637-trans-addr-param-ton) (cons 'formatted (number->string 637-trans-addr-param-ton))))
        (cons '637-reserved-bits-8-7f (list (cons 'raw 637-reserved-bits-8-7f) (cons 'formatted (number->string 637-reserved-bits-8-7f))))
        (cons '637-trans-subaddr-type (list (cons 'raw 637-trans-subaddr-type) (cons 'formatted (number->string 637-trans-subaddr-type))))
        (cons '637-trans-subaddr-num-fields (list (cons 'raw 637-trans-subaddr-num-fields) (cons 'formatted (number->string 637-trans-subaddr-num-fields))))
        (cons '637-reserved-bits-8-0f (list (cons 'raw 637-reserved-bits-8-0f) (cons 'formatted (number->string 637-reserved-bits-8-0f))))
        (cons '637-trans-bearer-reply-seq-num (list (cons 'raw 637-trans-bearer-reply-seq-num) (cons 'formatted (number->string 637-trans-bearer-reply-seq-num))))
        (cons '637-reserved-bits-8-03 (list (cons 'raw 637-reserved-bits-8-03) (cons 'formatted (number->string 637-reserved-bits-8-03))))
        (cons '637-trans-cause-codes-seq-num (list (cons 'raw 637-trans-cause-codes-seq-num) (cons 'formatted (number->string 637-trans-cause-codes-seq-num))))
        (cons '637-trans-cause-codes-code (list (cons 'raw 637-trans-cause-codes-code) (cons 'formatted (number->string 637-trans-cause-codes-code))))
        )))

    (catch (e)
      (err (str "ANSI-637 parse error: " e)))))

;; dissect-ansi-637: parse ANSI-637 from bytevector
;; Returns (ok fields-alist) or (err message)