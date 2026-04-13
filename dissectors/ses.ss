;; packet-ses.c
;;
;; Routine to dissect ITU-T Rec. X.225 (1995 E)/ISO 8327-1 OSI Session Protocol packets
;;
;; Yuriy Sidelnikov <YSidelnikov@hotmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ses.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ses.c

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
(def (dissect-ses buffer)
  "ses dissector"
  (try
    (let* (
           (user-data (unwrap (slice buffer 0 1)))
           (ss-user-reference (unwrap (slice buffer 0 1)))
           (reference (unwrap (slice buffer 0 1)))
           (reference-information (unwrap (slice buffer 0 1)))
           (activity-token (extract-bits item-options-flags 0x0 0))
           (minor-token (extract-bits item-options-flags 0x0 0))
           (token (extract-bits item-options-flags 0x0 0))
           (transport-option-flags (unwrap (read-u8 buffer 0)))
           (transport-connection (extract-bits transport-option-flags 0x0 0))
           (transport-user-abort (extract-bits transport-option-flags 0x0 0))
           (transport-protocol-error (extract-bits transport-option-flags 0x0 0))
           (transport-no-reason (extract-bits transport-option-flags 0x0 0))
           (transport-implementation-restriction (extract-bits transport-option-flags 0x0 0))
           (protocol-options-flags (unwrap (read-u8 buffer 0)))
           (to-receive-extended-concatenated-SPDU (extract-bits protocol-options-flags 0x0 0))
           (user-req-flags (unwrap (read-u16be buffer 0)))
           (exception-report (extract-bits user-req-flags 0x0 0))
           (separation-function-unit (extract-bits user-req-flags 0x0 0))
           (synchronize-function-unit (extract-bits user-req-flags 0x0 0))
           (data-function-unit (extract-bits user-req-flags 0x0 0))
           (release-function-unit (extract-bits user-req-flags 0x0 0))
           (management-function-unit (extract-bits user-req-flags 0x0 0))
           (resynchronize-function-unit (extract-bits user-req-flags 0x0 0))
           (data-resynchronize-function-unit (extract-bits user-req-flags 0x0 0))
           (function-unit (extract-bits user-req-flags 0x0 0))
           (duplex-function-unit (extract-bits user-req-flags 0x0 0))
           (tsdu-maximum-size-i2r (unwrap (read-u16be buffer 0)))
           (tsdu-maximum-size-r2i (unwrap (read-u16be buffer 0)))
           (number-options-flags (unwrap (read-u8 buffer 0)))
           (version-2 (extract-bits number-options-flags 0x0 0))
           (version-1 (extract-bits number-options-flags 0x0 0))
           (item-options-flags (unwrap (read-u8 buffer 0)))
           (of-SSDU (extract-bits item-options-flags 0x0 0))
           (identifier (unwrap (slice buffer 0 1)))
           (number (unwrap (slice buffer 0 1)))
           (session-selector (unwrap (slice buffer 0 1)))
           (serial-number (unwrap (slice buffer 0 1)))
           (initial-serial-number (unwrap (slice buffer 0 1)))
           (second-initial-serial-number (unwrap (slice buffer 0 1)))
           (parameter-length (unwrap (read-u32be buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           )

      (ok (list
        (cons 'user-data (list (cons 'raw user-data) (cons 'formatted (fmt-bytes user-data))))
        (cons 'ss-user-reference (list (cons 'raw ss-user-reference) (cons 'formatted (fmt-bytes ss-user-reference))))
        (cons 'reference (list (cons 'raw reference) (cons 'formatted (fmt-bytes reference))))
        (cons 'reference-information (list (cons 'raw reference-information) (cons 'formatted (fmt-bytes reference-information))))
        (cons 'activity-token (list (cons 'raw activity-token) (cons 'formatted (if (= activity-token 0) "Not set" "Set"))))
        (cons 'minor-token (list (cons 'raw minor-token) (cons 'formatted (if (= minor-token 0) "Not set" "Set"))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (if (= token 0) "Not set" "Set"))))
        (cons 'transport-option-flags (list (cons 'raw transport-option-flags) (cons 'formatted (fmt-hex transport-option-flags))))
        (cons 'transport-connection (list (cons 'raw transport-connection) (cons 'formatted (if (= transport-connection 0) "Kept" "Released"))))
        (cons 'transport-user-abort (list (cons 'raw transport-user-abort) (cons 'formatted (if (= transport-user-abort 0) "Not set" "Set"))))
        (cons 'transport-protocol-error (list (cons 'raw transport-protocol-error) (cons 'formatted (if (= transport-protocol-error 0) "Not set" "Set"))))
        (cons 'transport-no-reason (list (cons 'raw transport-no-reason) (cons 'formatted (if (= transport-no-reason 0) "Not set" "Set"))))
        (cons 'transport-implementation-restriction (list (cons 'raw transport-implementation-restriction) (cons 'formatted (if (= transport-implementation-restriction 0) "Not set" "Set"))))
        (cons 'protocol-options-flags (list (cons 'raw protocol-options-flags) (cons 'formatted (fmt-hex protocol-options-flags))))
        (cons 'to-receive-extended-concatenated-SPDU (list (cons 'raw to-receive-extended-concatenated-SPDU) (cons 'formatted (if (= to-receive-extended-concatenated-SPDU 0) "Not set" "Set"))))
        (cons 'user-req-flags (list (cons 'raw user-req-flags) (cons 'formatted (fmt-hex user-req-flags))))
        (cons 'exception-report (list (cons 'raw exception-report) (cons 'formatted (if (= exception-report 0) "Not set" "Set"))))
        (cons 'separation-function-unit (list (cons 'raw separation-function-unit) (cons 'formatted (if (= separation-function-unit 0) "Not set" "Set"))))
        (cons 'synchronize-function-unit (list (cons 'raw synchronize-function-unit) (cons 'formatted (if (= synchronize-function-unit 0) "Not set" "Set"))))
        (cons 'data-function-unit (list (cons 'raw data-function-unit) (cons 'formatted (if (= data-function-unit 0) "Not set" "Set"))))
        (cons 'release-function-unit (list (cons 'raw release-function-unit) (cons 'formatted (if (= release-function-unit 0) "Not set" "Set"))))
        (cons 'management-function-unit (list (cons 'raw management-function-unit) (cons 'formatted (if (= management-function-unit 0) "Not set" "Set"))))
        (cons 'resynchronize-function-unit (list (cons 'raw resynchronize-function-unit) (cons 'formatted (if (= resynchronize-function-unit 0) "Not set" "Set"))))
        (cons 'data-resynchronize-function-unit (list (cons 'raw data-resynchronize-function-unit) (cons 'formatted (if (= data-resynchronize-function-unit 0) "Not set" "Set"))))
        (cons 'function-unit (list (cons 'raw function-unit) (cons 'formatted (if (= function-unit 0) "Not set" "Set"))))
        (cons 'duplex-function-unit (list (cons 'raw duplex-function-unit) (cons 'formatted (if (= duplex-function-unit 0) "Not set" "Set"))))
        (cons 'tsdu-maximum-size-i2r (list (cons 'raw tsdu-maximum-size-i2r) (cons 'formatted (number->string tsdu-maximum-size-i2r))))
        (cons 'tsdu-maximum-size-r2i (list (cons 'raw tsdu-maximum-size-r2i) (cons 'formatted (number->string tsdu-maximum-size-r2i))))
        (cons 'number-options-flags (list (cons 'raw number-options-flags) (cons 'formatted (fmt-hex number-options-flags))))
        (cons 'version-2 (list (cons 'raw version-2) (cons 'formatted (if (= version-2 0) "Not set" "Set"))))
        (cons 'version-1 (list (cons 'raw version-1) (cons 'formatted (if (= version-1 0) "Not set" "Set"))))
        (cons 'item-options-flags (list (cons 'raw item-options-flags) (cons 'formatted (fmt-hex item-options-flags))))
        (cons 'of-SSDU (list (cons 'raw of-SSDU) (cons 'formatted (if (= of-SSDU 0) "Not set" "Set"))))
        (cons 'identifier (list (cons 'raw identifier) (cons 'formatted (fmt-bytes identifier))))
        (cons 'number (list (cons 'raw number) (cons 'formatted (utf8->string number))))
        (cons 'session-selector (list (cons 'raw session-selector) (cons 'formatted (fmt-bytes session-selector))))
        (cons 'serial-number (list (cons 'raw serial-number) (cons 'formatted (utf8->string serial-number))))
        (cons 'initial-serial-number (list (cons 'raw initial-serial-number) (cons 'formatted (utf8->string initial-serial-number))))
        (cons 'second-initial-serial-number (list (cons 'raw second-initial-serial-number) (cons 'formatted (utf8->string second-initial-serial-number))))
        (cons 'parameter-length (list (cons 'raw parameter-length) (cons 'formatted (number->string parameter-length))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        )))

    (catch (e)
      (err (str "SES parse error: " e)))))

;; dissect-ses: parse SES from bytevector
;; Returns (ok fields-alist) or (err message)