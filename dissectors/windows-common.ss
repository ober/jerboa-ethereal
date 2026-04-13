;; packet-windows-common.c
;; Routines for dissecting various Windows data types
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/windows-common.ss
;; Auto-generated from wireshark/epan/dissectors/packet-windows_common.c

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
(def (dissect-windows-common buffer)
  "windows-common dissector"
  (try
    (let* (
           (ace-sra-name-offset (unwrap (read-u32be buffer 4)))
           (ace-sra-reserved (unwrap (read-u16be buffer 4)))
           (ace-sra-flags (unwrap (read-u32le buffer 4)))
           (ace-sra-value-count (unwrap (read-u32be buffer 4)))
           (ace-sra-value-offset (unwrap (read-u32be buffer 4)))
           (ace-cond-value-int8 (unwrap (read-u8 buffer 4)))
           (ace-cond-value-int16 (unwrap (read-u16be buffer 4)))
           (ace-cond-value-int32 (unwrap (read-u32be buffer 4)))
           (ace-cond-value-int64 (unwrap (read-u64be buffer 4)))
           (ace-cond-value-string (unwrap (slice buffer 4 1)))
           (ace-cond-value-octet-string (unwrap (slice buffer 4 1)))
           (ace-cond-local-attr (unwrap (slice buffer 4 1)))
           (ace-cond-user-attr (unwrap (slice buffer 4 1)))
           (ace-cond-resource-attr (unwrap (slice buffer 4 1)))
           (ace-cond-device-attr (unwrap (slice buffer 4 1)))
           (ace-flags-object (unwrap (read-u32le buffer 8)))
           (ace-guid (unwrap (slice buffer 12 16)))
           (ace-inherited-guid (unwrap (slice buffer 28 16)))
           (ace-flags (unwrap (read-u8 buffer 44)))
           (ace-flags-failed-access (extract-bits ace-flags 0x80 7))
           (ace-flags-successful-access (extract-bits ace-flags 0x40 6))
           (ace-flags-inherited-ace (extract-bits ace-flags 0x10 4))
           (ace-flags-inherit-only (extract-bits ace-flags 0x8 3))
           (ace-flags-non-propagate-inherit (extract-bits ace-flags 0x4 2))
           (ace-flags-container-inherit (extract-bits ace-flags 0x2 1))
           (ace-flags-object-inherit (extract-bits ace-flags 0x1 0))
           (ace-size (unwrap (read-u16be buffer 46)))
           (sec-desc-type (unwrap (read-u16le buffer 48)))
           (security-information (unwrap (read-u32le buffer 50)))
           (security-information-sacl (extract-bits security-information 0x8 3))
           (security-information-dacl (extract-bits security-information 0x4 2))
           (security-information-group (extract-bits security-information 0x2 1))
           (security-information-owner (extract-bits security-information 0x1 0))
           )

      (ok (list
        (cons 'ace-sra-name-offset (list (cons 'raw ace-sra-name-offset) (cons 'formatted (number->string ace-sra-name-offset))))
        (cons 'ace-sra-reserved (list (cons 'raw ace-sra-reserved) (cons 'formatted (fmt-hex ace-sra-reserved))))
        (cons 'ace-sra-flags (list (cons 'raw ace-sra-flags) (cons 'formatted (fmt-hex ace-sra-flags))))
        (cons 'ace-sra-value-count (list (cons 'raw ace-sra-value-count) (cons 'formatted (number->string ace-sra-value-count))))
        (cons 'ace-sra-value-offset (list (cons 'raw ace-sra-value-offset) (cons 'formatted (number->string ace-sra-value-offset))))
        (cons 'ace-cond-value-int8 (list (cons 'raw ace-cond-value-int8) (cons 'formatted (number->string ace-cond-value-int8))))
        (cons 'ace-cond-value-int16 (list (cons 'raw ace-cond-value-int16) (cons 'formatted (number->string ace-cond-value-int16))))
        (cons 'ace-cond-value-int32 (list (cons 'raw ace-cond-value-int32) (cons 'formatted (number->string ace-cond-value-int32))))
        (cons 'ace-cond-value-int64 (list (cons 'raw ace-cond-value-int64) (cons 'formatted (number->string ace-cond-value-int64))))
        (cons 'ace-cond-value-string (list (cons 'raw ace-cond-value-string) (cons 'formatted (utf8->string ace-cond-value-string))))
        (cons 'ace-cond-value-octet-string (list (cons 'raw ace-cond-value-octet-string) (cons 'formatted (fmt-bytes ace-cond-value-octet-string))))
        (cons 'ace-cond-local-attr (list (cons 'raw ace-cond-local-attr) (cons 'formatted (utf8->string ace-cond-local-attr))))
        (cons 'ace-cond-user-attr (list (cons 'raw ace-cond-user-attr) (cons 'formatted (utf8->string ace-cond-user-attr))))
        (cons 'ace-cond-resource-attr (list (cons 'raw ace-cond-resource-attr) (cons 'formatted (utf8->string ace-cond-resource-attr))))
        (cons 'ace-cond-device-attr (list (cons 'raw ace-cond-device-attr) (cons 'formatted (utf8->string ace-cond-device-attr))))
        (cons 'ace-flags-object (list (cons 'raw ace-flags-object) (cons 'formatted (fmt-hex ace-flags-object))))
        (cons 'ace-guid (list (cons 'raw ace-guid) (cons 'formatted (fmt-bytes ace-guid))))
        (cons 'ace-inherited-guid (list (cons 'raw ace-inherited-guid) (cons 'formatted (fmt-bytes ace-inherited-guid))))
        (cons 'ace-flags (list (cons 'raw ace-flags) (cons 'formatted (fmt-hex ace-flags))))
        (cons 'ace-flags-failed-access (list (cons 'raw ace-flags-failed-access) (cons 'formatted (if (= ace-flags-failed-access 0) "Failed accesses will not be audited" "Failed accesses will be audited"))))
        (cons 'ace-flags-successful-access (list (cons 'raw ace-flags-successful-access) (cons 'formatted (if (= ace-flags-successful-access 0) "Successful accesses will not be audited" "Successful accesses will be audited"))))
        (cons 'ace-flags-inherited-ace (list (cons 'raw ace-flags-inherited-ace) (cons 'formatted (if (= ace-flags-inherited-ace 0) "This ACE was not inherited from its parent object" "This ACE was inherited from its parent object"))))
        (cons 'ace-flags-inherit-only (list (cons 'raw ace-flags-inherit-only) (cons 'formatted (if (= ace-flags-inherit-only 0) "This ACE applies to the current object" "This ACE does not apply to the current object"))))
        (cons 'ace-flags-non-propagate-inherit (list (cons 'raw ace-flags-non-propagate-inherit) (cons 'formatted (if (= ace-flags-non-propagate-inherit 0) "Subordinate object will propagate the inherited ACE further" "Subordinate object will not propagate the inherited ACE further"))))
        (cons 'ace-flags-container-inherit (list (cons 'raw ace-flags-container-inherit) (cons 'formatted (if (= ace-flags-container-inherit 0) "Subordinate containers will not inherit this ACE" "Subordinate containers will inherit this ACE"))))
        (cons 'ace-flags-object-inherit (list (cons 'raw ace-flags-object-inherit) (cons 'formatted (if (= ace-flags-object-inherit 0) "Subordinate files will not inherit this ACE" "Subordinate files will inherit this ACE"))))
        (cons 'ace-size (list (cons 'raw ace-size) (cons 'formatted (number->string ace-size))))
        (cons 'sec-desc-type (list (cons 'raw sec-desc-type) (cons 'formatted (fmt-hex sec-desc-type))))
        (cons 'security-information (list (cons 'raw security-information) (cons 'formatted (fmt-hex security-information))))
        (cons 'security-information-sacl (list (cons 'raw security-information-sacl) (cons 'formatted (if (= security-information-sacl 0) "Do NOT request SACL" "Request SACL"))))
        (cons 'security-information-dacl (list (cons 'raw security-information-dacl) (cons 'formatted (if (= security-information-dacl 0) "Do NOT request DACL" "Request DACL"))))
        (cons 'security-information-group (list (cons 'raw security-information-group) (cons 'formatted (if (= security-information-group 0) "Do NOT request group" "Request GROUP"))))
        (cons 'security-information-owner (list (cons 'raw security-information-owner) (cons 'formatted (if (= security-information-owner 0) "Do NOT request owner" "Request OWNER"))))
        )))

    (catch (e)
      (err (str "WINDOWS-COMMON parse error: " e)))))

;; dissect-windows-common: parse WINDOWS-COMMON from bytevector
;; Returns (ok fields-alist) or (err message)