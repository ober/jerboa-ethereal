;; packet-bacapp.c
;; Routines for BACnet (APDU) dissection
;; Copyright 2001, Hartmut Mueller <hartmut[AT]abmlinux.org>, FH Dortmund
;; Enhanced by Steve Karg, 2005, <skarg[AT]users.sourceforge.net>, Atlanta
;; Enhanced by Herbert Lischka, 2005, <lischka[AT]kieback-peter.de>, Berlin
;; Enhanced by Felix Kraemer, 2010, <sauter-cumulus[AT]de.sauter-bc.com>,
;; Sauter-Cumulus GmbH, Freiburg
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald[AT]wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bacapp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bacapp.c

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
(def (dissect-bacapp buffer)
  "Building Automation and Control Network APDU"
  (try
    (let* (
           (hf-BACnetContextTagNumber (unwrap (read-u8 buffer 0)))
           (hf-BACnetExtendedTagNumber (unwrap (read-u8 buffer 0)))
           (tag-ProcessId (unwrap (read-u32be buffer 0)))
           (present-value-null (unwrap (slice buffer 0 1)))
           (present-value-bool (unwrap (read-u8 buffer 1)))
           (present-value-unsigned (unwrap (read-u64be buffer 1)))
           (present-value-signed (unwrap (read-u64be buffer 1)))
           (present-value-real (unwrap (read-u64be buffer 1)))
           (present-value-double (unwrap (read-u64be buffer 1)))
           (present-value-octet-string (unwrap (slice buffer 1 1)))
           (present-value-enum-index (unwrap (read-u32be buffer 1)))
           (tag-IPV4 (unwrap (read-u32be buffer 1)))
           (tag-PORT (unwrap (read-u16be buffer 1)))
           (tag-IPV6 (unwrap (slice buffer 1 16)))
           (present-value-char-string (unwrap (slice buffer 7 1)))
           (object-name (unwrap (slice buffer 7 1)))
           (unused-bits (unwrap (read-u8 buffer 7)))
           (complete-bitstring (unwrap (slice buffer 7 1)))
           (reserved-ashrea (unwrap (slice buffer 7 1)))
           (pduflags (unwrap (read-u8 buffer 7)))
           (SEG (unwrap (read-u8 buffer 7)))
           (MOR (unwrap (read-u8 buffer 7)))
           (NAK (unwrap (read-u8 buffer 7)))
           (hf-BACnetTagClass (unwrap (read-u8 buffer 17)))
           )

      (ok (list
        (cons 'hf-BACnetContextTagNumber (list (cons 'raw hf-BACnetContextTagNumber) (cons 'formatted (number->string hf-BACnetContextTagNumber))))
        (cons 'hf-BACnetExtendedTagNumber (list (cons 'raw hf-BACnetExtendedTagNumber) (cons 'formatted (number->string hf-BACnetExtendedTagNumber))))
        (cons 'tag-ProcessId (list (cons 'raw tag-ProcessId) (cons 'formatted (number->string tag-ProcessId))))
        (cons 'present-value-null (list (cons 'raw present-value-null) (cons 'formatted (utf8->string present-value-null))))
        (cons 'present-value-bool (list (cons 'raw present-value-bool) (cons 'formatted (number->string present-value-bool))))
        (cons 'present-value-unsigned (list (cons 'raw present-value-unsigned) (cons 'formatted (number->string present-value-unsigned))))
        (cons 'present-value-signed (list (cons 'raw present-value-signed) (cons 'formatted (number->string present-value-signed))))
        (cons 'present-value-real (list (cons 'raw present-value-real) (cons 'formatted (number->string present-value-real))))
        (cons 'present-value-double (list (cons 'raw present-value-double) (cons 'formatted (number->string present-value-double))))
        (cons 'present-value-octet-string (list (cons 'raw present-value-octet-string) (cons 'formatted (fmt-bytes present-value-octet-string))))
        (cons 'present-value-enum-index (list (cons 'raw present-value-enum-index) (cons 'formatted (number->string present-value-enum-index))))
        (cons 'tag-IPV4 (list (cons 'raw tag-IPV4) (cons 'formatted (fmt-ipv4 tag-IPV4))))
        (cons 'tag-PORT (list (cons 'raw tag-PORT) (cons 'formatted (number->string tag-PORT))))
        (cons 'tag-IPV6 (list (cons 'raw tag-IPV6) (cons 'formatted (fmt-ipv6-address tag-IPV6))))
        (cons 'present-value-char-string (list (cons 'raw present-value-char-string) (cons 'formatted (utf8->string present-value-char-string))))
        (cons 'object-name (list (cons 'raw object-name) (cons 'formatted (utf8->string object-name))))
        (cons 'unused-bits (list (cons 'raw unused-bits) (cons 'formatted (number->string unused-bits))))
        (cons 'complete-bitstring (list (cons 'raw complete-bitstring) (cons 'formatted (fmt-bytes complete-bitstring))))
        (cons 'reserved-ashrea (list (cons 'raw reserved-ashrea) (cons 'formatted (fmt-bytes reserved-ashrea))))
        (cons 'pduflags (list (cons 'raw pduflags) (cons 'formatted (fmt-hex pduflags))))
        (cons 'SEG (list (cons 'raw SEG) (cons 'formatted (if (= SEG 0) "Unsegmented Request" "Segmented Request"))))
        (cons 'MOR (list (cons 'raw MOR) (cons 'formatted (if (= MOR 0) "No More Segments Follow" "More Segments Follow"))))
        (cons 'NAK (list (cons 'raw NAK) (cons 'formatted (number->string NAK))))
        (cons 'hf-BACnetTagClass (list (cons 'raw hf-BACnetTagClass) (cons 'formatted (if (= hf-BACnetTagClass 0) "Application Tag" "Context Specific Tag"))))
        )))

    (catch (e)
      (err (str "BACAPP parse error: " e)))))

;; dissect-bacapp: parse BACAPP from bytevector
;; Returns (ok fields-alist) or (err message)