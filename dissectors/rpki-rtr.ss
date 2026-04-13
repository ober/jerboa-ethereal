;; packet-rpki-rtr.c
;; Routines for RPKI-Router Protocol dissection (RFC6810)
;; Copyright 2013, Alexis La Goutte <alexis.lagoutte at gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; The information used comes from:
;; RFC6810: The Resource Public Key Infrastructure (RPKI) to Router Protocol
;;

;; jerboa-ethereal/dissectors/rpki-rtr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rpki_rtr.c
;; RFC 6810

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
(def (dissect-rpki-rtr buffer)
  "RPKI-Router Protocol"
  (try
    (let* (
           (ipv4-prefix (unwrap (read-u32be buffer 34)))
           (prefix-length (unwrap (read-u8 buffer 49)))
           (max-length (unwrap (read-u8 buffer 50)))
           (ipv6-prefix (unwrap (slice buffer 52 16)))
           (session-id (unwrap (read-u16be buffer 72)))
           (serial-number (unwrap (read-u32be buffer 78)))
           (refresh-interval (unwrap (read-u32be buffer 82)))
           (retry-interval (unwrap (read-u32be buffer 86)))
           (expire-interval (unwrap (read-u32be buffer 90)))
           (flags-rk (unwrap (read-u8 buffer 94)))
           (subject-key-identifier (unwrap (slice buffer 100 20)))
           (as-number (unwrap (read-u32be buffer 120)))
           (length-pdu (unwrap (read-u32be buffer 130)))
           (error-pdu (unwrap (slice buffer 134 1)))
           (length-text (unwrap (read-u32be buffer 134)))
           (error-text (unwrap (slice buffer 138 1)))
           (flags (unwrap (read-u8 buffer 138)))
           (flags-aw (unwrap (read-u8 buffer 138)))
           (reserved (unwrap (slice buffer 139 1)))
           (aspa-customer-asn (unwrap (read-u32be buffer 144)))
           (aspa-provider-asn (unwrap (read-u32be buffer 148)))
           (length (unwrap (read-u32be buffer 154)))
           (version (unwrap (read-u8 buffer 158)))
           )

      (ok (list
        (cons 'ipv4-prefix (list (cons 'raw ipv4-prefix) (cons 'formatted (fmt-ipv4 ipv4-prefix))))
        (cons 'prefix-length (list (cons 'raw prefix-length) (cons 'formatted (number->string prefix-length))))
        (cons 'max-length (list (cons 'raw max-length) (cons 'formatted (number->string max-length))))
        (cons 'ipv6-prefix (list (cons 'raw ipv6-prefix) (cons 'formatted (fmt-ipv6-address ipv6-prefix))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (number->string session-id))))
        (cons 'serial-number (list (cons 'raw serial-number) (cons 'formatted (number->string serial-number))))
        (cons 'refresh-interval (list (cons 'raw refresh-interval) (cons 'formatted (number->string refresh-interval))))
        (cons 'retry-interval (list (cons 'raw retry-interval) (cons 'formatted (number->string retry-interval))))
        (cons 'expire-interval (list (cons 'raw expire-interval) (cons 'formatted (number->string expire-interval))))
        (cons 'flags-rk (list (cons 'raw flags-rk) (cons 'formatted (if (= flags-rk 0) "Delete Router Key" "New Router Key"))))
        (cons 'subject-key-identifier (list (cons 'raw subject-key-identifier) (cons 'formatted (fmt-bytes subject-key-identifier))))
        (cons 'as-number (list (cons 'raw as-number) (cons 'formatted (number->string as-number))))
        (cons 'length-pdu (list (cons 'raw length-pdu) (cons 'formatted (number->string length-pdu))))
        (cons 'error-pdu (list (cons 'raw error-pdu) (cons 'formatted (fmt-bytes error-pdu))))
        (cons 'length-text (list (cons 'raw length-text) (cons 'formatted (number->string length-text))))
        (cons 'error-text (list (cons 'raw error-text) (cons 'formatted (utf8->string error-text))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-aw (list (cons 'raw flags-aw) (cons 'formatted (if (= flags-aw 0) "Withdrawal" "Announcement"))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'aspa-customer-asn (list (cons 'raw aspa-customer-asn) (cons 'formatted (number->string aspa-customer-asn))))
        (cons 'aspa-provider-asn (list (cons 'raw aspa-provider-asn) (cons 'formatted (number->string aspa-provider-asn))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        )))

    (catch (e)
      (err (str "RPKI-RTR parse error: " e)))))

;; dissect-rpki-rtr: parse RPKI-RTR from bytevector
;; Returns (ok fields-alist) or (err message)