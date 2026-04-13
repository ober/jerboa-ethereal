;; packet-ossp.c
;; Routines for Organization Specific Slow Protocol dissection
;; IEEE Std 802.3, Annex 57B
;;
;; Copyright 2002 Steve Housley <steve_housley@3com.com>
;; Copyright 2009 Artem Tamazov <artem.tamazov@telllabs.com>
;; Copyright 2010 Roberto Morro <roberto.morro[AT]tilab.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ossp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ossp.c

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
(def (dissect-ossp buffer)
  "Organization Specific Slow Protocol"
  (try
    (let* (
           (subtype (unwrap (read-u16be buffer 0)))
           (oui (unwrap (read-u24be buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (event-flag (unwrap (read-u8 buffer 0)))
           (reserved-bits (unwrap (read-u8 buffer 0)))
           (reserved-octets (unwrap (read-u24be buffer 1)))
           (quality-level (unwrap (read-u16be buffer 6)))
           (tlv-ql-unused (unwrap (read-u8 buffer 7)))
           (tlv-ql-ssm (unwrap (read-u8 buffer 7)))
           (tlv-length (unwrap (read-u16be buffer 9)))
           (tlv-ext-ql-essm (unwrap (read-u8 buffer 11)))
           (tlv-ext-ql-clockid (unwrap (read-u64be buffer 12)))
           (tlv-ext-ql-flag-reserved (unwrap (read-u8 buffer 20)))
           (tlv-ext-ql-flag-chain (unwrap (read-u8 buffer 20)))
           (tlv-ext-ql-flag-mixed (unwrap (read-u8 buffer 20)))
           (tlv-ext-ql-eeec (unwrap (read-u8 buffer 21)))
           (tlv-ext-ql-eec (unwrap (read-u8 buffer 22)))
           (tlv-ext-ql-reserved (unwrap (slice buffer 23 5)))
           )

      (ok (list
        (cons 'subtype (list (cons 'raw subtype) (cons 'formatted (fmt-hex subtype))))
        (cons 'oui (list (cons 'raw oui) (cons 'formatted (number->string oui))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'event-flag (list (cons 'raw event-flag) (cons 'formatted (if (= event-flag 0) "Information ESMC PDU" "Time-critical Event ESMC PDU"))))
        (cons 'reserved-bits (list (cons 'raw reserved-bits) (cons 'formatted (fmt-hex reserved-bits))))
        (cons 'reserved-octets (list (cons 'raw reserved-octets) (cons 'formatted (fmt-hex reserved-octets))))
        (cons 'quality-level (list (cons 'raw quality-level) (cons 'formatted (fmt-hex quality-level))))
        (cons 'tlv-ql-unused (list (cons 'raw tlv-ql-unused) (cons 'formatted (fmt-hex tlv-ql-unused))))
        (cons 'tlv-ql-ssm (list (cons 'raw tlv-ql-ssm) (cons 'formatted (fmt-hex tlv-ql-ssm))))
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (fmt-hex tlv-length))))
        (cons 'tlv-ext-ql-essm (list (cons 'raw tlv-ext-ql-essm) (cons 'formatted (fmt-hex tlv-ext-ql-essm))))
        (cons 'tlv-ext-ql-clockid (list (cons 'raw tlv-ext-ql-clockid) (cons 'formatted (fmt-hex tlv-ext-ql-clockid))))
        (cons 'tlv-ext-ql-flag-reserved (list (cons 'raw tlv-ext-ql-flag-reserved) (cons 'formatted (fmt-hex tlv-ext-ql-flag-reserved))))
        (cons 'tlv-ext-ql-flag-chain (list (cons 'raw tlv-ext-ql-flag-chain) (cons 'formatted (if (= tlv-ext-ql-flag-chain 0) "False" "True"))))
        (cons 'tlv-ext-ql-flag-mixed (list (cons 'raw tlv-ext-ql-flag-mixed) (cons 'formatted (if (= tlv-ext-ql-flag-mixed 0) "False" "True"))))
        (cons 'tlv-ext-ql-eeec (list (cons 'raw tlv-ext-ql-eeec) (cons 'formatted (number->string tlv-ext-ql-eeec))))
        (cons 'tlv-ext-ql-eec (list (cons 'raw tlv-ext-ql-eec) (cons 'formatted (number->string tlv-ext-ql-eec))))
        (cons 'tlv-ext-ql-reserved (list (cons 'raw tlv-ext-ql-reserved) (cons 'formatted (fmt-hex tlv-ext-ql-reserved))))
        )))

    (catch (e)
      (err (str "OSSP parse error: " e)))))

;; dissect-ossp: parse OSSP from bytevector
;; Returns (ok fields-alist) or (err message)