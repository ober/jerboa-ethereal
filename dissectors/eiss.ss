;; packet-eiss.c
;;
;; Routines for ETV-AM EISS (OC-SP-ETV-AM1.0-I05)
;; Copyright 2012, Weston Schmidt <weston_schmidt@alumni.purdue.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/eiss.ss
;; Auto-generated from wireshark/epan/dissectors/packet-eiss.c

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
(def (dissect-eiss buffer)
  "ETV-AM EISS Section"
  (try
    (let* (
           (reserved2 (unwrap (read-u8 buffer 0)))
           (section-number (unwrap (read-u8 buffer 0)))
           (last-section-number (unwrap (read-u8 buffer 0)))
           (protocol-version-major (unwrap (read-u8 buffer 0)))
           (protocol-version-minor (unwrap (read-u8 buffer 0)))
           (application-type (unwrap (read-u16be buffer 0)))
           (organisation-id (unwrap (read-u32be buffer 2)))
           (hf-pdtHWModel (unwrap (read-u16be buffer 3)))
           (hf-pdtHWVersionMajor (unwrap (read-u8 buffer 5)))
           (hf-pdtHWVersionMinor (unwrap (read-u8 buffer 5)))
           (hf-pdtSWManufacturer (unwrap (read-u24be buffer 5)))
           (hf-pdtSWModel (unwrap (read-u16be buffer 8)))
           (platform-id-length (unwrap (read-u8 buffer 8)))
           (hf-pdtSWVersionMajor (unwrap (read-u8 buffer 10)))
           (hf-pdtSWVersionMinor (unwrap (read-u8 buffer 10)))
           (hf-pdtProfile (unwrap (read-u8 buffer 10)))
           (aid-app-version-major (unwrap (read-u8 buffer 10)))
           (aid-app-version-minor (unwrap (read-u8 buffer 10)))
           (aid-max-proto-version-major (unwrap (read-u8 buffer 10)))
           (aid-max-proto-version-minor (unwrap (read-u8 buffer 10)))
           (aid-test-flag (unwrap (read-u8 buffer 10)))
           (aid-reserved (unwrap (read-u24be buffer 10)))
           (aid-priority (unwrap (read-u8 buffer 13)))
           (irl-type (unwrap (read-u16be buffer 13)))
           (irl-length (unwrap (read-u16be buffer 13)))
           (descriptor-length (unwrap (read-u8 buffer 15)))
           (mtd-time-value (unwrap (read-u32be buffer 15)))
           (sed-reserved (unwrap (read-u16be buffer 15)))
           (sed-descriptor-length (unwrap (read-u16be buffer 15)))
           (sed-time-value (unwrap (read-u32be buffer 17)))
           (hf-pdtHWManufacturer (unwrap (read-u24be buffer 21)))
           )

      (ok (list
        (cons 'reserved2 (list (cons 'raw reserved2) (cons 'formatted (fmt-hex reserved2))))
        (cons 'section-number (list (cons 'raw section-number) (cons 'formatted (number->string section-number))))
        (cons 'last-section-number (list (cons 'raw last-section-number) (cons 'formatted (number->string last-section-number))))
        (cons 'protocol-version-major (list (cons 'raw protocol-version-major) (cons 'formatted (fmt-hex protocol-version-major))))
        (cons 'protocol-version-minor (list (cons 'raw protocol-version-minor) (cons 'formatted (fmt-hex protocol-version-minor))))
        (cons 'application-type (list (cons 'raw application-type) (cons 'formatted (fmt-hex application-type))))
        (cons 'organisation-id (list (cons 'raw organisation-id) (cons 'formatted (fmt-hex organisation-id))))
        (cons 'hf-pdtHWModel (list (cons 'raw hf-pdtHWModel) (cons 'formatted (fmt-hex hf-pdtHWModel))))
        (cons 'hf-pdtHWVersionMajor (list (cons 'raw hf-pdtHWVersionMajor) (cons 'formatted (fmt-hex hf-pdtHWVersionMajor))))
        (cons 'hf-pdtHWVersionMinor (list (cons 'raw hf-pdtHWVersionMinor) (cons 'formatted (fmt-hex hf-pdtHWVersionMinor))))
        (cons 'hf-pdtSWManufacturer (list (cons 'raw hf-pdtSWManufacturer) (cons 'formatted (fmt-hex hf-pdtSWManufacturer))))
        (cons 'hf-pdtSWModel (list (cons 'raw hf-pdtSWModel) (cons 'formatted (fmt-hex hf-pdtSWModel))))
        (cons 'platform-id-length (list (cons 'raw platform-id-length) (cons 'formatted (number->string platform-id-length))))
        (cons 'hf-pdtSWVersionMajor (list (cons 'raw hf-pdtSWVersionMajor) (cons 'formatted (fmt-hex hf-pdtSWVersionMajor))))
        (cons 'hf-pdtSWVersionMinor (list (cons 'raw hf-pdtSWVersionMinor) (cons 'formatted (fmt-hex hf-pdtSWVersionMinor))))
        (cons 'hf-pdtProfile (list (cons 'raw hf-pdtProfile) (cons 'formatted (fmt-hex hf-pdtProfile))))
        (cons 'aid-app-version-major (list (cons 'raw aid-app-version-major) (cons 'formatted (fmt-hex aid-app-version-major))))
        (cons 'aid-app-version-minor (list (cons 'raw aid-app-version-minor) (cons 'formatted (fmt-hex aid-app-version-minor))))
        (cons 'aid-max-proto-version-major (list (cons 'raw aid-max-proto-version-major) (cons 'formatted (fmt-hex aid-max-proto-version-major))))
        (cons 'aid-max-proto-version-minor (list (cons 'raw aid-max-proto-version-minor) (cons 'formatted (fmt-hex aid-max-proto-version-minor))))
        (cons 'aid-test-flag (list (cons 'raw aid-test-flag) (cons 'formatted (fmt-hex aid-test-flag))))
        (cons 'aid-reserved (list (cons 'raw aid-reserved) (cons 'formatted (fmt-hex aid-reserved))))
        (cons 'aid-priority (list (cons 'raw aid-priority) (cons 'formatted (fmt-hex aid-priority))))
        (cons 'irl-type (list (cons 'raw irl-type) (cons 'formatted (fmt-hex irl-type))))
        (cons 'irl-length (list (cons 'raw irl-length) (cons 'formatted (number->string irl-length))))
        (cons 'descriptor-length (list (cons 'raw descriptor-length) (cons 'formatted (number->string descriptor-length))))
        (cons 'mtd-time-value (list (cons 'raw mtd-time-value) (cons 'formatted (number->string mtd-time-value))))
        (cons 'sed-reserved (list (cons 'raw sed-reserved) (cons 'formatted (number->string sed-reserved))))
        (cons 'sed-descriptor-length (list (cons 'raw sed-descriptor-length) (cons 'formatted (number->string sed-descriptor-length))))
        (cons 'sed-time-value (list (cons 'raw sed-time-value) (cons 'formatted (number->string sed-time-value))))
        (cons 'hf-pdtHWManufacturer (list (cons 'raw hf-pdtHWManufacturer) (cons 'formatted (fmt-hex hf-pdtHWManufacturer))))
        )))

    (catch (e)
      (err (str "EISS parse error: " e)))))

;; dissect-eiss: parse EISS from bytevector
;; Returns (ok fields-alist) or (err message)