;; packet-wtls.c
;;
;; Routines to dissect WTLS component of WAP traffic.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; WAP dissector based on original work by Ben Fowler
;; Updated by Neil Hunter <neil.hunter@energis-squared.com>
;; WTLS support by Alexandre P. Ferreira (Splice IP)
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wtls.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wtls.c

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
(def (dissect-wtls buffer)
  "Wireless Transport Layer Security"
  (try
    (let* (
           (record-sequence (unwrap (read-u16be buffer 4)))
           (record-length (unwrap (read-u16be buffer 6)))
           (hands-length (unwrap (read-u16be buffer 13)))
           (hands-cli-hello-version (unwrap (read-u8 buffer 15)))
           (hands-cli-hello-cli-key-len (unwrap (read-u16be buffer 53)))
           (hands-cli-hello-key-parameter-index (unwrap (read-u8 buffer 55)))
           (hands-cli-hello-key-parameter-set (unwrap (slice buffer 55 1)))
           (hands-cli-hello-key-identifier-size (unwrap (read-u8 buffer 75)))
           (hands-cli-hello-cipher-suite-item (unwrap (slice buffer 76 2)))
           (hands-cli-hello-key-refresh (unwrap (read-u8 buffer 77)))
           (hands-serv-hello-version (unwrap (read-u8 buffer 77)))
           (hands-serv-hello-cli-key-id (unwrap (read-u8 buffer 93)))
           (hands-serv-hello-key-refresh (unwrap (read-u8 buffer 93)))
           (hands-certificate-wtls-version (unwrap (read-u8 buffer 95)))
           (hands-certificate-wtls-key-parameter-index (unwrap (read-u8 buffer 103)))
           (hands-certificate-wtls-key-parameter-set (unwrap (slice buffer 103 1)))
           (hands-certificate-wtls-rsa-exponent (unwrap (read-u32be buffer 103)))
           (hands-certificate-wtls-rsa-modules (unwrap (read-u32be buffer 105)))
           (hands-certificate-wtls-signature (unwrap (read-u32be buffer 107)))
           )

      (ok (list
        (cons 'record-sequence (list (cons 'raw record-sequence) (cons 'formatted (number->string record-sequence))))
        (cons 'record-length (list (cons 'raw record-length) (cons 'formatted (number->string record-length))))
        (cons 'hands-length (list (cons 'raw hands-length) (cons 'formatted (number->string hands-length))))
        (cons 'hands-cli-hello-version (list (cons 'raw hands-cli-hello-version) (cons 'formatted (number->string hands-cli-hello-version))))
        (cons 'hands-cli-hello-cli-key-len (list (cons 'raw hands-cli-hello-cli-key-len) (cons 'formatted (number->string hands-cli-hello-cli-key-len))))
        (cons 'hands-cli-hello-key-parameter-index (list (cons 'raw hands-cli-hello-key-parameter-index) (cons 'formatted (number->string hands-cli-hello-key-parameter-index))))
        (cons 'hands-cli-hello-key-parameter-set (list (cons 'raw hands-cli-hello-key-parameter-set) (cons 'formatted (utf8->string hands-cli-hello-key-parameter-set))))
        (cons 'hands-cli-hello-key-identifier-size (list (cons 'raw hands-cli-hello-key-identifier-size) (cons 'formatted (number->string hands-cli-hello-key-identifier-size))))
        (cons 'hands-cli-hello-cipher-suite-item (list (cons 'raw hands-cli-hello-cipher-suite-item) (cons 'formatted (utf8->string hands-cli-hello-cipher-suite-item))))
        (cons 'hands-cli-hello-key-refresh (list (cons 'raw hands-cli-hello-key-refresh) (cons 'formatted (number->string hands-cli-hello-key-refresh))))
        (cons 'hands-serv-hello-version (list (cons 'raw hands-serv-hello-version) (cons 'formatted (number->string hands-serv-hello-version))))
        (cons 'hands-serv-hello-cli-key-id (list (cons 'raw hands-serv-hello-cli-key-id) (cons 'formatted (fmt-hex hands-serv-hello-cli-key-id))))
        (cons 'hands-serv-hello-key-refresh (list (cons 'raw hands-serv-hello-key-refresh) (cons 'formatted (number->string hands-serv-hello-key-refresh))))
        (cons 'hands-certificate-wtls-version (list (cons 'raw hands-certificate-wtls-version) (cons 'formatted (fmt-hex hands-certificate-wtls-version))))
        (cons 'hands-certificate-wtls-key-parameter-index (list (cons 'raw hands-certificate-wtls-key-parameter-index) (cons 'formatted (number->string hands-certificate-wtls-key-parameter-index))))
        (cons 'hands-certificate-wtls-key-parameter-set (list (cons 'raw hands-certificate-wtls-key-parameter-set) (cons 'formatted (utf8->string hands-certificate-wtls-key-parameter-set))))
        (cons 'hands-certificate-wtls-rsa-exponent (list (cons 'raw hands-certificate-wtls-rsa-exponent) (cons 'formatted (number->string hands-certificate-wtls-rsa-exponent))))
        (cons 'hands-certificate-wtls-rsa-modules (list (cons 'raw hands-certificate-wtls-rsa-modules) (cons 'formatted (number->string hands-certificate-wtls-rsa-modules))))
        (cons 'hands-certificate-wtls-signature (list (cons 'raw hands-certificate-wtls-signature) (cons 'formatted (number->string hands-certificate-wtls-signature))))
        )))

    (catch (e)
      (err (str "WTLS parse error: " e)))))

;; dissect-wtls: parse WTLS from bytevector
;; Returns (ok fields-alist) or (err message)