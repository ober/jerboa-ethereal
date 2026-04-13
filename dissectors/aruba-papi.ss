;; packet-aruba-papi.c
;; Routines for Aruba PAPI dissection
;; Copyright 2010, Alexis La Goutte <alexis.lagoutte at gmail dot com>
;;
;; Real name of PAPI : Protocol Application Program Interface
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/aruba-papi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-aruba_papi.c

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
(def (dissect-aruba-papi buffer)
  "Aruba PAPI"
  (try
    (let* (
           (licmgr-payload-len (unwrap (read-u32be buffer 0)))
           (hdr-magic (unwrap (read-u16be buffer 0)))
           (licmgr-type (unwrap (read-u16be buffer 2)))
           (hdr-version (unwrap (read-u16be buffer 2)))
           (licmgr-length (unwrap (read-u16be buffer 4)))
           (hdr-dest-ip (unwrap (read-u32be buffer 4)))
           (licmgr-value (unwrap (slice buffer 6 1)))
           (licmgr-ip (unwrap (read-u32be buffer 6)))
           (licmgr-serial-number (unwrap (slice buffer 6 32)))
           (licmgr-hostname (unwrap (slice buffer 6 1)))
           (licmgr-mac-address (unwrap (slice buffer 6 6)))
           (licmgr-license-ap-remaining (unwrap (read-u32be buffer 6)))
           (licmgr-license-pef-remaining (unwrap (read-u32be buffer 6)))
           (licmgr-license-rfp-remaining (unwrap (read-u32be buffer 6)))
           (licmgr-license-xsec-remaining (unwrap (read-u32be buffer 6)))
           (licmgr-license-acr-remaining (unwrap (read-u32be buffer 6)))
           (licmgr-license-ap-used (unwrap (read-u32be buffer 6)))
           (licmgr-license-pef-used (unwrap (read-u32be buffer 6)))
           (licmgr-license-rfp-used (unwrap (read-u32be buffer 6)))
           (licmgr-license-xsec-used (unwrap (read-u32be buffer 6)))
           (licmgr-license-acr-used (unwrap (read-u32be buffer 6)))
           (licmgr-padding (unwrap (slice buffer 6 1)))
           (debug-text (unwrap (slice buffer 6 1)))
           (debug-text-length (unwrap (read-u16be buffer 6)))
           (debug-48bits (unwrap (read-u64be buffer 6)))
           (hdr-src-ip (unwrap (read-u32be buffer 8)))
           (hdr-nat-port-number (unwrap (read-u16be buffer 12)))
           (debug-8bits (unwrap (read-u8 buffer 13)))
           (hdr-garbage (unwrap (read-u16be buffer 14)))
           (debug-32bits (unwrap (read-u32be buffer 18)))
           (hdr-packet-size (unwrap (read-u16be buffer 22)))
           (debug-ipv4 (unwrap (read-u32be buffer 23)))
           (hdr-seq-number (unwrap (read-u16be buffer 24)))
           (hdr-message-code (unwrap (read-u16be buffer 26)))
           (debug-16bits (unwrap (read-u16be buffer 28)))
           (hdr-checksum (unwrap (slice buffer 28 16)))
           (debug-bytes (unwrap (slice buffer 31 1)))
           (debug-bytes-length (unwrap (read-u16be buffer 31)))
           (debug-64bits (unwrap (read-u64be buffer 31)))
           )

      (ok (list
        (cons 'licmgr-payload-len (list (cons 'raw licmgr-payload-len) (cons 'formatted (number->string licmgr-payload-len))))
        (cons 'hdr-magic (list (cons 'raw hdr-magic) (cons 'formatted (fmt-hex hdr-magic))))
        (cons 'licmgr-type (list (cons 'raw licmgr-type) (cons 'formatted (number->string licmgr-type))))
        (cons 'hdr-version (list (cons 'raw hdr-version) (cons 'formatted (number->string hdr-version))))
        (cons 'licmgr-length (list (cons 'raw licmgr-length) (cons 'formatted (number->string licmgr-length))))
        (cons 'hdr-dest-ip (list (cons 'raw hdr-dest-ip) (cons 'formatted (fmt-ipv4 hdr-dest-ip))))
        (cons 'licmgr-value (list (cons 'raw licmgr-value) (cons 'formatted (fmt-bytes licmgr-value))))
        (cons 'licmgr-ip (list (cons 'raw licmgr-ip) (cons 'formatted (fmt-ipv4 licmgr-ip))))
        (cons 'licmgr-serial-number (list (cons 'raw licmgr-serial-number) (cons 'formatted (utf8->string licmgr-serial-number))))
        (cons 'licmgr-hostname (list (cons 'raw licmgr-hostname) (cons 'formatted (utf8->string licmgr-hostname))))
        (cons 'licmgr-mac-address (list (cons 'raw licmgr-mac-address) (cons 'formatted (fmt-mac licmgr-mac-address))))
        (cons 'licmgr-license-ap-remaining (list (cons 'raw licmgr-license-ap-remaining) (cons 'formatted (number->string licmgr-license-ap-remaining))))
        (cons 'licmgr-license-pef-remaining (list (cons 'raw licmgr-license-pef-remaining) (cons 'formatted (number->string licmgr-license-pef-remaining))))
        (cons 'licmgr-license-rfp-remaining (list (cons 'raw licmgr-license-rfp-remaining) (cons 'formatted (number->string licmgr-license-rfp-remaining))))
        (cons 'licmgr-license-xsec-remaining (list (cons 'raw licmgr-license-xsec-remaining) (cons 'formatted (number->string licmgr-license-xsec-remaining))))
        (cons 'licmgr-license-acr-remaining (list (cons 'raw licmgr-license-acr-remaining) (cons 'formatted (number->string licmgr-license-acr-remaining))))
        (cons 'licmgr-license-ap-used (list (cons 'raw licmgr-license-ap-used) (cons 'formatted (number->string licmgr-license-ap-used))))
        (cons 'licmgr-license-pef-used (list (cons 'raw licmgr-license-pef-used) (cons 'formatted (number->string licmgr-license-pef-used))))
        (cons 'licmgr-license-rfp-used (list (cons 'raw licmgr-license-rfp-used) (cons 'formatted (number->string licmgr-license-rfp-used))))
        (cons 'licmgr-license-xsec-used (list (cons 'raw licmgr-license-xsec-used) (cons 'formatted (number->string licmgr-license-xsec-used))))
        (cons 'licmgr-license-acr-used (list (cons 'raw licmgr-license-acr-used) (cons 'formatted (number->string licmgr-license-acr-used))))
        (cons 'licmgr-padding (list (cons 'raw licmgr-padding) (cons 'formatted (fmt-bytes licmgr-padding))))
        (cons 'debug-text (list (cons 'raw debug-text) (cons 'formatted (utf8->string debug-text))))
        (cons 'debug-text-length (list (cons 'raw debug-text-length) (cons 'formatted (number->string debug-text-length))))
        (cons 'debug-48bits (list (cons 'raw debug-48bits) (cons 'formatted (number->string debug-48bits))))
        (cons 'hdr-src-ip (list (cons 'raw hdr-src-ip) (cons 'formatted (fmt-ipv4 hdr-src-ip))))
        (cons 'hdr-nat-port-number (list (cons 'raw hdr-nat-port-number) (cons 'formatted (number->string hdr-nat-port-number))))
        (cons 'debug-8bits (list (cons 'raw debug-8bits) (cons 'formatted (number->string debug-8bits))))
        (cons 'hdr-garbage (list (cons 'raw hdr-garbage) (cons 'formatted (number->string hdr-garbage))))
        (cons 'debug-32bits (list (cons 'raw debug-32bits) (cons 'formatted (number->string debug-32bits))))
        (cons 'hdr-packet-size (list (cons 'raw hdr-packet-size) (cons 'formatted (number->string hdr-packet-size))))
        (cons 'debug-ipv4 (list (cons 'raw debug-ipv4) (cons 'formatted (fmt-ipv4 debug-ipv4))))
        (cons 'hdr-seq-number (list (cons 'raw hdr-seq-number) (cons 'formatted (number->string hdr-seq-number))))
        (cons 'hdr-message-code (list (cons 'raw hdr-message-code) (cons 'formatted (number->string hdr-message-code))))
        (cons 'debug-16bits (list (cons 'raw debug-16bits) (cons 'formatted (number->string debug-16bits))))
        (cons 'hdr-checksum (list (cons 'raw hdr-checksum) (cons 'formatted (fmt-bytes hdr-checksum))))
        (cons 'debug-bytes (list (cons 'raw debug-bytes) (cons 'formatted (fmt-bytes debug-bytes))))
        (cons 'debug-bytes-length (list (cons 'raw debug-bytes-length) (cons 'formatted (number->string debug-bytes-length))))
        (cons 'debug-64bits (list (cons 'raw debug-64bits) (cons 'formatted (number->string debug-64bits))))
        )))

    (catch (e)
      (err (str "ARUBA-PAPI parse error: " e)))))

;; dissect-aruba-papi: parse ARUBA-PAPI from bytevector
;; Returns (ok fields-alist) or (err message)