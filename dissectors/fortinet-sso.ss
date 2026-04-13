;; packet-fortinet-sso.c
;; Routines for Fortinet Single Sign-On
;; Copyright 2020, Alexis La Goutte <alexis.lagoutte at gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; No spec/doc is available based on reverse/analysis of protocol...
;;

;; jerboa-ethereal/dissectors/fortinet-sso.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fortinet_sso.c

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
(def (dissect-fortinet-sso buffer)
  "Fortinet Single Sign On"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 0)))
           (client-ip (unwrap (read-u32be buffer 6)))
           (payload-length (unwrap (read-u16be buffer 10)))
           (string (unwrap (slice buffer 12 1)))
           (domain (unwrap (slice buffer 12 1)))
           (user (unwrap (slice buffer 12 1)))
           (version (unwrap (slice buffer 12 1)))
           (host (unwrap (slice buffer 12 1)))
           (unknown-ipv4 (unwrap (read-u32be buffer 28)))
           (unknown (unwrap (slice buffer 48 5)))
           (tsagent-number-port-range (unwrap (read-u16be buffer 59)))
           (tsagent-port-range-min (unwrap (read-u16be buffer 61)))
           (tsagent-port-range-max (unwrap (read-u16be buffer 63)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'client-ip (list (cons 'raw client-ip) (cons 'formatted (fmt-ipv4 client-ip))))
        (cons 'payload-length (list (cons 'raw payload-length) (cons 'formatted (number->string payload-length))))
        (cons 'string (list (cons 'raw string) (cons 'formatted (utf8->string string))))
        (cons 'domain (list (cons 'raw domain) (cons 'formatted (utf8->string domain))))
        (cons 'user (list (cons 'raw user) (cons 'formatted (utf8->string user))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (utf8->string version))))
        (cons 'host (list (cons 'raw host) (cons 'formatted (utf8->string host))))
        (cons 'unknown-ipv4 (list (cons 'raw unknown-ipv4) (cons 'formatted (fmt-ipv4 unknown-ipv4))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (fmt-bytes unknown))))
        (cons 'tsagent-number-port-range (list (cons 'raw tsagent-number-port-range) (cons 'formatted (number->string tsagent-number-port-range))))
        (cons 'tsagent-port-range-min (list (cons 'raw tsagent-port-range-min) (cons 'formatted (number->string tsagent-port-range-min))))
        (cons 'tsagent-port-range-max (list (cons 'raw tsagent-port-range-max) (cons 'formatted (number->string tsagent-port-range-max))))
        )))

    (catch (e)
      (err (str "FORTINET-SSO parse error: " e)))))

;; dissect-fortinet-sso: parse FORTINET-SSO from bytevector
;; Returns (ok fields-alist) or (err message)