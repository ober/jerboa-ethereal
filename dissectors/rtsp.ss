;; packet-rtsp.c
;; Routines for RTSP packet disassembly (RFC 2326)
;;
;; Jason Lango <jal@netapp.com>
;; Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References:
;; RTSP is defined in RFC 2326, https://tools.ietf.org/html/rfc2326
;; https://www.iana.org/assignments/rsvp-parameters
;; RFC 7826 describes RTSP 2.0, and technically obsoletes RFC 2326.
;; However, in practice due to lack of backwards compatibility, it has
;; has seen limited adoption and this dissector does not attempt to
;; dissect it. RFC 7826 does, however, have some useful comments about
;; ambiguities and pitfalls in RFC 2326.
;;

;; jerboa-ethereal/dissectors/rtsp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rtsp.c
;; RFC 2326

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
(def (dissect-rtsp buffer)
  "Real Time Streaming Protocol"
  (try
    (let* (
           (url (unwrap (slice buffer 0 1)))
           (transport (unwrap (slice buffer 0 1)))
           (content-type (unwrap (slice buffer 0 1)))
           (content-length (unwrap (read-u32be buffer 0)))
           (session (unwrap (slice buffer 0 1)))
           (X-Vig-Msisdn (unwrap (slice buffer 0 1)))
           (rdtfeaturelevel (unwrap (read-u32be buffer 0)))
           (cseq (unwrap (read-u32be buffer 0)))
           (content-base (unwrap (slice buffer 0 1)))
           (content-location (unwrap (slice buffer 0 1)))
           (data (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'url (list (cons 'raw url) (cons 'formatted (utf8->string url))))
        (cons 'transport (list (cons 'raw transport) (cons 'formatted (utf8->string transport))))
        (cons 'content-type (list (cons 'raw content-type) (cons 'formatted (utf8->string content-type))))
        (cons 'content-length (list (cons 'raw content-length) (cons 'formatted (number->string content-length))))
        (cons 'session (list (cons 'raw session) (cons 'formatted (utf8->string session))))
        (cons 'X-Vig-Msisdn (list (cons 'raw X-Vig-Msisdn) (cons 'formatted (utf8->string X-Vig-Msisdn))))
        (cons 'rdtfeaturelevel (list (cons 'raw rdtfeaturelevel) (cons 'formatted (number->string rdtfeaturelevel))))
        (cons 'cseq (list (cons 'raw cseq) (cons 'formatted (number->string cseq))))
        (cons 'content-base (list (cons 'raw content-base) (cons 'formatted (utf8->string content-base))))
        (cons 'content-location (list (cons 'raw content-location) (cons 'formatted (utf8->string content-location))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        )))

    (catch (e)
      (err (str "RTSP parse error: " e)))))

;; dissect-rtsp: parse RTSP from bytevector
;; Returns (ok fields-alist) or (err message)